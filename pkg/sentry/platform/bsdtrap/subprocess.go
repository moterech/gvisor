// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build freebsd && amd64

package bsdtrap

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bsdsys"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

const (
	spinIters   = 20000
	waitSliceNs = 100 * 1000 * 1000 // re-check stub liveness every 100ms
)

// errStubDied is returned when the stub process exits unexpectedly.
var errStubDied = fmt.Errorf("bsdtrap: stub process died")

// subprocess is one application address space: a stub process under
// gsb.ko plus the shared control area used to drive it.
//
// It implements platform.AddressSpace.
type subprocess struct {
	platform.NoAddressSpaceIO

	proc *os.Process
	dead atomic.Bool

	// ctl is the shared control area (struct ctl + slots).
	ctl []byte

	// sock is our end of the fd-passing socket.
	sock int

	// mu serializes control requests and protects the fields below.
	mu       sync.Mutex
	fds      map[fdKey]int // host file -> fd number in the stub
	nextSlot int
	free     []int // slots whose thread has exited
	released bool
}

// fdKey identifies a host file independently of its (reusable) fd number.
type fdKey struct {
	fd       int
	dev, ino uint64
}

func (s *subprocess) u32(off int) *uint32 { return (*uint32)(unsafe.Pointer(&s.ctl[off])) }
func (s *subprocess) i64(off int) *int64  { return (*int64)(unsafe.Pointer(&s.ctl[off])) }

func newSubprocess(stubPath string) (*subprocess, error) {
	ctlFD, err := memutil.CreateMemFD("bsdtrap-ctl", 0)
	if err != nil {
		return nil, fmt.Errorf("bsdtrap: control area: %w", err)
	}
	ctlFile := os.NewFile(uintptr(ctlFD), "bsdtrap-ctl")
	defer ctlFile.Close()
	if err := unix.Ftruncate(ctlFD, ctlAreaSize); err != nil {
		return nil, err
	}
	ctl, err := unix.Mmap(ctlFD, 0, ctlAreaSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}

	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		unix.Munmap(ctl)
		return nil, err
	}
	child := os.NewFile(uintptr(sp[1]), "bsdtrap-sock")
	defer child.Close()

	// fd 3 = control area, fd 4 = socket; see stub/bsdtrap_abi.h.
	proc, err := os.StartProcess(stubPath, []string{"gsb-bsdtrap-stub"}, &os.ProcAttr{
		Files: []*os.File{nil, nil, os.Stderr, ctlFile, child},
	})
	if err != nil {
		unix.Munmap(ctl)
		unix.Close(sp[0])
		return nil, fmt.Errorf("bsdtrap: starting stub %s: %w", stubPath, err)
	}
	s := &subprocess{
		proc: proc,
		ctl:  ctl,
		sock: sp[0],
		fds:  make(map[fdKey]int),
	}
	go func() {
		proc.Wait()
		s.dead.Store(true)
	}()
	return s, nil
}

// wait blocks until *seq != old: spin, then sleep on it, re-checking that
// the stub is alive. sleeping is our "Sentry sleeps" flag for the peer.
func (s *subprocess) wait(seq *uint32, old uint32, sleeping *uint32) (uint32, error) {
	for i := 0; i < spinIters; i++ {
		if v := atomic.LoadUint32(seq); v != old {
			return v, nil
		}
	}
	defer atomic.StoreUint32(sleeping, 0)
	for {
		atomic.StoreUint32(sleeping, 1)
		if v := atomic.LoadUint32(seq); v != old {
			return v, nil
		}
		if s.dead.Load() {
			return 0, errStubDied
		}
		if err := bsdsys.UmtxWaitUintTimeout(uintptr(unsafe.Pointer(seq)), old, true, waitSliceNs); err != nil {
			return 0, err
		}
	}
}

// publish bumps *seq and wakes the stub if it sleeps on it.
func publish(seq *uint32, peerSleeping *uint32) {
	atomic.AddUint32(seq, 1)
	if atomic.LoadUint32(peerSleeping) != 0 {
		bsdsys.UmtxWake(uintptr(unsafe.Pointer(seq)), 1, true)
	}
}

// request runs one control operation in the stub. s.mu must be held.
func (s *subprocess) request(op uint32, args ...uint64) (int64, error) {
	if s.released {
		return 0, unix.ESRCH
	}
	*s.u32(ctlOp) = op
	for i, a := range args {
		*(*uint64)(unsafe.Pointer(&s.ctl[ctlArgs+8*i])) = a
	}
	old := atomic.LoadUint32(s.u32(ctlRespSeq))
	publish(s.u32(ctlReqSeq), s.u32(ctlStubSleep))
	if _, err := s.wait(s.u32(ctlRespSeq), old, s.u32(ctlSentrySleep)); err != nil {
		return 0, err
	}
	r := atomic.LoadInt64(s.i64(ctlRet))
	if r < 0 && r > -4096 {
		return r, unix.Errno(-r)
	}
	return r, nil
}

// stubFD returns the stub's fd number for host fd, sending it if needed.
// s.mu must be held.
func (s *subprocess) stubFD(fd int) (int, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return -1, err
	}
	key := fdKey{fd: fd, dev: st.Dev, ino: st.Ino}
	if sfd, ok := s.fds[key]; ok {
		return sfd, nil
	}
	if err := unix.Sendmsg(s.sock, []byte{0}, unix.UnixRights(fd), nil, 0); err != nil {
		return -1, fmt.Errorf("bsdtrap: sending fd: %w", err)
	}
	sfd, err := s.request(opRecvFD)
	if err != nil {
		return -1, err
	}
	s.fds[key] = int(sfd)
	return int(sfd), nil
}

// MapFile implements platform.AddressSpace.MapFile.
func (s *subprocess) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error {
	fd, err := f.DataFD(fr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sfd, err := s.stubFD(fd)
	if err != nil {
		return err
	}
	flags := unix.MAP_SHARED | unix.MAP_FIXED
	if precommit {
		flags |= unix.MAP_PREFAULT_READ
	}
	r, err := s.request(opMmap, uint64(addr), fr.Length(), uint64(at.Prot()), uint64(flags), uint64(sfd), fr.Start)
	if err != nil {
		return err
	}
	if hostarch.Addr(r) != addr {
		return fmt.Errorf("bsdtrap: stub mapped %#x at %#x", addr, r)
	}
	return nil
}

// Unmap implements platform.AddressSpace.Unmap.
func (s *subprocess) Unmap(addr hostarch.Addr, length uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.request(opMunmap, uint64(addr), length); err != nil && !s.released && !s.dead.Load() {
		panic(fmt.Sprintf("bsdtrap: munmap(%#x, %#x) in stub: %v", addr, length, err))
	}
}

// newThread starts a stub thread in a free slot and waits for its first
// (template) event.
func (s *subprocess) newThread() (*stubThread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, f := range s.free {
		// Reuse only slots whose thread has really exited (tid word set
		// to 1 by thr_exit).
		if atomic.LoadInt64(s.i64(slotOffset(f)+slotTID)) == 1 {
			idx = f
			s.free = append(s.free[:i], s.free[i+1:]...)
			break
		}
	}
	if idx < 0 {
		if s.nextSlot >= maxThreads {
			return nil, unix.EAGAIN
		}
		idx = s.nextSlot
		s.nextSlot++
	}
	t := &stubThread{s: s, idx: idx, slot: s.ctl[slotOffset(idx) : slotOffset(idx)+slotSize]}
	t.evSeen = atomic.LoadUint32(t.u32(slotEvSeq))
	if _, err := s.request(opNewThread, uint64(idx)); err != nil {
		return nil, err
	}
	// The first event is the thread's NR_ENTER trap.
	if err := t.waitEvent(); err != nil {
		return nil, err
	}
	si := t.siginfo()
	if si.Signo != hostSIGSYS || si.Trapno != nrEnter {
		return nil, fmt.Errorf("bsdtrap: unexpected first event: signal %d trapno %d", si.Signo, si.Trapno)
	}
	t.tid = int(atomic.LoadInt64(t.i64(slotTID)))
	return t, nil
}

func slotOffset(idx int) int { return ctlSize + idx*slotSize }

// releaseThread stops t's thread and returns its slot.
func (s *subprocess) releaseThread(t *stubThread) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return
	}
	*t.u32(slotCmd) = cmdExit
	publish(t.u32(slotCmdSeq), t.u32(slotStubSleep))
	s.free = append(s.free, t.idx)
}

// Release implements platform.AddressSpace.Release.
func (s *subprocess) Release() {
	s.mu.Lock()
	if !s.released {
		*s.u32(ctlOp) = opExit
		publish(s.u32(ctlReqSeq), s.u32(ctlStubSleep))
		s.released = true
	}
	s.mu.Unlock()
	// The stub exits on its own; make sure, then release our side.
	s.proc.Kill()
	unix.Close(s.sock)
	// ctl stays mapped until the process is gone: stub threads may still
	// be touching it, and a late access must not fault in the Sentry.
	go func() {
		for !s.dead.Load() {
			time.Sleep(10 * time.Millisecond)
		}
		unix.Munmap(s.ctl)
	}()
}

// PreFork implements platform.AddressSpace.PreFork.
func (s *subprocess) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (s *subprocess) PostFork() {}

// PrepareForPtrace implements platform.AddressSpace.PrepareForPtrace.
func (s *subprocess) PrepareForPtrace(pkgcontext.Context, platform.MemoryManager) error { return nil }

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS. gs_base
// is passed to the stub on every Switch, so nothing to do.
func (s *subprocess) UserModifiedGS(pkgcontext.Context, platform.MemoryManager) error { return nil }
