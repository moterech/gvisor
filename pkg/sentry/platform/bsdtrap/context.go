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
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/interrupt"
)

// stubThread is one host thread in a stub, bound to one context.
type stubThread struct {
	s    *subprocess
	idx  int
	slot []byte
	tid  int

	// evSeen is the last event sequence number consumed.
	evSeen uint32
}

func (t *stubThread) u32(off int) *uint32 { return (*uint32)(unsafe.Pointer(&t.slot[off])) }
func (t *stubThread) i64(off int) *int64  { return (*int64)(unsafe.Pointer(&t.slot[off])) }
func (t *stubThread) mcontext() *mcontext {
	return (*mcontext)(unsafe.Pointer(&t.slot[slotMcontext]))
}
func (t *stubThread) siginfo() *siginfo {
	return (*siginfo)(unsafe.Pointer(&t.slot[slotSiginfo]))
}
func (t *stubThread) xfpu(n int) []byte { return t.slot[slotXfpu : slotXfpu+n] }

// waitEvent waits for the thread's next event.
func (t *stubThread) waitEvent() error {
	v, err := t.s.wait(t.u32(slotEvSeq), t.evSeen, t.u32(slotSentrySleep))
	if err != nil {
		return err
	}
	t.evSeen = v
	return nil
}

// context is a platform.Context: the execution state of one Linux thread.
type context struct {
	platform.NoCPUNumbers

	interrupt interrupt.Forwarder

	mu      sync.Mutex
	threads map[*subprocess]*stubThread

	// running is the stub thread currently executing app code for this
	// context, if any; target of interrupts.
	running atomic.Pointer[stubThread]
}

func newContext() *context {
	c := &context{threads: make(map[*subprocess]*stubThread)}
	c.interrupt.Dst = c
	return c
}

func (c *context) thread(s *subprocess) (*stubThread, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.threads[s]; ok {
		return t, nil
	}
	t, err := s.newThread()
	if err != nil {
		return nil, err
	}
	c.threads[s] = t
	return t, nil
}

// Switch implements platform.Context.Switch.
func (c *context) Switch(ctx pkgcontext.Context, mm platform.MemoryManager, ac *arch.Context64, cpu int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	s := mm.AddressSpace().(*subprocess)
	t, err := c.thread(s)
	if err != nil {
		return nil, hostarch.NoAccess, err
	}

	if !c.interrupt.Enable() {
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}
	defer c.interrupt.Disable()

	// Hand the app state to the stub thread. Its last event's context is
	// the template for everything Linux registers don't determine.
	mc := t.mcontext()
	regs := &ac.StateData().Regs
	tmpl := *mc
	fromPtraceRegs(regs, &tmpl, mc)
	xlen := fpToHost(ac.FloatingPointData().Slice(), mc, t.slot[slotXfpu:], int(atomic.LoadUint32(t.u32(slotXfpuLen))))
	atomic.StoreUint32(t.u32(slotXfpuLen), uint32(xlen))
	*t.u32(slotCmd) = cmdRun

	c.running.Store(t)
	publish(t.u32(slotCmdSeq), t.u32(slotStubSleep))
	err = t.waitEvent()
	c.running.Store(nil)
	if err != nil {
		return nil, hostarch.NoAccess, err
	}

	// Collect the new state.
	toPtraceRegs(mc, regs)
	fpFromHost(ac.FloatingPointData().Slice(), mc, t.xfpu(int(atomic.LoadUint32(t.u32(slotXfpuLen)))))
	if !ac.SetTLS(uintptr(regs.Fs_base)) {
		return nil, hostarch.NoAccess, unix.EINVAL
	}

	si := t.siginfo()
	sig := *t.u32(slotEvSig)
	switch {
	case sig == hostSIGSYS && si.Code == gsbSISyscall:
		// A redirected app syscall. rax holds the number.
		regs.Orig_rax = regs.Rax
		return nil, hostarch.NoAccess, nil

	case sig == hostSIGUSR1:
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}

	lsig, ok := hostToLinuxSignal[int32(sig)]
	if !ok {
		lsig = linux.SIGSEGV
	}
	info := &linux.SignalInfo{Signo: int32(lsig), Code: si.Code}
	info.SetAddr(si.Addr)
	at := hostarch.NoAccess
	if lsig == linux.SIGSEGV || lsig == linux.SIGBUS {
		at = faultAccess(mc, si.Addr)
	}
	return info, at, platform.ErrContextSignal
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt: kick the
// stub thread out of app code with SIGUSR1. If it is not in the app yet,
// the signal stays pending (blocked in the handler) and fires on entry.
func (c *context) NotifyInterrupt() {
	if t := c.running.Load(); t != nil {
		unix.Syscall(unix.SYS_THR_KILL2, uintptr(t.s.proc.Pid), uintptr(t.tid), hostSIGUSR1)
	}
}

// Interrupt implements platform.Context.Interrupt.
func (c *context) Interrupt() { c.interrupt.NotifyInterrupt() }

// Preempt implements platform.Context.Preempt.
func (c *context) Preempt() {}

// PullFullState implements platform.Context.PullFullState. Switch always
// returns the full state.
func (c *context) PullFullState(as platform.AddressSpace, ac *arch.Context64) error { return nil }

// FullStateChanged implements platform.Context.FullStateChanged.
func (c *context) FullStateChanged() {}

// Release implements platform.Context.Release.
func (c *context) Release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for s, t := range c.threads {
		s.releaseThread(t)
		delete(c.threads, s)
	}
}

// PrepareSleep implements platform.Context.PrepareSleep.
func (c *context) PrepareSleep() {}

// PrepareUninterruptibleSleep implements platform.Context.PrepareUninterruptibleSleep.
func (c *context) PrepareUninterruptibleSleep() {}

// PrepareStop implements platform.Context.PrepareStop.
func (c *context) PrepareStop() {}

// PrepareExecve implements platform.Context.PrepareExecve.
func (c *context) PrepareExecve() {}

// PrepareExit implements platform.Context.PrepareExit.
func (c *context) PrepareExit() {}
