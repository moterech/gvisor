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

//go:build freebsd

// Package porttest exercises the FreeBSD host layer of the gVisor port
// against a real FreeBSD kernel. Each test covers one primitive that was
// re-implemented for FreeBSD (kqueue for epoll, _umtx_op for futex,
// shm_open2 for memfd, FreeBSD ucontext offsets in safecopy, ...).
//
// Build on any host and run on FreeBSD:
//
//	GOOS=freebsd GOARCH=amd64 go test -c -o porttest.test ./test/freebsd/porttest
package porttest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bsdsys"
	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safecopy"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/waiter"
)

// safecopy's hand-written signal handler must recover from SIGSEGV using
// FreeBSD ucontext/siginfo offsets.
func TestSafecopySegv(t *testing.T) {
	m, err := unix.Mmap(-1, 0, 4096, unix.PROT_NONE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(m)
	addr := uintptr(unsafe.Pointer(&m[0]))

	buf := make([]byte, 16)
	n, err := safecopy.CopyIn(buf, unsafe.Pointer(addr+8))
	var segv safecopy.SegvError
	if !errors.As(err, &segv) {
		t.Fatalf("CopyIn from PROT_NONE: n=%d err=%v, want SegvError", n, err)
	}
	if segv.Addr != addr+8 {
		t.Errorf("SegvError.Addr = %#x, want %#x", segv.Addr, addr+8)
	}
	if _, err := safecopy.SwapUint32(unsafe.Pointer(addr), 1); !errors.As(err, &segv) {
		t.Errorf("SwapUint32 on PROT_NONE: err=%v, want SegvError", err)
	}
}

// SIGBUS is 10 on FreeBSD (7 on Linux): touching a file mapping beyond EOF.
func TestSafecopyBus(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "bus"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(8192); err != nil {
		t.Fatal(err)
	}
	m, err := unix.Mmap(int(f.Fd()), 0, 8192, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(m)
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_, err = safecopy.CopyIn(buf, unsafe.Pointer(&m[4096]))
	var bus safecopy.BusError
	var segv safecopy.SegvError
	switch {
	case errors.As(err, &bus):
	case errors.As(err, &segv):
		t.Logf("FreeBSD reported SIGSEGV (not SIGBUS) beyond EOF; recovered at %#x", segv.Addr)
	default:
		t.Fatalf("CopyIn beyond EOF: err=%v, want BusError", err)
	}
}

// Host errnos (FreeBSD numbering) must translate to Linux errnos.
func TestSyserrTranslation(t *testing.T) {
	for _, tc := range []struct {
		host unix.Errno
		want uint32
	}{
		{unix.EAGAIN, 11},        // FreeBSD 35
		{unix.ENOTSUP, 95},       // == EOPNOTSUPP on FreeBSD (45)
		{unix.ETIMEDOUT, 110},    // FreeBSD 60
		{unix.Errno(94), 1},      // ECAPMODE -> EPERM
		{unix.Errno(93), 1},      // ENOTCAPABLE -> EPERM
		{unix.ENAMETOOLONG, 36},  // FreeBSD 63
		{unix.ECONNREFUSED, 111}, // FreeBSD 61
	} {
		e := syserr.FromError(tc.host)
		if got := uint32(e.ToLinux()); got != tc.want {
			t.Errorf("host errno %d (%v) -> Linux %d, want %d", tc.host, tc.host, got, tc.want)
		}
	}
}

func TestHostsyscall(t *testing.T) {
	r, e := hostsyscall.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
	if e != 0 || int(r) != os.Getpid() {
		t.Errorf("getpid: r=%d e=%v, want %d", r, e, os.Getpid())
	}
	// FreeBSD signals failure with CF=1 and a positive errno.
	if _, e := hostsyscall.RawSyscall(unix.SYS_CLOSE, ^uintptr(0), 0, 0); e != unix.EBADF {
		t.Errorf("close(-1): errno=%v, want EBADF", e)
	}
	if e := hostsyscall.RawSyscallErrno6(unix.SYS_CLOSE, ^uintptr(0), 0, 0, 0, 0, 0); e != unix.EBADF {
		t.Errorf("RawSyscallErrno6 close(-1): %v, want EBADF", e)
	}
}

func TestEventfd(t *testing.T) {
	ev, err := eventfd.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	if err := ev.Write(3); err != nil {
		t.Fatal(err)
	}
	if err := ev.Write(4); err != nil {
		t.Fatal(err)
	}
	v, err := ev.Read()
	if err != nil || v != 7 {
		t.Fatalf("Read = %d, %v; want 7", v, err)
	}
}

// fdnotifier on kqueue: an edge on a pipe reaches the waiter queue.
func TestFdnotifier(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])

	var q waiter.Queue
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	q.EventRegister(&e)
	defer q.EventUnregister(&e)
	if err := fdnotifier.AddFD(int32(p[0]), &q); err != nil {
		t.Fatal(err)
	}
	defer fdnotifier.RemoveFD(int32(p[0]))

	if m := fdnotifier.NonBlockingPoll(int32(p[0]), waiter.ReadableEvents); m != 0 {
		t.Errorf("empty pipe readable: %v", m)
	}
	if _, err := unix.Write(p[1], []byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no readable notification from kqueue")
	}
	if m := fdnotifier.NonBlockingPoll(int32(p[0]), waiter.ReadableEvents); m&waiter.ReadableEvents == 0 {
		t.Errorf("NonBlockingPoll after write = %v, want readable", m)
	}

	// Edge-triggered: a second write must notify again.
	if _, err := unix.Write(p[1], []byte("y")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no second notification (EV_CLEAR edge)")
	}

	// Writer close -> HUp/RdHUp via EV_EOF.
	he, hch := waiter.NewChannelEntry(waiter.EventHUp)
	q.EventRegister(&he)
	defer q.EventUnregister(&he)
	fdnotifier.UpdateFD(int32(p[0]))
	unix.Close(p[1])
	p[1] = -1
	select {
	case <-hch:
	case <-time.After(2 * time.Second):
		t.Fatal("no HUp notification on writer close")
	}
}

// flipcall across two separate mappings of one shm window: exercises the
// process-shared _umtx_op path used between Sentry and Gofer.
func TestFlipcall(t *testing.T) {
	pwa, err := flipcall.NewPacketWindowAllocator()
	if err != nil {
		t.Fatal(err)
	}
	defer pwa.Destroy()
	pwd, err := pwa.Allocate(flipcall.PacketWindowLengthForDataCap(4096))
	if err != nil {
		t.Fatal(err)
	}
	client, err := flipcall.NewEndpoint(flipcall.ClientSide, pwd)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	server, err := flipcall.NewEndpoint(flipcall.ServerSide, pwd)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Destroy()
	if client.DataAddr() == server.DataAddr() {
		t.Fatal("endpoints share a mapping; test would not cover shared umtx")
	}

	const rounds = 2000
	done := make(chan error, 1)
	go func() {
		n, err := server.RecvFirst()
		for i := 0; err == nil; i++ {
			// Echo back the request with each byte incremented.
			d := server.Data()[:n]
			for j := range d {
				d[j]++
			}
			n, err = server.SendRecv(n)
		}
		var se flipcall.ShutdownError
		if errors.As(err, &se) {
			err = nil
		}
		done <- err
	}()

	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rounds; i++ {
		msg := []byte{byte(i), byte(i >> 8), 7}
		copy(client.Data(), msg)
		n, err := client.SendRecv(uint32(len(msg)))
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		want := []byte{byte(i) + 1, byte(i>>8) + 1, 8}
		if got := client.Data()[:n]; !bytes.Equal(got, want) {
			t.Fatalf("round %d: got %v want %v", i, got, want)
		}
	}
	client.Shutdown()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not observe shutdown")
	}
}

// memfd -> shm_open2(SHM_ANON), and hole punching via fspacectl.
func TestMemFDAndPunchHole(t *testing.T) {
	fd, err := memutil.CreateMemFD("porttest", 0x1 /* MFD_CLOEXEC */)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	const size = 4 * 4096
	if err := unix.Ftruncate(fd, size); err != nil {
		t.Fatal(err)
	}
	m, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(m)
	for i := range m {
		m[i] = 0xaa
	}
	if err := bsdsys.FspacectlDealloc(fd, 4096, 2*4096); err != nil {
		t.Fatalf("fspacectl on shm: %v", err)
	}
	if m[4096] != 0 || m[3*4096-1] != 0 {
		t.Errorf("punched range not zero: %#x %#x", m[4096], m[3*4096-1])
	}
	if m[0] != 0xaa || m[3*4096] != 0xaa {
		t.Errorf("outside punched range changed: %#x %#x", m[0], m[3*4096])
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Size != size {
		t.Errorf("size after punch = %d (%v), want %d (KEEP_SIZE)", st.Size, err, size)
	}
}

func TestMembarrier(t *testing.T) {
	mask, err := bsdsys.Membarrier(bsdsys.MEMBARRIER_CMD_QUERY, 0)
	if err != nil {
		t.Fatalf("membarrier(QUERY): %v", err)
	}
	t.Logf("membarrier commands supported: %#x", mask)
	if mask&bsdsys.MEMBARRIER_CMD_GLOBAL == 0 {
		t.Errorf("MEMBARRIER_CMD_GLOBAL not supported")
	}
}

// hostfd.Preadv2: offset -1 must use the file position (readv), and an
// explicit offset must not move it (preadv).
func TestHostfdPreadv2(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "pread")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("0123456789"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(2, 0); err != nil {
		t.Fatal(err)
	}
	fd := int32(f.Fd())

	a, b := make([]byte, 3), make([]byte, 2)
	two := safemem.BlockSeqFromSlice([]safemem.Block{safemem.BlockFromSafeSlice(a), safemem.BlockFromSafeSlice(b)})
	n, err := hostfd.Preadv2(fd, two, -1, 0)
	if err != nil || n != 5 || string(a)+string(b) != "23456" {
		t.Fatalf("Preadv2(-1) = %d %v %q%q, want 5 \"23456\"", n, err, a, b)
	}
	n, err = hostfd.Preadv2(fd, two, 0, 0)
	if err != nil || n != 5 || string(a)+string(b) != "01234" {
		t.Fatalf("Preadv2(0) = %d %v %q%q, want 5 \"01234\"", n, err, a, b)
	}
	if off, _ := f.Seek(0, 1); off != 7 {
		t.Errorf("file offset = %d, want 7 (explicit offset must not move it)", off)
	}
	if _, err := hostfd.Preadv2(fd, two, 0, linux.RWF_HIPRI); !errors.Is(err, unix.EOPNOTSUPP) {
		t.Errorf("RWF_HIPRI: err=%v, want EOPNOTSUPP", err)
	}
}

// unet over AF_UNIX with SCM_RIGHTS: Msghdr Controllen/Iovlen widths differ
// from Linux.
func TestUnetPassFD(t *testing.T) {
	a, b, err := unet.SocketPair(false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	f, err := os.CreateTemp(t.TempDir(), "passfd")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString("hello")

	w := a.Writer(true)
	w.ControlMessage.PackFDs(int(f.Fd()))
	if _, err := w.WriteVec([][]byte{[]byte("ab"), []byte("cd")}); err != nil {
		t.Fatal(err)
	}

	r := b.Reader(true)
	r.EnableFDs(1)
	buf := make([]byte, 8)
	n, err := r.ReadVec([][]byte{buf})
	if err != nil || string(buf[:n]) != "abcd" {
		t.Fatalf("ReadVec = %d %v %q", n, err, buf[:n])
	}
	fds, err := r.ExtractFDs()
	if err != nil || len(fds) != 1 {
		t.Fatalf("ExtractFDs = %v %v", fds, err)
	}
	defer unix.Close(fds[0])
	got := make([]byte, 5)
	if _, err := unix.Pread(fds[0], got, 0); err != nil || string(got) != "hello" {
		t.Errorf("passed fd reads %q (%v), want hello", got, err)
	}
}
