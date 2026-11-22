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
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

func TestMain(m *testing.M) {
	// As at Sentry startup: FP state sizing needs the host feature set.
	cpuid.Initialize()
	os.Exit(m.Run())
}

// Linux/amd64 machine code snippets, at fixed offsets in the code page.
var snippets = map[string][]byte{
	// getpid(); exit(result)
	"syscalls": {
		0xb8, 0x27, 0, 0, 0, // mov $39, %eax
		0x0f, 0x05, //          syscall
		0x48, 0x89, 0xc7, //    mov %rax, %rdi
		0xb8, 0x3c, 0, 0, 0, // mov $60, %eax
		0x0f, 0x05, //          syscall
	},
	"read":  {0x48, 0x8b, 0x04, 0x25, 0x00, 0x50, 0x34, 0x12},                         // mov 0x12345000, %rax
	"write": {0x48, 0xc7, 0x04, 0x25, 0x00, 0x50, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00}, // movq $1, 0x12345000
	"exec":  {0x48, 0xb8, 0x00, 0x50, 0x34, 0x12, 0, 0, 0, 0, 0xff, 0xe0},             // mov $0x12345000, %rax; jmp *%rax
	"spin":  {0xeb, 0xfe},                                                             // jmp .
	"tlsfp": {
		0x66, 0x48, 0x0f, 0x7e, 0xc6, // movq %xmm0, %rsi
		0x66, 0x48, 0x0f, 0x6e, 0xce, // movq %rsi, %xmm1
		0x64, 0x48, 0x8b, 0x3c, 0x25, 0, 0, 0, 0, // mov %fs:0, %rdi
		0xb8, 0xe8, 0x03, 0, 0, // mov $1000, %eax
		0x0f, 0x05, //             syscall
	},
	"data": {0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00}, // mov 0x500000, %rax
	// for (;;) getpid();
	"loop": {0xb8, 0x27, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xf7},
}

const (
	codeAddr  = 0x400000
	dataAddr  = 0x500000
	stackAddr = 0x600000
	page      = 4096
)

var offsets = map[string]uint64{}

// fakeFile is a memmap.File backed by a shm fd; only DataFD is used.
type fakeFile struct{ fd int }

func (f *fakeFile) IncRef(memmap.FileRange, uint32) {}
func (f *fakeFile) DecRef(memmap.FileRange)         {}
func (f *fakeFile) MapInternal(memmap.FileRange, hostarch.AccessType) (safemem.BlockSeq, error) {
	panic("unused")
}
func (f *fakeFile) MemoryType() hostarch.MemoryType              { return hostarch.MemoryTypeWriteBack }
func (f *fakeFile) BufferReadAt(uint64, []byte) (uint64, error)  { panic("unused") }
func (f *fakeFile) BufferWriteAt(uint64, []byte) (uint64, error) { panic("unused") }
func (f *fakeFile) DataFD(memmap.FileRange) (int, error)         { return f.fd, nil }
func (f *fakeFile) FD() int                                      { return f.fd }

// fakeMM supplies just AddressSpace(), all Switch needs.
type fakeMM struct {
	platform.MemoryManager
	as platform.AddressSpace
}

func (m fakeMM) AddressSpace() platform.AddressSpace { return m.as }

type env struct {
	p    *BSDTrap
	as   platform.AddressSpace
	mm   fakeMM
	file *fakeFile
}

func setup(t testing.TB) *env {
	t.Helper()
	if _, err := unix.SysctlUint64("security.gsb.redirects"); err != nil {
		t.Skip("gsb.ko not loaded")
	}
	path := os.Getenv("GSB_BSDTRAP_STUB")
	if path == "" {
		path = DefaultStubPath
	}
	p, err := New(path)
	if err != nil {
		t.Skip(err)
	}

	// One shm object: code page, data page, stack page.
	fd, err := memutil.CreateMemFD("bsdtrap-test", 0x1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Ftruncate(fd, 3*page); err != nil {
		t.Fatal(err)
	}
	m, err := unix.Mmap(fd, 0, 3*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	off := uint64(0)
	for _, name := range []string{"syscalls", "read", "write", "exec", "spin", "tlsfp", "data", "loop"} {
		offsets[name] = off
		off += uint64(copy(m[off:], snippets[name]))
	}
	binary.LittleEndian.PutUint64(m[page:], 0xdeadbeef)
	unix.Munmap(m)

	as, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(as.Release)
	e := &env{p: p, as: as, mm: fakeMM{as: as}, file: &fakeFile{fd: fd}}
	for _, mp := range []struct {
		addr hostarch.Addr
		off  uint64
		at   hostarch.AccessType
	}{
		{codeAddr, 0, hostarch.ReadExecute},
		{dataAddr, page, hostarch.ReadWrite},
		{stackAddr, 2 * page, hostarch.ReadWrite},
	} {
		if err := as.MapFile(mp.addr, e.file, memmap.FileRange{Start: mp.off, End: mp.off + page}, mp.at, false); err != nil {
			t.Fatalf("MapFile(%#x): %v", mp.addr, err)
		}
	}
	return e
}

func (e *env) newThread(t testing.TB, snippet string) (platform.Context, *arch.Context64) {
	c := e.p.NewContext(nil)
	t.Cleanup(c.Release)
	ac := arch.New(arch.AMD64)
	regs := &ac.StateData().Regs
	regs.Rip = codeAddr + offsets[snippet]
	regs.Rsp = stackAddr + page - 64
	return c, ac
}

func TestSyscalls(t *testing.T) {
	e := setup(t)
	c, ac := e.newThread(t, "syscalls")
	regs := &ac.StateData().Regs
	regs.R10 = 0x10101010

	info, _, err := c.Switch(nil, e.mm, ac, 0)
	if err != nil || info != nil {
		t.Fatalf("Switch: %v %v", info, err)
	}
	if regs.Orig_rax != 39 || regs.Rip != codeAddr+offsets["syscalls"]+7 {
		t.Fatalf("syscall %d at %#x, want getpid(39) at %#x", regs.Orig_rax, regs.Rip, codeAddr+offsets["syscalls"]+7)
	}
	if regs.R10 != 0x10101010 || regs.Rcx != regs.Rip || regs.R11 != regs.Eflags {
		t.Errorf("Linux syscall register semantics: r10=%#x rcx=%#x rip=%#x r11=%#x rflags=%#x", regs.R10, regs.Rcx, regs.Rip, regs.R11, regs.Eflags)
	}
	regs.Rax = 1234 // the Sentry's getpid result

	if _, _, err := c.Switch(nil, e.mm, ac, 0); err != nil {
		t.Fatal(err)
	}
	if regs.Orig_rax != 60 || regs.Rdi != 1234 {
		t.Errorf("second syscall %d(rdi=%d), want exit(1234)", regs.Orig_rax, regs.Rdi)
	}
}

func TestFaults(t *testing.T) {
	e := setup(t)
	for _, tc := range []struct {
		snippet     string
		write, exec bool
	}{
		{"read", false, false},
		{"write", true, false},
		{"exec", false, true},
	} {
		c, ac := e.newThread(t, tc.snippet)
		info, at, err := c.Switch(nil, e.mm, ac, 0)
		if !errors.Is(err, platform.ErrContextSignal) || info == nil {
			t.Fatalf("%s: Switch = %v, %v; want a signal", tc.snippet, info, err)
		}
		if linux.Signal(info.Signo) != linux.SIGSEGV || info.Addr() != 0x12345000 {
			t.Errorf("%s: signal %d addr %#x, want SIGSEGV at 0x12345000", tc.snippet, info.Signo, info.Addr())
		}
		if !at.Read || at.Write != tc.write || at.Execute != tc.exec {
			t.Errorf("%s: access %+v, want write=%v exec=%v", tc.snippet, at, tc.write, tc.exec)
		}
	}
}

func TestTLSAndFP(t *testing.T) {
	e := setup(t)
	c, ac := e.newThread(t, "tlsfp")
	if !ac.SetTLS(dataAddr) {
		t.Fatal("SetTLS")
	}
	fp := ac.FloatingPointData().Slice()
	binary.LittleEndian.PutUint64(fp[160:], 0x1122334455667788) // XMM0
	if _, _, err := c.Switch(nil, e.mm, ac, 0); err != nil {
		t.Fatal(err)
	}
	regs := &ac.StateData().Regs
	if regs.Orig_rax != 1000 {
		t.Fatalf("syscall %d, want 1000", regs.Orig_rax)
	}
	if regs.Rdi != 0xdeadbeef {
		t.Errorf("%%fs:0 = %#x, want 0xdeadbeef (fs_base not applied)", regs.Rdi)
	}
	if regs.Rsi != 0x1122334455667788 {
		t.Errorf("xmm0 = %#x (FP state not passed to the stub)", regs.Rsi)
	}
	if got := binary.LittleEndian.Uint64(ac.FloatingPointData().Slice()[176:]); got != 0x1122334455667788 {
		t.Errorf("xmm1 after = %#x (FP state not returned)", got)
	}
	if regs.Fs_base != dataAddr {
		t.Errorf("fs_base after = %#x", regs.Fs_base)
	}
}

func TestInterrupt(t *testing.T) {
	e := setup(t)
	c, ac := e.newThread(t, "spin")
	go func() {
		time.Sleep(100 * time.Millisecond)
		c.Interrupt()
	}()
	start := time.Now()
	_, _, err := c.Switch(nil, e.mm, ac, 0)
	if !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch = %v, want ErrContextInterrupt", err)
	}
	if rip := ac.StateData().Regs.Rip; rip != codeAddr+offsets["spin"] {
		t.Errorf("interrupted at %#x, want inside the spin loop", rip)
	}
	t.Logf("interrupted after %v", time.Since(start))
}

func TestThreadsShareAddressSpace(t *testing.T) {
	e := setup(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, ac := e.newThread(t, "syscalls")
			for n := 0; n < 200; n++ {
				regs := &ac.StateData().Regs
				regs.Rip = codeAddr + offsets["syscalls"]
				if _, _, err := c.Switch(nil, e.mm, ac, 0); err != nil || regs.Orig_rax != 39 {
					t.Errorf("thread %d iter %d: %v nr %d", i, n, err, regs.Orig_rax)
					return
				}
				regs.Rax = uint64(i*1000 + n)
				if _, _, err := c.Switch(nil, e.mm, ac, 0); err != nil || regs.Rdi != uint64(i*1000+n) {
					t.Errorf("thread %d iter %d: %v rdi %d", i, n, err, regs.Rdi)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestUnmap(t *testing.T) {
	e := setup(t)
	c, ac := e.newThread(t, "data")
	if _, _, err := c.Switch(nil, e.mm, ac, 0); !errors.Is(err, platform.ErrContextSignal) {
		// Mapped: the load succeeds and execution runs into zeroed code.
		t.Logf("first run: %v", err)
	}
	e.as.Unmap(dataAddr, page)
	c2, ac2 := e.newThread(t, "data")
	info, _, err := c2.Switch(nil, e.mm, ac2, 0)
	if !errors.Is(err, platform.ErrContextSignal) || info.Addr() != dataAddr {
		t.Fatalf("after Unmap: %v %v, want SIGSEGV at %#x", info, err, dataAddr)
	}
}

// BenchmarkSyscall measures one app syscall round trip through the
// platform: app -> gsb.ko SIGSYS -> stub -> Sentry -> stub -> sigreturn.
func BenchmarkSyscall(b *testing.B) {
	e := setup(b)
	c, ac := e.newThread(b, "loop")
	regs := &ac.StateData().Regs
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.Switch(nil, e.mm, ac, 0); err != nil || regs.Orig_rax != 39 {
			b.Fatalf("Switch: %v nr %d", err, regs.Orig_rax)
		}
		regs.Rax = 1
	}
}
