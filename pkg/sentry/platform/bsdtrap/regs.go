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
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

// mcontext is FreeBSD/amd64 mcontext_t (800 bytes, <x86/ucontext.h>).
type mcontext struct {
	Onstack      int64
	Rdi          uint64
	Rsi          uint64
	Rdx          uint64
	Rcx          uint64
	R8           uint64
	R9           uint64
	Rax          uint64
	Rbx          uint64
	Rbp          uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Trapno       uint32
	Fs           uint16
	Gs           uint16
	Addr         uint64
	Flags        uint32
	Es           uint16
	Ds           uint16
	Err          uint64
	Rip          uint64
	Cs           uint64
	Rflags       uint64
	Rsp          uint64
	Ss           uint64
	Len          int64
	Fpformat     int64
	Ownedfp      int64
	Fpstate      [512]byte
	Fsbase       uint64
	Gsbase       uint64
	Xfpustate    uint64
	XfpustateLen uint64
	Spare        [4]int64
}

var _ [800]byte = [unsafe.Sizeof(mcontext{})]byte{}
var _ [224]byte = [unsafe.Offsetof(mcontext{}.Fpstate)]byte{}
var _ [736]byte = [unsafe.Offsetof(mcontext{}.Fsbase)]byte{}

// siginfo is the prefix of FreeBSD/amd64 siginfo_t that we read.
type siginfo struct {
	Signo  int32
	Errno  int32
	Code   int32
	Pid    int32
	UID    uint32
	Status int32
	Addr   uint64
	Value  uint64
	Trapno int32 // _reason._fault._trapno
}

const (
	mcHasBases    = 0x2
	mcHasFPXState = 0x4

	// pslUserChange are the rflags bits user code may change (FreeBSD
	// PSL_USERCHANGE); sigreturn rejects changes to any other bit.
	pslUserChange = 0x254dd5

	// Linux user segment selectors, reported to the Sentry.
	linuxUserCS = 0x33
	linuxUserDS = 0x2b

	// x86 page-fault error code bits (mc_err for T_PAGEFLT).
	pfWrite = 0x2
	pfInstr = 0x10

	tPageFault = 12 // T_PAGEFLT
)

// FreeBSD -> Linux numbers for the signals a stub thread can report.
// Fault si_codes (SEGV_*, BUS_*, ILL_*, FPE_*, TRAP_*) have the same values.
var hostToLinuxSignal = map[int32]linux.Signal{
	4:  linux.SIGILL,
	5:  linux.SIGTRAP,
	8:  linux.SIGFPE,
	10: linux.SIGBUS,
	11: linux.SIGSEGV,
	12: linux.SIGSYS,
}

const (
	hostSIGSYS  = 12
	hostSIGSEGV = 11
	hostSIGBUS  = 10
	hostSIGUSR1 = 30 // platform interrupt
)

// toPtraceRegs converts a stub mcontext to Linux registers. gsb.ko has
// already given rcx/r11/r10 Linux post-syscall semantics.
func toPtraceRegs(mc *mcontext, r *arch.Registers) {
	r.R15, r.R14, r.R13, r.R12 = mc.R15, mc.R14, mc.R13, mc.R12
	r.Rbp, r.Rbx, r.R11, r.R10 = mc.Rbp, mc.Rbx, mc.R11, mc.R10
	r.R9, r.R8, r.Rax, r.Rcx = mc.R9, mc.R8, mc.Rax, mc.Rcx
	r.Rdx, r.Rsi, r.Rdi = mc.Rdx, mc.Rsi, mc.Rdi
	r.Orig_rax = ^uint64(0)
	r.Rip = mc.Rip
	r.Cs = linuxUserCS
	r.Eflags = mc.Rflags
	r.Rsp = mc.Rsp
	r.Ss = linuxUserDS
	r.Fs_base = mc.Fsbase
	r.Gs_base = mc.Gsbase
	r.Ds, r.Es, r.Fs, r.Gs = 0, 0, 0, 0
}

// fromPtraceRegs builds the mcontext to resume with. tmpl supplies
// everything Linux registers don't determine (selectors, non-user rflags,
// mc_len, FP format), from the thread's last event.
func fromPtraceRegs(r *arch.Registers, tmpl *mcontext, mc *mcontext) {
	*mc = *tmpl
	mc.R15, mc.R14, mc.R13, mc.R12 = r.R15, r.R14, r.R13, r.R12
	mc.Rbp, mc.Rbx, mc.R11, mc.R10 = r.Rbp, r.Rbx, r.R11, r.R10
	mc.R9, mc.R8, mc.Rax, mc.Rcx = r.R9, r.R8, r.Rax, r.Rcx
	mc.Rdx, mc.Rsi, mc.Rdi = r.Rdx, r.Rsi, r.Rdi
	mc.Rip = r.Rip
	mc.Rsp = r.Rsp
	mc.Rflags = (tmpl.Rflags &^ pslUserChange) | (r.Eflags & pslUserChange)
	mc.Fsbase = r.Fs_base
	mc.Gsbase = r.Gs_base
	mc.Flags |= mcHasBases
	mc.Onstack = 0
}

// fpToHost splits the Sentry's XSAVE image into FreeBSD's legacy area and
// extended state. Returns the number of extended bytes to pass (xlen as
// last reported by the host for this thread).
func fpToHost(fp fpu.State, mc *mcontext, xfpu []byte, xlen int) int {
	b := fp.Slice()
	copy(mc.Fpstate[:], b)
	if xlen <= 0 || len(b) < 512 {
		return 0
	}
	if xlen > len(b)-512 {
		xlen = len(b) - 512
	}
	return copy(xfpu[:xlen], b[512:])
}

// fpFromHost assembles the Sentry's XSAVE image from the host state.
func fpFromHost(fp fpu.State, mc *mcontext, xfpu []byte) {
	b := fp.Slice()
	copy(b, mc.Fpstate[:])
	if len(xfpu) > 0 && len(b) > 512 {
		copy(b[512:], xfpu)
	}
}

// faultAccess derives the access type of a fault from the page-fault error
// code, which FreeBSD exposes in mc_err (ptrace cannot, hence its guesses).
func faultAccess(mc *mcontext, addr uint64) hostarch.AccessType {
	at := hostarch.Read
	if mc.Trapno == tPageFault {
		if mc.Err&pfWrite != 0 {
			at.Write = true
		}
		if mc.Err&pfInstr != 0 {
			at.Execute = true
		}
		return at
	}
	if addr == mc.Rip {
		at.Execute = true
	}
	return at
}
