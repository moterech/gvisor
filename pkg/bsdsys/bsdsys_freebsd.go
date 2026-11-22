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

// Package bsdsys collects the FreeBSD host interfaces that the gVisor port
// needs but golang.org/x/sys/unix does not (yet) provide: syscalls added in
// FreeBSD 13-15 and a few kernel ABI structs. Keeping them in one place keeps
// the rest of the FreeBSD port a thin layer of *_freebsd.go files.
//
// Numbers and layouts are from FreeBSD 15.1-RELEASE <sys/syscall.h> and
// friends (amd64).
package bsdsys

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Syscall numbers missing from x/sys/unix.
const (
	SYS_SHM_OPEN2       = 571
	SYS_SPECIALFD       = 577 // __specialfd(2): eventfd, inotify
	SYS_FSPACECTL       = 580
	SYS_SCHED_GETCPU    = 581
	SYS_KQUEUEX         = 583
	SYS_MEMBARRIER      = 584
	SYS_TIMERFD_CREATE  = 585
	SYS_TIMERFD_GETTIME = 586
	SYS_TIMERFD_SETTIME = 587
	SYS_PDWAIT          = 601
)

// _umtx_op(2) operations (<sys/umtx.h>).
const (
	UMTX_OP_WAKE              = 3
	UMTX_OP_WAIT_UINT         = 11
	UMTX_OP_WAIT_UINT_PRIVATE = 15
	UMTX_OP_WAKE_PRIVATE      = 16
)

// __specialfd(2) / eventfd(2) (<sys/specialfd.h>, <sys/eventfd.h>).
const (
	SPECIALFD_EVENTFD = 1

	EFD_SEMAPHORE = 0x1
	EFD_NONBLOCK  = 0x4
	EFD_CLOEXEC   = 0x100000
)

// open(2)/*at(2) flags added after the x/sys/unix tables were generated
// (<sys/fcntl.h>).
const (
	O_VERIFY          = 0x00200000
	O_PATH            = 0x00400000
	O_RESOLVE_BENEATH = 0x00800000
	O_DSYNC           = 0x01000000
	O_EMPTY_PATH      = 0x02000000

	AT_RESOLVE_BENEATH = 0x2000
	AT_EMPTY_PATH      = 0x4000
)

// shm_open2(2) (<sys/mman.h>).
const (
	SHM_ANON          = 1 // (char *)1
	SHM_ALLOW_SEALING = 0x1
)

// fspacectl(2) (<sys/fcntl.h>).
const SPACECTL_DEALLOC = 1

// membarrier(2) (<sys/membarrier.h>); values match Linux.
const (
	MEMBARRIER_CMD_QUERY                      = 0x0
	MEMBARRIER_CMD_GLOBAL                     = 0x1
	MEMBARRIER_CMD_GLOBAL_EXPEDITED           = 0x2
	MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED  = 0x4
	MEMBARRIER_CMD_PRIVATE_EXPEDITED          = 0x8
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED = 0x10
)

// ioctl requests missing from x/sys/unix (<sys/filio.h>).
const FIONREAD = 0x4004667f

// Signal and poll details that differ from Linux.
const (
	// SI_USER is the lowest si_code of a user-generated signal; codes
	// below it (and above zero) come from the kernel.
	SI_USER = 0x10001

	POLLRDHUP = 0x4000
)

// Sigaction is struct sigaction on FreeBSD/amd64 (32 bytes):
// handler at 0, sa_flags at 8, sa_mask at 12.
type Sigaction struct {
	Handler uintptr
	Flags   int32
	Mask    [4]uint32
	_       uint32
}

var _ [32]byte = [unsafe.Sizeof(Sigaction{})]byte{}

// Eventfd creates an eventfd(2) descriptor.
func Eventfd(initval uint32, flags int) (int, error) {
	args := struct {
		initval uint32
		flags   int32
	}{initval, int32(flags)}
	fd, _, e := unix.RawSyscall(SYS_SPECIALFD, SPECIALFD_EVENTFD,
		uintptr(unsafe.Pointer(&args)), unsafe.Sizeof(args))
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

// ShmAnon creates an anonymous shared memory object, FreeBSD's memfd.
// name is only a debugging label.
func ShmAnon(name string, flags, shmflags int) (int, error) {
	p, err := unix.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	fd, _, e := unix.Syscall6(SYS_SHM_OPEN2, SHM_ANON, uintptr(flags|unix.O_RDWR),
		0600, uintptr(shmflags), uintptr(unsafe.Pointer(p)), 0)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

// FspacectlDealloc punches a hole in fd: FreeBSD's
// fallocate(FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE).
func FspacectlDealloc(fd int, off, length int64) error {
	rqsr := struct{ off, len int64 }{off, length}
	for rqsr.len > 0 {
		var rmsr struct{ off, len int64 }
		_, _, e := unix.Syscall6(SYS_FSPACECTL, uintptr(fd), SPACECTL_DEALLOC,
			uintptr(unsafe.Pointer(&rqsr)), 0, uintptr(unsafe.Pointer(&rmsr)), 0)
		if e == unix.EINTR {
			rqsr = rmsr
			continue
		}
		if e != 0 {
			return e
		}
		return nil
	}
	return nil
}

// Membarrier issues membarrier(2).
func Membarrier(cmd, flags int) (int, error) {
	r, _, e := unix.RawSyscall(SYS_MEMBARRIER, uintptr(cmd), uintptr(flags), 0)
	if e != 0 {
		return 0, e
	}
	return int(r), nil
}

// UmtxWaitUint blocks while *addr == val. shared selects the
// process-shared variant, needed for memory shared between processes.
// EINTR and EAGAIN-style spurious wakeups are returned as nil, like
// FUTEX_WAIT callers in gVisor expect.
func UmtxWaitUint(addr uintptr, val uint32, shared bool) error {
	op := uintptr(UMTX_OP_WAIT_UINT_PRIVATE)
	if shared {
		op = UMTX_OP_WAIT_UINT
	}
	_, _, e := unix.Syscall6(unix.SYS__UMTX_OP, addr, op, uintptr(val), 0, 0, 0)
	if e != 0 && e != unix.EINTR && e != unix.EAGAIN {
		return e
	}
	return nil
}

// UmtxWake wakes up to n waiters blocked on addr.
func UmtxWake(addr uintptr, n int, shared bool) error {
	op := uintptr(UMTX_OP_WAKE_PRIVATE)
	if shared {
		op = UMTX_OP_WAKE
	}
	if _, _, e := unix.RawSyscall6(unix.SYS__UMTX_OP, addr, op, uintptr(n), 0, 0, 0); e != 0 {
		return e
	}
	return nil
}
