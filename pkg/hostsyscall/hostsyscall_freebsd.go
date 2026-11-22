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

// Package hostsyscall provides functions like unix.RawSyscall, but without the
// overhead of multiple stack frame allocations.
//
// On FreeBSD a failed syscall sets the carry flag and returns the (positive)
// errno in %rax, instead of Linux's negative return value.
package hostsyscall

import (
	"golang.org/x/sys/unix"
)

// RawSyscall6 is a copy of runtime.Syscall6.
func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1 uintptr, errno unix.Errno)

// RawSyscall is a copy of runtime.Syscall6, but only uses the first three arguments.
func RawSyscall(trap, a1, a2, a3 uintptr) (r1 uintptr, errno unix.Errno)

// RawSyscallErrno6 is like RawSyscall6, but only returns errno,
// and 0 if successful.
func RawSyscallErrno6(trap, a1, a2, a3, a4, a5, a6 uintptr) unix.Errno

// RawSyscallErrno is like RawSyscall, but only returns errno,
// and 0 if successful.
func RawSyscallErrno(trap, a1, a2, a3 uintptr) unix.Errno
