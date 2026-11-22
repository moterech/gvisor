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

// Package rawfile contains utilities for using raw host files on FreeBSD.
//
// This is the subset the Sentry needs (eventfd, host fds). The mmsg-based
// helpers used only by the Linux packet-socket link endpoints are not
// provided: FreeBSD's sendmmsg/recvmmsg are libc wrappers, not syscalls,
// and those endpoints are not built for FreeBSD.
package rawfile

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// SizeofIovec is the size of a unix.Iovec in bytes.
const SizeofIovec = unsafe.Sizeof(unix.Iovec{})

// MaxIovs is the maximum number of iovecs host APIs accept (IOV_MAX).
const MaxIovs = 1024

// IovecFromBytes returns a unix.Iovec representing bs.
func IovecFromBytes(bs []byte) unix.Iovec {
	iov := unix.Iovec{
		Base: &bs[0],
	}
	iov.SetLen(len(bs))
	return iov
}

// AppendIovecFromBytes returns append(iovs, IovecFromBytes(bs)). If len(bs) ==
// 0, AppendIovecFromBytes returns iovs without modification. If len(iovs) >=
// max, AppendIovecFromBytes replaces the final iovec in iovs with one that
// also includes the contents of bs.
func AppendIovecFromBytes(iovs []unix.Iovec, bs []byte, max int) []unix.Iovec {
	if len(bs) == 0 {
		return iovs
	}
	if len(iovs) < max {
		return append(iovs, IovecFromBytes(bs))
	}
	iovs[len(iovs)-1] = IovecFromBytes(append(
		unsafe.Slice(iovs[len(iovs)-1].Base, iovs[len(iovs)-1].Len), bs...))
	return iovs
}

// NonBlockingWrite writes the given buffer to a file descriptor. It fails if
// partial data is written.
func NonBlockingWrite(fd int, buf []byte) unix.Errno {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}
	_, _, e := unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	return e
}

// NonBlockingWriteIovec writes iovec to a file descriptor in a single syscall.
// It fails if partial data is written.
func NonBlockingWriteIovec(fd int, iovec []unix.Iovec) unix.Errno {
	iovecLen := uintptr(len(iovec))
	_, _, e := unix.RawSyscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), iovecLen)
	return e
}

// PollEvent represents the pollfd structure passed to a poll() system call.
type PollEvent struct {
	FD      int32
	Events  int16
	Revents int16
}

// BlockingPoll is ppoll(2). Linux uses a hand-written variant that avoids a
// scheduler round trip; unix.Syscall6 is used here until that is measured to
// matter on FreeBSD.
func BlockingPoll(fds *PollEvent, nfds int, timeout *unix.Timespec) (int, unix.Errno) {
	n, _, e := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(fds)), uintptr(nfds),
		uintptr(unsafe.Pointer(timeout)), 0, 0, 0)
	return int(n), e
}

// BlockingRead reads from a file descriptor that is set up as non-blocking.
// If no data is available, it will block in a poll() syscall until the file
// descriptor becomes readable.
func BlockingRead(fd int, b []byte) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if e == 0 {
			return int(n), 0
		}

		event := PollEvent{
			FD:     int32(fd),
			Events: unix.POLLIN,
		}

		_, e = BlockingPoll(&event, 1, nil)
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

// BlockingReadvUntilStopped reads from a non-blocking fd into iovecs,
// blocking in ppoll until fd is readable or efd signals stop (returns -1).
func BlockingReadvUntilStopped(efd int, fd int, iovecs []unix.Iovec) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		if e == 0 {
			return int(n), 0
		}
		if e != unix.EWOULDBLOCK {
			return 0, e
		}
		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

// BlockingPollUntilStopped polls for events on fd or until a stop is signalled
// on the event fd efd. Returns true if stopped, i.e., efd has event POLLIN.
func BlockingPollUntilStopped(efd int, fd int, events int16) (bool, unix.Errno) {
	pevents := [...]PollEvent{
		{FD: int32(efd), Events: unix.POLLIN},
		{FD: int32(fd), Events: events},
	}
	_, errno := BlockingPoll(&pevents[0], len(pevents), nil)
	if errno != 0 {
		return pevents[0].Revents&unix.POLLIN != 0, errno
	}
	if pevents[1].Revents&unix.POLLHUP != 0 || pevents[1].Revents&unix.POLLERR != 0 {
		errno = unix.ECONNRESET
	}
	return pevents[0].Revents&unix.POLLIN != 0, errno
}
