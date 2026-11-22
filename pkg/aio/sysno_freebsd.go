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

package aio

import "golang.org/x/sys/unix"

// GoQueue always passes an explicit offset, and zero RWF flags, so the plain
// positional syscalls are equivalent. (LinuxQueue, io_submit-based, is not
// available on FreeBSD.)
const (
	sysPread   = unix.SYS_PREAD
	sysPwrite  = unix.SYS_PWRITE
	sysPreadv  = unix.SYS_PREADV
	sysPwritev = unix.SYS_PWRITEV
)

// LinuxQueue is Linux native AIO (io_setup/io_submit). FreeBSD has POSIX
// aio(4) instead, which is not wired up; callers fall back to GoQueue.
type LinuxQueue = GoQueue

// NewLinuxQueue always fails on FreeBSD.
func NewLinuxQueue(cap int) (*LinuxQueue, error) {
	return nil, unix.ENOSYS
}
