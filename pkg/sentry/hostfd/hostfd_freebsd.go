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

package hostfd

import "golang.org/x/sys/unix"

// MaxReadWriteIov is the maximum permitted size of a struct iovec array in a
// readv(2)/writev(2)/preadv(2)/pwritev(2) syscall (IOV_MAX).
const MaxReadWriteIov = 1024

// MaxSendRecvMsgIov is the maximum permitted size of a struct iovec array in a
// sendmsg(2)/recvmsg(2) syscall (IOV_MAX).
const MaxSendRecvMsgIov = 1024

// FreeBSD's pread/pwrite take a full 64-bit offset; there is no *64 variant.
const (
	sysPread64  = unix.SYS_PREAD
	sysPwrite64 = unix.SYS_PWRITE
)

// FreeBSD has no preadv2/pwritev2. offset == -1 means "current file
// position" to callers (as for Linux preadv2); preadv/pwritev reject a
// negative offset, so use readv/writev instead. The flags argument that
// iovecsReadWrite passes in the 6th slot is ignored by these syscalls.
func preadv2Sysno(offset int64) uintptr {
	if offset == -1 {
		return unix.SYS_READV
	}
	return unix.SYS_PREADV
}

func pwritev2Sysno(offset int64) uintptr {
	if offset == -1 {
		return unix.SYS_WRITEV
	}
	return unix.SYS_PWRITEV
}

// unsupportedRWFlags reports RWF_* flags the host cannot honour: FreeBSD
// supports none of them.
func unsupportedRWFlags(flags uint32) bool { return flags != 0 }
