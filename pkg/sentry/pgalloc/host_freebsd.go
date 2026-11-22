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

package pgalloc

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bsdsys"
)

// madvInvalid is rejected by FreeBSD's madvise(2) with EINVAL.
const madvInvalid = 0x7fffffff

const (
	// FreeBSD promotes superpages automatically; there are no THP hints.
	// MemoryFileOpts.Advise{No,}Hugepage should stay false on FreeBSD; if
	// set, madvise fails and the failure is logged.
	madvHugepage   = madvInvalid
	madvNoHugepage = madvInvalid

	// No MADV_POPULATE_WRITE; EINVAL makes tryPopulateMadv disable itself
	// and fall back to mlock-based population.
	madvPopulateWrite = madvInvalid

	fallocPunchHoleKeepSize = 0x3 // FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE
)

// hostFallocate implements the two fallocate(2) modes MemoryFile uses.
func hostFallocate(fd int, mode uint32, off, length int64) error {
	switch mode {
	case 0:
		// posix_fallocate(2) returns the error as its value, not via errno.
		r, _, e := unix.Syscall(unix.SYS_POSIX_FALLOCATE, uintptr(fd), uintptr(off), uintptr(length))
		if e == 0 && r != 0 {
			e = unix.Errno(r)
		}
		switch e {
		case 0:
			return nil
		case unix.EINVAL, unix.ENODEV, unix.EOPNOTSUPP:
			// Committing is an optimisation; memory is allocated on
			// first touch if the object can't preallocate.
			return nil
		default:
			return e
		}
	case fallocPunchHoleKeepSize:
		return bsdsys.FspacectlDealloc(fd, off, length)
	default:
		return unix.EOPNOTSUPP
	}
}
