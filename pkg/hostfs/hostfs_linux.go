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

// Package hostfs provides the Linux-shaped host filesystem syscalls the
// Sentry uses (statx, fallocate, fdatasync, statfs, and a few open/at
// flags), so that callers can be written once. On Linux every name is an
// alias for golang.org/x/sys/unix; on other hosts the package emulates them.
//
// Masks passed to Statx and returned in Statx_t.Mask use the Linux statx(2)
// encoding (linux.STATX_*), as do Fallocate modes.
package hostfs

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// Statx_t is struct statx.
type Statx_t = unix.Statx_t

// StatxTimestamp is struct statx_timestamp.
type StatxTimestamp = unix.StatxTimestamp

// Host open(2) and *at(2) flags that x/sys/unix does not define everywhere.
const (
	AT_EMPTY_PATH   = unix.AT_EMPTY_PATH
	AT_NO_AUTOMOUNT = unix.AT_NO_AUTOMOUNT
	O_PATH          = unix.O_PATH
	O_DSYNC         = unix.O_DSYNC
)

// Statx is statx(2).
func Statx(dirfd int, path string, flags int, mask int, stat *Statx_t) error {
	return unix.Statx(dirfd, path, flags, mask, stat)
}

// Fallocate is fallocate(2); mode uses Linux FALLOC_FL_* values.
func Fallocate(fd int, mode uint32, off, length int64) error {
	return unix.Fallocate(fd, mode, off, length)
}

// Fdatasync is fdatasync(2).
func Fdatasync(fd int) error {
	return unix.Fdatasync(fd)
}

// Fstatfs returns fstatfs(2) for fd as a linux.Statfs.
func Fstatfs(fd int) (linux.Statfs, error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(fd, &s); err != nil {
		return linux.Statfs{}, err
	}
	return linux.Statfs{
		Type:            uint64(s.Type),
		BlockSize:       s.Bsize,
		FragmentSize:    s.Bsize,
		Blocks:          s.Blocks,
		BlocksFree:      s.Bfree,
		BlocksAvailable: s.Bavail,
		Files:           s.Files,
		FilesFree:       s.Ffree,
		NameLength:      uint64(s.Namelen),
	}, nil
}

// OpenFlagsToLinux converts host open(2)/F_GETFL flags to Linux flags. On
// Linux this is the identity.
func OpenFlagsToLinux(hostFlags int) uint32 {
	return uint32(hostFlags)
}
