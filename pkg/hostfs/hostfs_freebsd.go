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
// alias for golang.org/x/sys/unix; on FreeBSD they are emulated here.
//
// Masks passed to Statx and returned in Statx_t.Mask use the Linux statx(2)
// encoding (linux.STATX_*), as do Fallocate modes.
package hostfs

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bsdsys"
)

// StatxTimestamp mirrors Linux struct statx_timestamp.
type StatxTimestamp struct {
	Sec  int64
	Nsec uint32
	_    int32
}

// Statx_t mirrors the field names and types of x/sys/unix Statx_t on Linux,
// so code written against it compiles unchanged.
type Statx_t struct {
	Mask            uint32
	Blksize         uint32
	Attributes      uint64
	Nlink           uint32
	Uid             uint32
	Gid             uint32
	Mode            uint16
	_               [1]uint16
	Ino             uint64
	Size            uint64
	Blocks          uint64
	Attributes_mask uint64
	Atime           StatxTimestamp
	Btime           StatxTimestamp
	Ctime           StatxTimestamp
	Mtime           StatxTimestamp
	Rdev_major      uint32
	Rdev_minor      uint32
	Dev_major       uint32
	Dev_minor       uint32
	Mnt_id          uint64
}

// Host flags. AT_NO_AUTOMOUNT has no FreeBSD counterpart (there is no
// automount on *at() lookups) and is 0.
const (
	AT_EMPTY_PATH   = bsdsys.AT_EMPTY_PATH
	AT_NO_AUTOMOUNT = 0
	O_PATH          = bsdsys.O_PATH
	O_DSYNC         = bsdsys.O_DSYNC
)

// Linux fallocate(2) modes.
const (
	fallocKeepSize  = 0x1
	fallocPunchHole = 0x2
)

func statxTimestamp(ts unix.Timespec) StatxTimestamp {
	return StatxTimestamp{Sec: ts.Sec, Nsec: uint32(ts.Nsec)}
}

// Statx emulates statx(2) with fstatat(2). flags are host *at() flags; only
// AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH and AT_RESOLVE_BENEATH are meaningful.
// The returned mask is STATX_BASIC_STATS|STATX_BTIME regardless of the
// requested mask: FreeBSD always returns all of them, including birthtime.
func Statx(dirfd int, path string, flags int, mask int, stat *Statx_t) error {
	var s unix.Stat_t
	flags &= unix.AT_SYMLINK_NOFOLLOW | bsdsys.AT_EMPTY_PATH | bsdsys.AT_RESOLVE_BENEATH
	if err := unix.Fstatat(dirfd, path, &s, flags); err != nil {
		return err
	}
	*stat = Statx_t{
		Mask:       linux.STATX_BASIC_STATS | linux.STATX_BTIME,
		Blksize:    uint32(s.Blksize),
		Nlink:      uint32(s.Nlink),
		Uid:        s.Uid,
		Gid:        s.Gid,
		Mode:       s.Mode,
		Ino:        s.Ino,
		Size:       uint64(s.Size),
		Blocks:     uint64(s.Blocks),
		Atime:      statxTimestamp(s.Atim),
		Btime:      statxTimestamp(s.Btim),
		Ctime:      statxTimestamp(s.Ctim),
		Mtime:      statxTimestamp(s.Mtim),
		Rdev_major: unix.Major(s.Rdev),
		Rdev_minor: unix.Minor(s.Rdev),
		Dev_major:  unix.Major(s.Dev),
		Dev_minor:  unix.Minor(s.Dev),
	}
	return nil
}

// Fallocate emulates the fallocate(2) modes FreeBSD can express: 0
// (posix_fallocate) and PUNCH_HOLE|KEEP_SIZE (fspacectl). Others return
// EOPNOTSUPP, as Linux does for modes a filesystem does not support.
func Fallocate(fd int, mode uint32, off, length int64) error {
	switch mode {
	case 0:
		// posix_fallocate(2) returns its error as the value, not via errno.
		r, _, e := unix.Syscall(unix.SYS_POSIX_FALLOCATE, uintptr(fd), uintptr(off), uintptr(length))
		if e == 0 && r != 0 {
			e = unix.Errno(r)
		}
		if e != 0 {
			return e
		}
		return nil
	case fallocPunchHole | fallocKeepSize:
		return bsdsys.FspacectlDealloc(fd, off, length)
	default:
		return unix.EOPNOTSUPP
	}
}

// Fdatasync is fdatasync(2).
func Fdatasync(fd int) error {
	if _, _, e := unix.Syscall(unix.SYS_FDATASYNC, uintptr(fd), 0, 0); e != 0 {
		return e
	}
	return nil
}

// Fstatfs returns fstatfs(2) for fd as a linux.Statfs.
func Fstatfs(fd int) (linux.Statfs, error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(fd, &s); err != nil {
		return linux.Statfs{}, err
	}
	avail := s.Bavail
	if avail < 0 { // FreeBSD reports negative when over the reserve.
		avail = 0
	}
	ffree := s.Ffree
	if ffree < 0 {
		ffree = 0
	}
	return linux.Statfs{
		Type:            linuxFSMagic(s.Fstypename[:]),
		BlockSize:       int64(s.Bsize),
		FragmentSize:    int64(s.Bsize),
		Blocks:          s.Blocks,
		BlocksFree:      s.Bfree,
		BlocksAvailable: uint64(avail),
		Files:           s.Files,
		FilesFree:       uint64(ffree),
		NameLength:      uint64(s.Namemax),
	}, nil
}

// OpenFlagsToLinux converts host (FreeBSD) open(2)/F_GETFL flags to Linux
// flags. Only status flags that matter to an imported fd are kept; the
// access mode (O_RDONLY/O_WRONLY/O_RDWR) has the same encoding on both.
func OpenFlagsToLinux(hostFlags int) uint32 {
	l := uint32(hostFlags & unix.O_ACCMODE)
	for _, m := range [...]struct {
		host  int
		linux uint32
	}{
		{unix.O_NONBLOCK, linux.O_NONBLOCK},
		{unix.O_APPEND, linux.O_APPEND},
		{unix.O_ASYNC, linux.O_ASYNC},
		{unix.O_DIRECT, linux.O_DIRECT},
		{bsdsys.O_DSYNC, linux.O_DSYNC},
		{unix.O_SYNC, linux.O_SYNC},
		{unix.O_CLOEXEC, linux.O_CLOEXEC},
	} {
		if hostFlags&m.host != 0 {
			l |= m.linux
		}
	}
	return l
}

// linuxFSMagic maps a FreeBSD f_fstypename to the Linux statfs(2) f_type an
// application would expect for the closest Linux filesystem. Unknown types
// map to 0.
func linuxFSMagic(name []byte) uint64 {
	n := name
	for i, c := range name {
		if c == 0 {
			n = name[:i]
			break
		}
	}
	switch string(n) {
	case "tmpfs":
		return linux.TMPFS_MAGIC
	case "zfs":
		return 0x2fc12fc1 // ZFS_SUPER_MAGIC (OpenZFS on Linux)
	case "ufs":
		return 0x00011954 // UFS_MAGIC
	case "nullfs":
		return linux.OVERLAYFS_SUPER_MAGIC
	case "fusefs":
		return linux.FUSE_SUPER_MAGIC
	case "devfs":
		return linux.TMPFS_MAGIC // Linux /dev is devtmpfs
	case "procfs", "linprocfs":
		return linux.PROC_SUPER_MAGIC
	}
	return 0
}
