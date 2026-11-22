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

//go:build linux

package transport

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// hostPasscred reports whether the host socket asked for credentials.
func hostPasscred(fd int) (bool, error) {
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED)
	return v != 0, err
}

// hostCredsCmsg returns an SCM_CREDENTIALS control message carrying the
// sentry's pid and fd's owner, since application credentials cannot be
// passed to the host.
func hostCredsCmsg(fd int) ([]byte, error) {
	cmsgSlice := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&cmsgSlice[0]))
	cmsg.Level = unix.SOL_SOCKET
	cmsg.Type = unix.SCM_CREDENTIALS
	cmsgLen := unix.CmsgLen(unix.SizeofUcred)
	cmsg.SetLen(cmsgLen)
	cmsgData := (*unix.Ucred)(unsafe.Pointer(&cmsgSlice[unix.CmsgLen(0)]))
	// Collect owner information for fd. Gete(uid|gid) are forbidden by the
	// sentry's seccomp filters.
	s := unix.Stat_t{}
	if err := unix.Fstat(fd, &s); err != nil {
		return nil, err
	}
	if s.Uid == 0 || s.Gid == 0 {
		usingRootCredsLogger.Warningf("gVisor does not support setting UID or GID to root in SCM credentials sent from the sentry")
		return nil, unix.EINVAL
	}
	pid, _, err := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
	if err != 0 {
		return nil, err
	}
	*cmsgData = unix.Ucred{Pid: int32(pid), Uid: s.Uid, Gid: s.Gid}
	return cmsgSlice[:cmsgLen], nil
}
