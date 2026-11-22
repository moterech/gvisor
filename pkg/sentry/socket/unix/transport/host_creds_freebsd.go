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

package transport

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// sizeofCmsgcred is sizeof(struct cmsgcred) on FreeBSD/amd64: pid, uid,
// euid, gid (4 bytes each), short ngroups (+2 pad), gid_t groups[16].
const sizeofCmsgcred = 84

// solLocal is SOL_LOCAL, the option level for AF_UNIX sockets.
const solLocal = 0

// hostPasscred reports whether the host socket asked for credentials
// (LOCAL_CREDS, FreeBSD's SO_PASSCRED).
func hostPasscred(fd int) (bool, error) {
	v, err := unix.GetsockoptInt(fd, solLocal, unix.LOCAL_CREDS)
	return v != 0, err
}

// hostCredsCmsg returns an SCM_CREDS control message. On FreeBSD the sender
// only reserves space; the kernel fills in the sending process's real
// credentials, so the sentry's identity is sent and application credentials
// cannot be forged.
func hostCredsCmsg(fd int) ([]byte, error) {
	cmsgSlice := make([]byte, unix.CmsgSpace(sizeofCmsgcred))
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&cmsgSlice[0]))
	cmsg.Level = unix.SOL_SOCKET
	cmsg.Type = unix.SCM_CREDS
	cmsgLen := unix.CmsgLen(sizeofCmsgcred)
	cmsg.SetLen(cmsgLen)
	return cmsgSlice[:cmsgLen], nil
}
