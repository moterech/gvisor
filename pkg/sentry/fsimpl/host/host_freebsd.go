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

package host

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bsdsys"
)

// isEpollable reports whether fd supports readiness notification the way
// epoll(7) does. kqueue accepts regular files and directories (vnode
// filters, always readable), but epoll rejects them with EPERM and the
// Sentry treats such fds as always ready, so mirror that.
func isEpollable(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFDIR:
		return false
	}
	kq, err := unix.Kqueue()
	if err != nil {
		return false
	}
	defer unix.Close(kq)
	ev := unix.Kevent_t{Ident: uint64(fd), Filter: unix.EVFILT_READ, Flags: unix.EV_ADD}
	_, err = unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil)
	return err == nil
}

func newDummyEventfd() (int, error) {
	return bsdsys.Eventfd(0, 0)
}

// setStatMode sets st_mode, which is 16 bits on FreeBSD.
func setStatMode(stat *unix.Stat_t, mode uint32) {
	stat.Mode = uint16(mode)
}

// hostFIONREAD is the host FIONREAD ioctl request (Linux: 0x541b).
const hostFIONREAD = bsdsys.FIONREAD
