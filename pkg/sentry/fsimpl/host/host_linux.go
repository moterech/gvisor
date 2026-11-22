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
	"gvisor.dev/gvisor/pkg/abi/linux"
)

func isEpollable(fd int) bool {
	epollfd, err := unix.EpollCreate1(0)
	if err != nil {
		// This shouldn't happen. If it does, just say file doesn't support epoll.
		return false
	}
	defer unix.Close(epollfd)

	event := unix.EpollEvent{
		Fd:     int32(fd),
		Events: unix.EPOLLIN,
	}
	err = unix.EpollCtl(epollfd, unix.EPOLL_CTL_ADD, fd, &event)
	return err == nil
}

func newDummyEventfd() (int, error) {
	efd, _, err := unix.RawSyscall(unix.SYS_EVENTFD2, 0, 0, 0)
	if err != 0 {
		return -1, err
	}
	return int(efd), nil
}

func setStatMode(stat *unix.Stat_t, mode uint32) {
	stat.Mode = mode
}

// hostFIONREAD is the host FIONREAD ioctl request.
const hostFIONREAD = linux.FIONREAD
