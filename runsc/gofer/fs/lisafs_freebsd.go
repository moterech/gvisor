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

package fs

import (
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bsdsys"
	"gvisor.dev/gvisor/pkg/hostfs"
)

// reopenFD opens the file that hostFD refers to again with flags.
// FreeBSD has no /proc/self/fd magic links; openat(2) with O_EMPTY_PATH
// re-opens the fd's own vnode, which also works in capability mode.
func reopenFD(hostFD int, flags int) (int, error) {
	return unix.Openat(hostFD, "", flags|bsdsys.O_EMPTY_PATH, 0)
}

// fchmodFD changes the mode of the file hostFD (possibly an O_PATH fd)
// refers to.
func fchmodFD(hostFD int, mode uint32) error {
	return unix.Fchmodat(hostFD, "", mode, bsdsys.AT_EMPTY_PATH)
}

// openNoSymlinks opens dir as an O_PATH fd without following any symlink in
// any component. FreeBSD has no openat2(RESOLVE_NO_SYMLINKS); walking one
// component at a time with O_NOFOLLOW|O_DIRECTORY gives the same guarantee.
func openNoSymlinks(dir string) (int, error) {
	const flags = hostfs.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return -1, err
	}
	for _, c := range strings.Split(dir, "/") {
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			unix.Close(fd)
			return -1, unix.EINVAL
		}
		next, err := unix.Openat(fd, c, flags, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// connectWithGroups connects with the given supplementary groups. On Linux
// this runs on a throwaway OS thread whose groups are changed, since Linux
// credentials are per-thread at the syscall level. FreeBSD credentials are
// per-process: changing groups would affect the whole gofer, so only connect
// when the groups already match.
func connectWithGroups(gids []int, connect func() (int, error)) (int, error) {
	have, err := unix.Getgroups()
	if err != nil {
		return -1, err
	}
	if !groupsAlreadySet(gids, have) {
		return -1, unix.EPERM
	}
	return connect()
}
