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
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostfs"
	"gvisor.dev/gvisor/pkg/log"
)

// reopenFD opens the file that hostFD refers to again with flags, via its
// /proc/self/fd magic link.
func reopenFD(hostFD int, flags int) (int, error) {
	return unix.Openat(int(procSelfFD.FD()), strconv.Itoa(hostFD), flags, 0)
}

// fchmodFD changes the mode of the file hostFD (possibly an O_PATH fd)
// refers to.
func fchmodFD(hostFD int, mode uint32) error {
	return unix.Fchmodat(int(procSelfFD.FD()), strconv.Itoa(hostFD), mode, 0 /* flags */)
}

// openNoSymlinks opens dir as an O_PATH fd without following any symlink in
// any component.
func openNoSymlinks(dir string) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, dir, &unix.OpenHow{
		Flags:   hostfs.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
}

// connectWithGroups calls connect on a dedicated OS thread whose supplementary
// groups are set to gids. unix.Setgroups changes only the calling thread, which
// is what we want here (syscall.Setgroups would change every thread). The
// thread is never reused: connectOnItsOwnThread returns while still locked to
// it, so the runtime terminates it along with its groups. Threads the runtime
// starts from a locked thread are created by its template thread instead (see
// runtime.newm), so they don't inherit the groups either.
func connectWithGroups(gids []int, connect func() (int, error)) (int, error) {
	done := make(chan connectResult, 1)
	go connectOnItsOwnThread(gids, connect, done)
	res := <-done
	if res.panicValue != nil {
		panic(res.panicValue)
	}
	return res.sock, res.err
}

type connectResult struct {
	sock       int
	err        error
	panicValue any
}

func connectOnItsOwnThread(gids []int, connect func() (int, error), done chan connectResult) {
	runtime.LockOSThread()
	if isThreadGroupLeader() {
		// The runtime never terminates the thread group leader; it parks it for
		// the life of the process instead, so its groups must not change. Stay
		// locked to it so that the new goroutine runs on another thread.
		defer runtime.UnlockOSThread()
		mainless := make(chan connectResult, 1)
		go connectOnItsOwnThread(gids, connect, mainless)
		done <- <-mainless
		return
	}
	defer func() {
		if p := recover(); p != nil {
			done <- connectResult{sock: -1, panicValue: p}
		}
	}()
	if err := unix.Setgroups(gids); err != nil {
		log.Warningf("Failed to set %d supplementary groups; err: %v", len(gids), err)
		done <- connectResult{sock: -1, err: err}
		return
	}
	log.Debugf("Successfully set supplementary groups to %v", gids)
	sock, err := connect()
	done <- connectResult{sock: sock, err: err}
}

// isThreadGroupLeader returns true if the calling thread is the thread group
// leader, whose thread ID is the process ID.
func isThreadGroupLeader() bool {
	return unix.Gettid() == unix.Getpid()
}
