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

package memutil

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bsdsys"
)

// memfd_create(2) flags, as callers pass them.
const (
	mfdCloexec      = 0x1
	mfdAllowSealing = 0x2
)

// CreateMemFD creates the FreeBSD equivalent of a memfd, an anonymous
// shm_open2(SHM_ANON) object, and returns the fd. Linux memfd flags are
// translated; others are rejected.
func CreateMemFD(name string, flags int) (int, error) {
	if flags&^(mfdCloexec|mfdAllowSealing) != 0 {
		return -1, unix.EINVAL
	}
	oflags, shmflags := 0, 0
	if flags&mfdCloexec != 0 {
		oflags |= unix.O_CLOEXEC
	}
	if flags&mfdAllowSealing != 0 {
		shmflags |= bsdsys.SHM_ALLOW_SEALING
	}
	return bsdsys.ShmAnon(name, oflags, shmflags)
}
