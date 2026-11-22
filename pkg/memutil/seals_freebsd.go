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

package memutil

import "golang.org/x/sys/unix"

// fAddSeals is F_ADD_SEALS on FreeBSD (19; Linux uses 1033).
const fAddSeals = 19

// AddSeals applies F_SEAL_* seals (same values on Linux and FreeBSD) to a
// shm object created with SHM_ALLOW_SEALING.
func AddSeals(fd int, seals int) error {
	_, err := unix.FcntlInt(uintptr(fd), fAddSeals, seals)
	return err
}
