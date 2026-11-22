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

package time

import "golang.org/x/sys/unix"

// vdsoClockGettime reads a host clock. Linux calls clock_gettime through the
// host vDSO via Go runtime internals that do not exist on FreeBSD; this uses
// the system call. ClockID values are Linux's and are translated: FreeBSD
// numbers clocks differently (CLOCK_MONOTONIC is 4, not 1).
func vdsoClockGettime(clockid ClockID, ts *unix.Timespec) int {
	var id int32
	switch clockid {
	case Realtime:
		id = unix.CLOCK_REALTIME
	case Monotonic:
		id = unix.CLOCK_MONOTONIC
	case MonotonicRaw:
		// Not NTP-slewed; the closest FreeBSD has to CLOCK_MONOTONIC_RAW.
		id = unix.CLOCK_MONOTONIC_PRECISE
	default:
		return -int(unix.EINVAL)
	}
	if err := unix.ClockGettime(id, ts); err != nil {
		return -int(err.(unix.Errno))
	}
	return 0
}
