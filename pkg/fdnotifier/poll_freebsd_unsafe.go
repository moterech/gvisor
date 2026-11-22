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

package fdnotifier

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bsdsys"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Linux and FreeBSD agree on POLLIN/PRI/OUT/ERR/HUP/NVAL (0x1-0x20). Only
// POLLRDHUP differs (Linux 0x2000, FreeBSD 0x4000).
const commonPollBits = 0x3f

func toHostPoll(m waiter.EventMask) int16 {
	l := m.ToLinux()
	h := int16(l & commonPollBits)
	if l&linux.POLLRDHUP != 0 {
		h |= bsdsys.POLLRDHUP
	}
	return h
}

func fromHostPoll(h int16) waiter.EventMask {
	l := uint32(h) & commonPollBits
	if h&bsdsys.POLLRDHUP != 0 {
		l |= linux.POLLRDHUP
	}
	return waiter.EventMaskFromLinux(l)
}

// NonBlockingPoll polls the given FD in non-blocking fashion. It is used just
// to query the FD's current state.
func NonBlockingPoll(fd int32, mask waiter.EventMask) waiter.EventMask {
	e := struct {
		fd      int32
		events  int16
		revents int16
	}{
		fd:     fd,
		events: toHostPoll(mask),
	}

	ts := unix.Timespec{}
	for {
		n, _, err := unix.RawSyscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(&e)), 1,
			uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
		// Interrupted by signal, try again.
		if err == unix.EINTR {
			continue
		}
		// If an error occur we'll conservatively say the FD is ready for
		// whatever is being checked.
		if err != 0 {
			return mask
		}
		// If no FDs were returned, it wasn't ready for anything.
		if n == 0 {
			return 0
		}
		// Otherwise we got the ready events in the revents field.
		return fromHostPoll(e.revents)
	}
}

// Kevent_t.Udata is a *byte in x/sys; it carries our 64-bit id.
func setUdata(ev *unix.Kevent_t, id uint64) {
	ev.Udata = (*byte)(unsafe.Pointer(uintptr(id)))
}

func udata(ev *unix.Kevent_t) uint64 {
	return uint64(uintptr(unsafe.Pointer(ev.Udata)))
}
