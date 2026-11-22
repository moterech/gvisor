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

package gofer

import "golang.org/x/sys/unix"

// nonblockingPipeHasWriter reports whether the named pipe fd (opened
// O_RDONLY|O_NONBLOCK) has a writer. FreeBSD has no tee(2); a one-shot
// EVFILT_READ knote answers the same question without consuming data:
// data > 0 means the pipe is non-empty (it has, or had, a writer), EV_EOF
// with no data means no writer, and no event means empty with a writer.
//
// Known deviation from Linux: for a reader opened before any writer has
// ever opened the FIFO, FreeBSD suppresses EOF (write-generation logic, cf.
// POLLINIGNEOF) and exposes no writer count, so this reports true. A
// blocking O_RDONLY open of such a host FIFO therefore does not wait for a
// writer. All later transitions (writer present, data, writer gone) match.
func nonblockingPipeHasWriter(fd int32) (bool, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return false, err
	}
	defer unix.Close(kq)
	change := unix.Kevent_t{Ident: uint64(fd), Filter: unix.EVFILT_READ, Flags: unix.EV_ADD | unix.EV_ONESHOT}
	out := make([]unix.Kevent_t, 1)
	n, err := unix.Kevent(kq, []unix.Kevent_t{change}, out, &unix.Timespec{})
	if err != nil {
		return false, err
	}
	switch {
	case n == 0:
		return true, nil
	case out[0].Data > 0:
		return true, nil
	case out[0].Flags&unix.EV_EOF != 0:
		return false, nil
	default:
		return true, nil
	}
}
