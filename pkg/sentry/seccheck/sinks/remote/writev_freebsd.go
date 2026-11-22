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

package remote

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// writev is writev(2); x/sys/unix does not provide it on FreeBSD.
func writev(fd int, bufs [][]byte) (int, error) {
	iovs := make([]unix.Iovec, 0, len(bufs))
	for _, b := range bufs {
		if len(b) == 0 {
			continue
		}
		iov := unix.Iovec{Base: &b[0]}
		iov.SetLen(len(b))
		iovs = append(iovs, iov)
	}
	if len(iovs) == 0 {
		return 0, nil
	}
	n, _, e := unix.Syscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)))
	if e != 0 {
		return int(n), e
	}
	return int(n), nil
}
