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

package eventfd

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bsdsys"
)

// hostEventfd creates a host eventfd. flags are Linux EFD_* flags, whose
// values differ from FreeBSD's.
func hostEventfd(initVal uint32, flags int) (int, error) {
	var h int
	if flags&linux.EFD_NONBLOCK != 0 {
		h |= bsdsys.EFD_NONBLOCK
	}
	if flags&linux.EFD_SEMAPHORE != 0 {
		h |= bsdsys.EFD_SEMAPHORE
	}
	if flags&linux.EFD_CLOEXEC != 0 {
		h |= bsdsys.EFD_CLOEXEC
	}
	return bsdsys.Eventfd(initVal, h)
}
