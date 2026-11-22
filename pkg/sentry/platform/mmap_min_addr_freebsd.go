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

package platform

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// hostMMapMinAddr returns the lowest mappable user address. FreeBSD has no
// mmap_min_addr; instead security.bsd.map_at_zero (default 0) forbids
// mapping the page at address 0.
func hostMMapMinAddr() uint64 {
	v, err := unix.SysctlUint32("security.bsd.map_at_zero")
	if err != nil {
		panic(fmt.Sprintf("couldn't read security.bsd.map_at_zero: %v", err))
	}
	if v != 0 {
		return 0
	}
	return uint64(unix.Getpagesize())
}
