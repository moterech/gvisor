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

package fsutil

import "golang.org/x/sys/unix"

const sysRenameat2 = unix.SYS_RENAMEAT2

// sysFstatat is used by the amd64 StatAt.
const sysFstatat = unix.SYS_NEWFSTATAT

// supportedRenameFlags: all Linux renameat2(2) flags are passed through.
const supportedRenameFlags = ^uint32(0)

func direntIno(d *unix.Dirent) uint64 { return d.Ino }
