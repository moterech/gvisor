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

// FreeBSD 15 has renameat2(2) (syscall 602), supporting only
// AT_RENAME_NOREPLACE, which has the same value (1) as Linux
// RENAME_NOREPLACE. RENAME_EXCHANGE and RENAME_WHITEOUT are rejected with
// EINVAL, as an old Linux kernel would.
const sysRenameat2 = 602

const supportedRenameFlags = 0x1 // RENAME_NOREPLACE

// fstatat(2); FreeBSD has no newfstatat.
const sysFstatat = unix.SYS_FSTATAT

// FreeBSD calls d_ino d_fileno. DT_* values match Linux.
func direntIno(d *unix.Dirent) uint64 { return d.Fileno }
