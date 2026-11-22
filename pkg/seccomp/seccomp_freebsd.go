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

package seccomp

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bpf"
)

// FreeBSD has no seccomp. The rule-building parts of this package still
// compile so that platform interfaces can describe their host syscall needs;
// on FreeBSD those needs are enforced by Capsicum (cap_enter) for the Sentry
// and by gsb.ko for stub processes, not by installing a BPF program.

// SetFilter is unsupported on FreeBSD.
func SetFilter(instrs []bpf.Instruction) error {
	return unix.ENOSYS
}

// SetFilterInChild is unsupported on FreeBSD.
func SetFilterInChild(instrs []bpf.Instruction) unix.Errno {
	return unix.ENOSYS
}
