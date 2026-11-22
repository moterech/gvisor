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

package host

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// FreeBSD host TTYs are not yet supported. Their termios differs from Linux
// in layout, flag bits, c_cc indices and speed encoding, and needs a
// translation layer; until then every termios ioctl reports ENOTTY, so
// IsTTY is false and host terminals are imported as plain character
// devices.

func ioctlGetTermios(fd int) (*linux.Termios, error) { return nil, unix.ENOTTY }

// IsTTY returns true if the given fd is a host TTY that can be imported as
// one. Always false on FreeBSD for now (see above).
func IsTTY(fd int) bool { return false }

func ioctlSetTermios(fd int, req uint64, t *linux.Termios) error { return unix.ENOTTY }

func ioctlGetTermios2(fd int) (*linux.KernelTermios, error) { return nil, unix.ENOTTY }

func ioctlSetTermios2(fd int, req uint64, t *linux.KernelTermios) error { return unix.ENOTTY }
