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

package sighandling

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bsdsys"
)

func sigaction(sig unix.Signal, act, oact *bsdsys.Sigaction) error {
	if _, _, e := unix.RawSyscall(unix.SYS_SIGACTION, uintptr(sig),
		uintptr(unsafe.Pointer(act)), uintptr(unsafe.Pointer(oact))); e != 0 {
		return e
	}
	return nil
}

// IgnoreChildStop sets the SA_NOCLDSTOP flag, causing child processes to not
// generate SIGCHLD when they stop.
func IgnoreChildStop() error {
	var sa bsdsys.Sigaction
	if err := sigaction(unix.SIGCHLD, nil, &sa); err != nil {
		return err
	}
	sa.Flags |= 0x8 // SA_NOCLDSTOP
	return sigaction(unix.SIGCHLD, &sa, nil)
}

// ReplaceSignalHandler replaces the existing signal handler for the provided
// signal with the function pointer at `handler`. This bypasses the Go runtime
// signal handlers, and should only be used for low-level signal handlers where
// use of signal.Notify is not appropriate.
//
// It stores the value of the previously set handler in previous.
func ReplaceSignalHandler(sig unix.Signal, handler uintptr, previous *uintptr) error {
	var sa bsdsys.Sigaction
	if err := sigaction(sig, nil, &sa); err != nil {
		return err
	}
	// Fail if there isn't a previous handler.
	if sa.Handler == 0 {
		return fmt.Errorf("previous handler for signal %x isn't set", sig)
	}
	*previous = sa.Handler
	// Keep the Go runtime's flags (SA_SIGINFO|SA_ONSTACK|SA_RESTART) and mask.
	sa.Handler = handler
	return sigaction(sig, &sa, nil)
}

// KillItself sends SIGKILL to the current process. FreeBSD has no PID
// namespaces, so plain kill(2) is enough.
func KillItself() error {
	if err := unix.Kill(unix.Getpid(), unix.SIGKILL); err != nil {
		return err
	}
	panic("unreachable")
}
