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

package flipcall

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bsdsys"
)

// The packet window is shared between processes (Sentry and Gofer), so the
// process-shared _umtx_op variants are required; the *_PRIVATE ones key on
// the address-space and would never match the peer.

func (ep *Endpoint) futexSetPeerActive() error {
	if ep.connState().CompareAndSwap(ep.activeState, ep.inactiveState) {
		return nil
	}
	switch cs := ep.connState().Load(); cs {
	case csShutdown:
		return ShutdownError{}
	default:
		return fmt.Errorf("unexpected connection state before UMTX_OP_WAKE: %v", cs)
	}
}

func (ep *Endpoint) futexWakePeer() error {
	if err := ep.futexWakeConnState(1); err != nil {
		return fmt.Errorf("failed to UMTX_OP_WAKE peer Endpoint: %v", err)
	}
	return nil
}

func (ep *Endpoint) futexWaitUntilActive() error {
	for {
		switch cs := ep.connState().Load(); cs {
		case ep.activeState:
			return nil
		case ep.inactiveState:
			if ep.isShutdownLocally() {
				return ShutdownError{}
			}
			if err := ep.futexWaitConnState(ep.inactiveState); err != nil {
				return fmt.Errorf("failed to UMTX_OP_WAIT_UINT for peer Endpoint: %v", err)
			}
			continue
		case csShutdown:
			return ShutdownError{}
		default:
			return fmt.Errorf("unexpected connection state before UMTX_OP_WAIT_UINT: %v", cs)
		}
	}
}

func (ep *Endpoint) futexWakeConnState(numThreads int32) error {
	return bsdsys.UmtxWake(ep.packet, int(numThreads), true /* shared */)
}

func (ep *Endpoint) futexWaitConnState(curState uint32) error {
	return bsdsys.UmtxWaitUint(ep.packet, curState, true /* shared */)
}

func yieldThread() {
	unix.Syscall(unix.SYS_SCHED_YIELD, 0, 0, 0)
	// The thread we're trying to yield to may be waiting for a Go runtime P.
	// runtime.Gosched() will hand off ours if necessary.
	runtime.Gosched()
}
