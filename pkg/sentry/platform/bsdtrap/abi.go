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

//go:build freebsd && amd64

package bsdtrap

// Shared-memory protocol with the stub. Must match stub/bsdtrap_abi.h.
const (
	stubTextBase = 0x7f0000000000
	appMaxAddr   = 0x7f0000000000
	maxThreads   = 512

	ctlFD  = 3
	sockFD = 4

	ctlSize     = 4096
	slotSize    = 16384
	ctlAreaSize = ctlSize + maxThreads*slotSize

	nrEnter = 9999

	ctlReqSeq      = 0
	ctlRespSeq     = 4
	ctlStubSleep   = 8
	ctlSentrySleep = 12
	ctlOp          = 16
	ctlArgs        = 24
	ctlRet         = 72

	opMmap      = 1
	opMunmap    = 2
	opMprotect  = 3
	opRecvFD    = 4
	opClose     = 5
	opNewThread = 6
	opExit      = 7

	slotCmdSeq      = 0
	slotEvSeq       = 4
	slotStubSleep   = 8
	slotSentrySleep = 12
	slotCmd         = 16
	slotEvSig       = 20
	slotTID         = 24
	slotXfpuLen     = 32
	slotSiginfo     = 64
	slotMcontext    = 256
	slotXfpu        = 1088
	xfpuMax         = slotSize - slotXfpu

	cmdRun  = 1
	cmdExit = 2

	// gsbSISyscall is si_code of a SIGSYS from gsb.ko (gsb_abi.h).
	gsbSISyscall = 1
)
