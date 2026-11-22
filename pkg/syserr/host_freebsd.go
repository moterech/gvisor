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

package syserr

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// maxErrno also sizes linuxBackwardsTranslations, which is indexed by Linux
// errno, so it must cover Linux's range (< 134), not just FreeBSD's
// (ELAST = 97).
const maxErrno = 134

// noHostErrno marks a Linux errno with no FreeBSD counterpart.
const noHostErrno = unix.Errno(^uintptr(0))

// STREAMS errnos do not exist on FreeBSD.
const (
	hostENOSTR  = noHostErrno
	hostENODATA = noHostErrno
	hostETIME   = noHostErrno
	hostENOSR   = noHostErrno
)

var freebsdHostTranslations [maxErrno]*Error

func getHostTranslation(err unix.Errno) *Error {
	if uint64(err) >= uint64(len(freebsdHostTranslations)) {
		return nil
	}
	return freebsdHostTranslations[err]
}

func addHostTranslation(host unix.Errno, trans *Error) {
	if host == noHostErrno {
		return
	}
	if freebsdHostTranslations[host] != nil {
		panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
	}
	freebsdHostTranslations[host] = trans
}

// FreeBSD-only errnos (FreeBSD 15.1 <sys/errno.h>), mapped to the closest
// Linux errno so host failures surface to the application sensibly.
const (
	hostEPROCLIM      = unix.Errno(67)
	hostEBADRPC       = unix.Errno(72)
	hostERPCMISMATCH  = unix.Errno(73)
	hostEPROGUNAVAIL  = unix.Errno(74)
	hostEPROGMISMATCH = unix.Errno(75)
	hostEPROCUNAVAIL  = unix.Errno(76)
	hostEFTYPE        = unix.Errno(79)
	hostEAUTH         = unix.Errno(80)
	hostENEEDAUTH     = unix.Errno(81)
	hostEDOOFUS       = unix.Errno(88)
	hostENOTCAPABLE   = unix.Errno(93) // Capsicum: rights insufficient
	hostECAPMODE      = unix.Errno(94) // Capsicum: not allowed in capability mode
	hostEINTEGRITY    = unix.Errno(97)
)

func init() {
	for host, trans := range map[unix.Errno]*Error{
		hostEPROCLIM:      ErrTryAgain,
		hostEBADRPC:       ErrIO,
		hostERPCMISMATCH:  ErrIO,
		hostEPROGUNAVAIL:  ErrIO,
		hostEPROGMISMATCH: ErrIO,
		hostEPROCUNAVAIL:  ErrIO,
		hostEFTYPE:        ErrInvalidArgument,
		hostEAUTH:         ErrPermissionDenied,
		hostENEEDAUTH:     ErrPermissionDenied,
		hostEDOOFUS:       ErrInvalidArgument,
		hostENOTCAPABLE:   ErrNotPermitted,
		hostECAPMODE:      ErrNotPermitted,
		hostEINTEGRITY:    ErrIO,
	} {
		addHostTranslation(host, trans)
	}
}
