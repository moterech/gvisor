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

// Package bsdtrap is a FreeBSD platform, the counterpart of systrap.
//
// Each address space is a stub process that runs under the gsb kernel
// module, which turns every syscall the application makes into a SIGSYS
// delivered to the stub's own handler. The handler publishes the thread's
// context to shared memory and waits; the Sentry handles the event and
// sends the next context back. Application syscalls never reach the host
// kernel's implementations.
//
// Requirements: gsb.ko loaded, and the stub binary (stub/) installed at
// DefaultStubPath or at $GSB_BSDTRAP_STUB.
package bsdtrap

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// DefaultStubPath is where the stub binary is looked up by default.
const DefaultStubPath = "/usr/local/libexec/gsb-bsdtrap-stub"

// BSDTrap implements platform.Platform.
type BSDTrap struct {
	platform.NoCPUPreemptionDetection
	platform.NoCPUNumbers

	stubPath string
}

var _ platform.Platform = (*BSDTrap)(nil)

// New returns a BSDTrap platform using the stub at stubPath.
func New(stubPath string) (*BSDTrap, error) {
	if _, err := os.Stat(stubPath); err != nil {
		return nil, fmt.Errorf("bsdtrap: stub binary: %w", err)
	}
	return &BSDTrap{stubPath: stubPath}, nil
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
func (*BSDTrap) SupportsAddressSpaceIO() bool { return false }

// HaveGlobalMemoryBarrier implements platform.Platform.HaveGlobalMemoryBarrier.
func (*BSDTrap) HaveGlobalMemoryBarrier() bool { return false }

// GlobalMemoryBarrier implements platform.Platform.GlobalMemoryBarrier.
func (*BSDTrap) GlobalMemoryBarrier() error { return unix.ENOSYS }

// MapUnit implements platform.Platform.MapUnit.
func (*BSDTrap) MapUnit() uint64 { return 0 }

// MinUserAddress implements platform.Platform.MinUserAddress.
func (*BSDTrap) MinUserAddress() hostarch.Addr { return platform.SystemMMapMinAddr() }

// MaxUserAddress implements platform.Platform.MaxUserAddress. Everything
// above belongs to the stub (image, control area, stacks) and the FreeBSD
// shared page.
func (*BSDTrap) MaxUserAddress() hostarch.Addr { return appMaxAddr }

// NewAddressSpace implements platform.Platform.NewAddressSpace.
func (p *BSDTrap) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return newSubprocess(p.stubPath)
}

// NewContext implements platform.Platform.NewContext.
func (*BSDTrap) NewContext(pkgcontext.Context) platform.Context { return newContext() }

// SeccompInfo implements platform.Platform.SeccompInfo. FreeBSD has no
// seccomp; host syscalls are confined by Capsicum and gsb.ko instead.
func (*BSDTrap) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{PlatformName: "bsdtrap"}
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount.
func (*BSDTrap) ConcurrencyCount() int { return runtime.NumCPU() }

type constructor struct{}

// New implements platform.Constructor.New.
func (*constructor) New(platform.Options) (platform.Platform, error) {
	path := os.Getenv("GSB_BSDTRAP_STUB")
	if path == "" {
		path = DefaultStubPath
	}
	return New(path)
}

// PrecompiledSeccompInfo implements platform.Constructor.PrecompiledSeccompInfo.
func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo { return nil }

func init() {
	platform.Register("bsdtrap", &constructor{})
}
