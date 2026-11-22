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

// Command gsb-sentry boots a minimal Sentry on FreeBSD and runs one
// unmodified Linux/amd64 ELF binary on the bsdtrap platform.
//
//	gsb-sentry [-stub PATH] /path/to/linux-binary [args...]
//
// This is the first-light entry point: tmpfs root, no network, host stdio,
// the executable imported from the host by fd. It is not runsc: there is no
// OCI spec, Gofer, jail or Capsicum yet.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/cgroup2fs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform/bsdtrap"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"

	// Registers the Linux syscall table.
	_ "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
)

var (
	stubPath = flag.String("stub", bsdtrap.DefaultStubPath, "bsdtrap stub binary")
	debug    = flag.Bool("debug", false, "Sentry debug logging")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] /path/to/linux-binary [args...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	if *debug {
		log.SetLevel(log.Debug)
	}
	status, err := run(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "gsb-sentry: %v\n", err)
		os.Exit(125)
	}
	if status.Signaled() {
		fmt.Fprintf(os.Stderr, "gsb-sentry: killed by signal %d\n", status.TerminationSignal())
		os.Exit(128 + int(status.TerminationSignal()))
	}
	os.Exit(int(status.ExitStatus()))
}

func run(argv []string) (linux.WaitStatus, error) {
	cpuid.Initialize()
	if err := usage.Init(); err != nil {
		return 0, fmt.Errorf("memory accounting: %w", err)
	}

	p, err := bsdtrap.New(*stubPath)
	if err != nil {
		return 0, err
	}
	k := &kernel.Kernel{Platform: p}

	memfd, err := memutil.CreateMemFD("gsb-sentry-memory", 0)
	if err != nil {
		return 0, fmt.Errorf("memory file: %w", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memfd), "gsb-sentry-memory"), pgalloc.MemoryFileOpts{})
	if err != nil {
		return 0, fmt.Errorf("memory file: %w", err)
	}
	k.SetMemoryFile(mf)

	vdso, err := loader.PrepareVDSO(mf)
	if err != nil {
		return 0, fmt.Errorf("vdso: %w", err)
	}
	tk := kernel.NewTimekeeper()
	params := kernel.NewVDSOParamPage(mf, vdso.ParamPage.FileRange())
	tk.SetClocks(time.NewCalibratedClocks(false), params)

	userns := auth.NewRootUserNamespace()
	if err := k.Init(kernel.InitKernelArgs{
		FeatureSet:           cpuid.HostFeatureSet().Fixed(),
		Timekeeper:           tk,
		RootUserNamespace:    userns,
		RootNetworkNamespace: inet.NewRootNamespace(nil, nil, userns),
		ApplicationCores:     uint(runtime.NumCPU()),
		Vdso:                 vdso,
		VdsoParams:           params,
		RootUTSNamespace:     kernel.NewUTSNamespace("gsb", "", userns),
		RootIPCNamespace:     kernel.NewIPCNamespace(userns),
		RootPIDNamespace:     kernel.NewRootPIDNamespace(userns),
		MaxFDLimit:           kernel.MaxFdLimit,
		Cgroup2FSInit:        cgroup2fs.NewFilesystem,
	}); err != nil {
		return 0, fmt.Errorf("kernel init: %w", err)
	}

	ctx := k.SupervisorContext()
	creds := auth.NewRootCredentials(userns)
	k.VFS().MustRegisterFilesystemType(tmpfs.Name, &tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	mns, err := k.VFS().NewMountNamespace(ctx, creds, "", tmpfs.Name, &vfs.MountOptions{}, k)
	if err != nil {
		return 0, fmt.Errorf("root mount: %w", err)
	}

	// Mount for host fds imported into the sandbox (stdio, executable).
	hostFS, err := host.NewFilesystem(k.VFS())
	if err != nil {
		return 0, fmt.Errorf("host filesystem: %w", err)
	}
	defer hostFS.DecRef(ctx)
	k.SetHostMount(k.VFS().NewDisconnectedMount(hostFS, nil, &vfs.MountOptions{}))

	// The executable, imported from the host by fd.
	exeFD, err := unix.Open(argv[0], unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", argv[0], err)
	}
	exe, err := host.NewFD(ctx, k.HostMount(), exeFD, &host.NewFDOptions{})
	if err != nil {
		return 0, fmt.Errorf("import %s: %w", argv[0], err)
	}

	// Host stdio as fds 0-2.
	fdTable := k.NewFDTable()
	for i := 0; i < 3; i++ {
		hfd, err := unix.Dup(i)
		if err != nil {
			return 0, fmt.Errorf("dup stdio %d: %w", i, err)
		}
		f, err := host.NewFD(ctx, k.HostMount(), hfd, &host.NewFDOptions{})
		if err != nil {
			return 0, fmt.Errorf("import stdio %d: %w", i, err)
		}
		if _, err := fdTable.NewFDAt(ctx, int32(i), f, kernel.FDFlags{}); err != nil {
			return 0, err
		}
		f.DecRef(ctx)
	}

	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		return 0, err
	}
	tg, _, err := k.CreateProcess(kernel.CreateProcessArgs{
		// File only: a Filename would be resolved inside the (empty) root.
		File:                 exe,
		Argv:                 argv,
		Envv:                 []string{"PATH=/bin:/usr/bin", "HOME=/"},
		WorkingDirectory:     "/",
		Credentials:          creds,
		FDTable:              fdTable,
		Umask:                0022,
		Limits:               ls,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		UTSNamespace:         k.RootUTSNamespace(),
		IPCNamespace:         k.RootIPCNamespace(),
		PIDNamespace:         k.RootPIDNamespace(),
		MountNamespace:       mns,
	})
	if err != nil {
		return 0, fmt.Errorf("create process: %w", err)
	}
	fdTable.DecRef(ctx)

	if err := k.Start(); err != nil {
		return 0, err
	}
	tg.WaitExited()
	return tg.ExitStatus(), nil
}
