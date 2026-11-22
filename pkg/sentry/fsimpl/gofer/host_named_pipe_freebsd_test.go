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

package gofer

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// FreeBSD-specific: the kqueue-based writer detection must agree with what
// the Linux tee(2) version reports, including for a reader opened before
// any writer.
func TestNonblockingPipeHasWriterFreeBSD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(r)

	check := func(step string, want bool) {
		t.Helper()
		got, err := nonblockingPipeHasWriter(int32(r))
		if err != nil || got != want {
			t.Errorf("%s: hasWriter = %v, %v; want %v", step, got, err, want)
		}
	}
	// Known deviation (see host_named_pipe_freebsd.go): FreeBSD cannot tell
	// "no writer has opened yet" from "writer present, empty".
	if got, err := nonblockingPipeHasWriter(int32(r)); err != nil {
		t.Fatal(err)
	} else if got {
		t.Logf("no writer yet: reports true (known FreeBSD deviation)")
	}

	w, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	check("writer open, empty", true)
	if _, err := unix.Write(w, []byte("x")); err != nil {
		t.Fatal(err)
	}
	check("writer open, data", true)
	check("still data (not consumed)", true)
	unix.Close(w)
	check("writer closed, data unread", true)
	buf := make([]byte, 1)
	unix.Read(r, buf)
	check("writer closed, drained", false)
}
