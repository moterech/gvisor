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

package fs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostfs"
)

func TestReopenAndFchmodOPathFreeBSD(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	pathFD, err := unix.Open(p, hostfs.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pathFD)

	// O_PATH fds cannot be read; reopenFD must yield a usable fd.
	w, err := reopenFD(pathFD, unix.O_WRONLY|unix.O_APPEND)
	if err != nil {
		t.Fatalf("reopenFD(O_WRONLY): %v", err)
	}
	if _, err := unix.Write(w, []byte("d")); err != nil {
		t.Errorf("write via reopened fd: %v", err)
	}
	unix.Close(w)
	if b, _ := os.ReadFile(p); string(b) != "abcd" {
		t.Errorf("file = %q, want abcd", b)
	}

	if err := fchmodFD(pathFD, 0640); err != nil {
		t.Fatalf("fchmodFD on O_PATH fd: %v", err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0640 {
		t.Errorf("mode = %o, want 640", fi.Mode().Perm())
	}
}

func TestOpenNoSymlinksFreeBSD(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real", "dir")
	if err := os.MkdirAll(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	fd, err := openNoSymlinks(real)
	if err != nil {
		t.Fatalf("openNoSymlinks(%s): %v", real, err)
	}
	var st, want unix.Stat_t
	unix.Fstat(fd, &st)
	unix.Stat(real, &want)
	unix.Close(fd)
	if st.Ino != want.Ino {
		t.Errorf("opened inode %d, want %d", st.Ino, want.Ino)
	}

	if fd, err := openNoSymlinks(filepath.Join(root, "link", "dir")); err == nil {
		unix.Close(fd)
		t.Errorf("openNoSymlinks followed a symlink component")
	}
	// Not filepath.Join, which would clean the ".." away.
	if fd, err := openNoSymlinks(root + "/real/../real"); err == nil {
		unix.Close(fd)
		t.Errorf("openNoSymlinks accepted a .. component")
	}
}
