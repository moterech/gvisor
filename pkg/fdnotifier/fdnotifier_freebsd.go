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

// Package fdnotifier contains an adapter that translates IO events (e.g., a
// file became readable/writable) from native FDs to the notifications in the
// waiter package. On FreeBSD it uses kqueue in place of epoll: one
// EV_CLEAR (edge-triggered) EVFILT_READ and/or EVFILT_WRITE knote per fd,
// tagged with the same opaque 64-bit id the Linux version stores in
// epoll_event.data.
package fdnotifier

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

type fdInfo struct {
	queue *waiter.Queue

	// id is the key into notifier.queues; 0 if the fd has no knotes.
	id uint64

	// read and write record which kqueue filters are installed.
	read, write bool
}

// notifier holds all the state necessary to issue notifications when IO events
// occur in the observed FDs.
type notifier struct {
	// kqFD is the kqueue file descriptor used to register for io
	// notifications.
	kqFD int

	// pauseMu prevents notifications while held; see Pause/Resume.
	pauseMu sync.Mutex

	// mu protects fdMap, queues and lastID.
	mu sync.Mutex

	// fdMap maps file descriptors to their notification queues.
	fdMap map[int32]*fdInfo

	// queues maps knote ids to notification queues. Unlike fds, ids are
	// never reused, so a stale event for a closed fd cannot reach a new
	// fd's queue.
	queues map[uint64]*waiter.Queue

	lastID uint64
}

const readMask = waiter.ReadableEvents | waiter.EventRdHUp
const writeMask = waiter.WritableEvents

func (n *notifier) change(fd int32, filter int16, flags uint16, id uint64) error {
	ev := unix.Kevent_t{
		Ident:  uint64(fd),
		Filter: filter,
		Flags:  flags,
		Udata:  (*byte)(nil),
	}
	setUdata(&ev, id)
	_, err := unix.Kevent(n.kqFD, []unix.Kevent_t{ev}, nil, nil)
	return err
}

// waitFD waits on mask for fd. The fdMap mutex must be held.
func (n *notifier) waitFD(fd int32, fi *fdInfo, mask waiter.EventMask) error {
	wantRead := mask&readMask != 0
	wantWrite := mask&writeMask != 0

	id := fi.id
	if id == 0 && (wantRead || wantWrite) {
		id = n.lastID + 1
		if id == 0 {
			return unix.EOVERFLOW
		}
	}

	type op struct {
		have, want bool
		filter     int16
	}
	for _, o := range []op{{fi.read, wantRead, unix.EVFILT_READ}, {fi.write, wantWrite, unix.EVFILT_WRITE}} {
		switch {
		case o.want && !o.have:
			if err := n.change(fd, o.filter, unix.EV_ADD|unix.EV_CLEAR, id); err != nil {
				return err
			}
		case !o.want && o.have:
			// The fd may already be closed, which removes its knotes.
			_ = n.change(fd, o.filter, unix.EV_DELETE, id)
		}
	}
	fi.read, fi.write = wantRead, wantWrite

	switch {
	case (wantRead || wantWrite) && fi.id == 0:
		n.lastID = id
		fi.id = id
		n.queues[id] = fi.queue
	case !wantRead && !wantWrite && fi.id != 0:
		delete(n.queues, fi.id)
		fi.id = 0
	}
	return nil
}

// addFD adds an FD to the list of FDs observed by n.
func (n *notifier) addFD(fd int32, queue *waiter.Queue) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Lazy initialization.
	if n.fdMap == nil {
		kq, err := unix.Kqueue()
		if err != nil {
			return err
		}
		unix.CloseOnExec(kq)
		n.kqFD = kq
		n.fdMap = make(map[int32]*fdInfo)
		n.queues = make(map[uint64]*waiter.Queue)
		go n.waitAndNotify() // S/R-SAFE: pauseMu excludes callbacks during save/restore.
	}

	// Panic if we're already notifying on this FD.
	if _, ok := n.fdMap[fd]; ok {
		panic(fmt.Sprintf("File descriptor %v added twice", fd))
	}

	info := &fdInfo{queue: queue}
	// We might already have something in queue to wait for.
	if err := n.waitFD(fd, info, queue.Events()); err != nil {
		return err
	}
	n.fdMap[fd] = info
	return nil
}

// updateFD updates the set of events the fd needs to be notified on.
func (n *notifier) updateFD(fd int32) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if fi, ok := n.fdMap[fd]; ok {
		return n.waitFD(fd, fi, fi.queue.Events())
	}

	return nil
}

// removeFD removes an FD from the list of FDs observed by n.
func (n *notifier) removeFD(fd int32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Remove from map, then from kqueue object.
	if fi, ok := n.fdMap[fd]; ok {
		n.waitFD(fd, fi, 0)
	}
	delete(n.fdMap, fd)
}

// hasFD returns true if the fd is in the list of observed FDs.
func (n *notifier) hasFD(fd int32) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	_, ok := n.fdMap[fd]
	return ok
}

// waitAndNotify runs in its own goroutine and loops waiting for io event
// notifications from the kqueue object. Once notifications arrive, they are
// dispatched to the registered queue.
func (n *notifier) waitAndNotify() error {
	e := make([]unix.Kevent_t, 100)
	for {
		v, err := unix.Kevent(n.kqFD, nil, e, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n.notify(e[:v]) {
			// Let goroutines woken by Notify get a chance to run before
			// we kevent again.
			sync.Goyield()
		}
	}
}

// eventMask converts a returned knote to waiter events.
func eventMask(ev *unix.Kevent_t) waiter.EventMask {
	var m waiter.EventMask
	switch ev.Filter {
	case unix.EVFILT_READ:
		m = waiter.ReadableEvents
		if ev.Flags&unix.EV_EOF != 0 {
			m |= waiter.EventRdHUp | waiter.EventHUp
		}
	case unix.EVFILT_WRITE:
		m = waiter.WritableEvents
		if ev.Flags&unix.EV_EOF != 0 {
			m |= waiter.EventHUp
		}
	}
	if ev.Flags&unix.EV_ERROR != 0 {
		m |= waiter.EventErr
	}
	return m
}

func (n *notifier) notify(events []unix.Kevent_t) bool {
	n.pauseMu.Lock()
	defer n.pauseMu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()

	notified := false
	for i := range events {
		if queue := n.queues[udata(&events[i])]; queue != nil {
			queue.Notify(eventMask(&events[i]))
			notified = true
		}
	}
	return notified
}

var shared notifier

// AddFD adds an FD to the list of observed FDs.
func AddFD(fd int32, queue *waiter.Queue) error {
	return shared.addFD(fd, queue)
}

// UpdateFD updates the set of events the fd needs to be notified on.
func UpdateFD(fd int32) error {
	return shared.updateFD(fd)
}

// RemoveFD removes an FD from the list of observed FDs.
func RemoveFD(fd int32) {
	shared.removeFD(fd)
}

// HasFD returns true if the FD is in the list of observed FDs.
//
// This should only be used by tests to assert that FDs are correctly
// registered.
func HasFD(fd int32) bool {
	return shared.hasFD(fd)
}

// Pause prevents any new notifications from being sent.
func Pause() {
	shared.pauseMu.Lock()
}

// Resume allows notifications to be sent again.
func Resume() {
	shared.pauseMu.Unlock()
}
