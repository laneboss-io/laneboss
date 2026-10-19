//go:build linux

package admin

import (
	"errors"
	"os"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ended is released only by an actual primary pidfd event or terminal Wait.
// An observation error is not a death event and cannot release the creator.
type nativeSpawnLifetime struct {
	mu       sync.Mutex
	once     sync.Once
	ended    chan struct{}
	tid      int
	released bool

	threadDone chan struct{}
}

func newNativeSpawnLifetime() *nativeSpawnLifetime {
	return &nativeSpawnLifetime{ended: make(chan struct{}), threadDone: make(chan struct{})}
}

func (l *nativeSpawnLifetime) startedThread() {
	if l != nil {
		l.mu.Lock()
		l.tid = unix.Gettid()
		l.mu.Unlock()
	}
}

func (l *nativeSpawnLifetime) observedExit() {
	if l != nil && l.ended != nil {
		l.once.Do(func() { close(l.ended) })
	}
}

func (l *nativeSpawnLifetime) observedWait(state *os.ProcessState) {
	if state == nil {
		return
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if ok && (status.Exited() || status.Signaled()) {
		l.observedExit()
	}
}

func (l *nativeSpawnLifetime) holdThread() {
	if l != nil {
		<-l.ended
	}
}

func (l *nativeSpawnLifetime) releasedThread() {
	if l != nil {
		l.mu.Lock()
		if !l.released {
			l.released = true
			if l.threadDone != nil {
				close(l.threadDone)
			}
		}
		l.mu.Unlock()
	}
}

func (l *nativeSpawnLifetime) fact() string {
	if l == nil {
		return "unavailable"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return "released"
	}
	if l.tid <= 0 {
		return "unavailable"
	}
	if _, err := os.Stat("/proc/self/task/" + strconv.Itoa(l.tid)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "missing"
		}
		return "unavailable"
	}
	return "locked_present"
}
