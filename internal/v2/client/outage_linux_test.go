//go:build linux

package client

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
)

func drainOpens(t *testing.T, descriptor int) int {
	t.Helper()
	buffer := make([]byte, 4096)
	count := 0
	for {
		n, err := unix.Read(descriptor, buffer)
		if errors.Is(err, unix.EAGAIN) {
			return count
		}
		if err != nil {
			t.Fatal("inotify read failed")
		}
		if n == 0 {
			t.Fatal("inotify unexpectedly ended")
		}
		for offset := 0; offset < n; {
			if n-offset < unix.SizeofInotifyEvent {
				t.Fatal("inotify event was truncated")
			}
			mask := binary.NativeEndian.Uint32(buffer[offset+4 : offset+8])
			length := binary.NativeEndian.Uint32(buffer[offset+12 : offset+16])
			if mask&unix.IN_Q_OVERFLOW != 0 {
				t.Fatal("inotify canary overflowed")
			}
			if mask&unix.IN_OPEN != 0 {
				count++
			}
			offset += unix.SizeofInotifyEvent + int(length)
			if offset > n {
				t.Fatal("inotify event length was invalid")
			}
		}
	}
}

func TestOutageKeepsStateClosed(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.sqlite")
	canary := []byte(fixtureRequest(t).RequestID)
	if err := os.WriteFile(path, canary, 0600); err != nil {
		t.Fatal(err)
	}
	watch, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal("inotify prerequisite is missing")
	}
	t.Cleanup(func() {
		if err := unix.Close(watch); err != nil {
			t.Error(err)
		}
	})
	if _, err := unix.InotifyAddWatch(watch, path, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	control, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if drainOpens(t, watch) == 0 {
		t.Fatal("state open canary did not observe its control")
	}
	request := fixtureRequest(t)
	c := &Client{Options: Options{Config: request.Config, BindingFile: path}}
	// A private transport fixture reaches a genuine missing-socket error. The
	// readable canary is not a binding and production Open remains unavailable.
	c.dial = func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(directory, "missing.sock"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = c.Call(ctx, request)
	assertCode(t, err, api.CodeUnavailable)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if drainOpens(t, watch) != 0 {
		t.Fatal("socket outage opened direct state")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != sha256.Sum256(canary) {
		t.Fatal("socket outage changed direct state")
	}
}
