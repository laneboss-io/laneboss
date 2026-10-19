//go:build linux

package wire

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRejectReceivedFD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rpc.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	sender, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sender.Close(); err != nil {
			t.Error(err)
		}
	})
	receiver, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := receiver.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "fd-canary")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	before := descriptorsFor(t, info)
	if _, _, err := sender.WriteMsgUnix([]byte{0, 0, 0, 2, '{', '}'}, unix.UnixRights(int(file.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(receiver); err == nil {
		t.Fatal("descriptor-bearing request accepted")
	}
	if after := descriptorsFor(t, info); after != before {
		t.Fatalf("received descriptor leaked: %d -> %d", before, after)
	}
	controlSender, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controlSender.Close(); err != nil {
			t.Error(err)
		}
	})
	controlReceiver, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controlReceiver.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := controlReceiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(controlSender, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFrame(controlReceiver)
	if err != nil || string(data) != `{}` {
		t.Fatal("plain frame control failed", err)
	}
}

func descriptorsFor(t *testing.T, info os.FileInfo) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		current, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name()))
		if os.IsNotExist(err) {
			continue
		} // ReadDir's own descriptor is already closed.
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(info, current) {
			count++
		}
	}
	return count
}
