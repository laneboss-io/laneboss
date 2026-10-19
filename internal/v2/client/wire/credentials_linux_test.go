//go:build linux

package wire

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAdministratorUnitMembership(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	expected := "/system.slice/laneboss-helper@" + string(id) + ".service/control"
	pid := os.Getpid()
	actual := []byte("0::" + expected + "\n")
	members := []byte(strconv.Itoa(pid) + "\n")
	if err := administratorMembership(actual, members, expected, pid); err != nil {
		t.Fatal("matching helper controller facts were refused", err)
	}
	for _, check := range []struct {
		name    string
		actual  []byte
		members []byte
		pid     int
	}{
		{"outside_unit", []byte("0::/other\n"), members, pid},
		{"parent_only", []byte("0::" + strings.TrimSuffix(expected, "/control") + "\n"), members, pid},
		{"duplicate_unified", append(append([]byte{}, actual...), actual...), members, pid},
		{"wrong_process", actual, []byte(strconv.Itoa(pid + 1)), pid},
		{"another_process", actual, []byte(strconv.Itoa(pid) + "\n" + strconv.Itoa(pid+1)), pid},
		{"empty_control", actual, nil, pid},
		{"no_native_pid", actual, members, 0},
		{"no_unified", []byte("1:name=systemd:/other\n"), members, pid},
	} {
		t.Run(check.name, func(t *testing.T) {
			if err := administratorMembership(check.actual, check.members, expected, check.pid); err == nil {
				t.Fatal("another process or cgroup acquired helper controller identity")
			}
		})
	}
}

func credentialSockets(t *testing.T, passcred bool) (*net.UnixConn, *net.UnixConn, SocketPeer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if passcred {
		if err := EnableCredentials(listener); err != nil {
			t.Fatal(err)
		}
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
	receiver, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sender.Close(); err != nil {
			t.Error(err)
		}
		if err := receiver.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	peer, err := PeerCredentials(receiver)
	if err != nil {
		t.Fatal(err)
	}
	return sender, receiver, peer
}

func TestPinnedWriterCredentials(t *testing.T) {
	sender, receiver, peer := credentialSockets(t, true)
	if peer.PID != os.Getpid() || peer.UID != uint32(os.Geteuid()) {
		t.Fatal("kernel connector control differs")
	}
	if err := WriteFrame(sender, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadPinnedFrame(receiver, peer)
	if err != nil || string(frame.Bytes()) != `{}` {
		t.Fatal("credential frame control refused", err)
	}
	file, err := sender.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// This real native child inherits the connected writer descriptor. Its PID
	// must not borrow the parent's connector identity, even under the same UID.
	child := exec.Command("/usr/bin/printf", `\000\000\000\002{}`)
	child.Stdout = file
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPinnedFrame(receiver, peer); err == nil {
		t.Fatal("inherited socket writer was accepted")
	}
}

func TestMissingWriterCredentials(t *testing.T) {
	sender, receiver, peer := credentialSockets(t, false)
	if err := WriteFrame(sender, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPinnedFrame(receiver, peer); err == nil {
		t.Fatal("missing writer credentials were accepted")
	}
}
