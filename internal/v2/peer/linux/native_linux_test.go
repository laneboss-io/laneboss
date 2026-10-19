package linux

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestSocketLifetime(t *testing.T) {
	// The helper is this test executable, with no vendor/credential environment
	// contract. Its real socket and process exit exercise SO_PEERPIDFD.
	if len(os.Args) >= 3 && os.Args[len(os.Args)-2] == "peer-child" {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Args[len(os.Args)-1], Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Write([]byte("ready")); err != nil {
			t.Fatal(err)
		}
		one := make([]byte, 1)
		if _, err := io.ReadFull(connection, one); err != nil || one[0] != 'x' {
			t.Fatalf("peer exit handshake failed: %v", err)
		}
		return
	}
	v := fixtureVerifier(t)
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	observed, err := readProcess(os.Getpid(), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	// A unit fixture pins this test's existing group, including on a box whose
	// test command is in the cgroup root. The production registry rejects root.
	// This is a native-lifetime fixture, not inside-namespace acceptance.
	fd, _, err := openGroup(observed.group)
	if err != nil {
		t.Fatal(err)
	}
	bindFixtureGroup(t, v, fd)
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSocketLifetime$", "--", "peer-child", path)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			if err := command.Process.Kill(); err != nil {
				t.Error("fixture process could not stop")
			}
			if err := command.Wait(); err == nil {
				t.Error("killed fixture unexpectedly exited successfully")
			}
		}
	})
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 5)
	if _, err := io.ReadFull(connection, ready); err != nil || string(ready) != "ready" {
		t.Fatalf("peer ready handshake failed: %v", err)
	}
	verified, err := v.Verify(context.Background(), connection, boundFixtureConn(connection).Binding())
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	facts, err := verified.Facts(context.Background())
	if err != nil || facts.HostPID != command.Process.Pid || facts.HostUID != uint32(os.Getuid()) || facts.HostGID != uint32(os.Getgid()) ||
		facts.ContainmentID != "fixture-group" || facts.ProcessGeneration == "" {
		t.Fatalf("live socket facts did not match real child: %v", err)
	}
	peer := verified.(*nativePeer)
	initial := peer.initial
	peer.initial.ProcessGeneration = "different-generation"
	requireCode(t, peer.Alive(context.Background()), api.CodeUnauthenticated)
	peer.initial = initial
	if err := peer.Alive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := v.registry.RevokeContainment(context.Background(), "fixture-group"); err != nil {
		t.Fatal(err)
	}
	requireCode(t, peer.Alive(context.Background()), api.CodeContainmentUnknown)
	if _, err := connection.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	waitErr := command.Wait()
	waited = true
	if waitErr != nil {
		t.Fatal("fixture process failed")
	}
	requireCode(t, verified.Alive(context.Background()), api.CodeUnauthenticated)
}

func TestRejectContainmentPaths(t *testing.T) {
	for _, path := range []string{"../other", "/absolute", "one/../other", "", "bad\x00path"} {
		_, _, err := openGroup(path)
		requireCode(t, err, api.CodeContainmentUnknown)
	}
}
