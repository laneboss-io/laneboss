package linux

import (
	"context"
	"errors"
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

type nativeFixture struct {
	verifier *Verifier
	peer     *nativePeer
	conn     *net.UnixConn
	command  *exec.Cmd
	passed   *os.File
	ended    bool
}

func closeFixture(t *testing.T, close func() error) {
	t.Helper()
	if err := close(); err != nil {
		t.Errorf("fixture cleanup: close failed: %v", err)
	}
}

func (f *nativeFixture) end(t *testing.T) {
	t.Helper()
	if f.ended {
		return
	}
	if n, err := f.conn.Write([]byte("x")); err != nil {
		t.Fatalf("fixture cleanup: exit handshake failed: %v", err)
	} else if n != 1 {
		t.Fatalf("fixture cleanup: exit handshake wrote %d bytes, want 1", n)
	}
	err := f.command.Wait()
	f.ended = true
	if err != nil {
		t.Fatalf("fixture cleanup: child did not exit successfully: %v", err)
	}
}

func startNativeFixture(t *testing.T, mode string) *nativeFixture {
	t.Helper()
	f := new(nativeFixture)
	t.Cleanup(func() {
		if f.command != nil && !f.ended {
			// Stop only the owned child by its process handle, never a pattern.
			err := f.command.Process.Kill()
			if err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("fixture cleanup: child could not stop: %v", err)
			}
			waitErr := f.command.Wait()
			f.ended = true
			var exit *exec.ExitError
			if waitErr != nil && !errors.As(waitErr, &exit) {
				t.Errorf("fixture cleanup: child could not be reaped: %v", waitErr)
			}
		}
		if f.passed != nil {
			closeFixture(t, f.passed.Close)
		}
		if f.peer != nil {
			closeFixture(t, f.peer.Close)
		}
		if f.conn != nil {
			closeFixture(t, f.conn.Close)
		}
		if f.verifier != nil {
			closeFixture(t, f.verifier.Close)
		}
	})
	v := fixtureVerifier(t)
	f.verifier = v
	observed, err := readProcess(os.Getpid(), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatalf("fixture setup: host facts unavailable: %v", err)
	}
	fd, _, err := openGroup(observed.group)
	if err != nil {
		t.Fatalf("fixture setup: current cgroup unavailable: %v", err)
	}
	// Only this package fixture pins the test's existing group, possibly the
	// root. The production registry still requires a dedicated helper group.
	bindFixtureGroup(t, v, fd)
	if err := unix.Close(fd); err != nil {
		t.Fatalf("fixture setup: original cgroup pin could not close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("fixture setup: listener failed: %v", err)
	}
	t.Cleanup(func() { closeFixture(t, listener.Close) })
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("fixture setup: listener deadline failed: %v", err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPeerChecksFixture$",
		"--", "fixture-child", path, mode)
	var control *net.UnixConn
	var childControl *os.File
	if mode == "transfer" {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("fixture setup: transfer pair failed: %v", err)
		}
		parentFile := os.NewFile(uintptr(fds[0]), "fixture-parent")
		childControl = os.NewFile(uintptr(fds[1]), "fixture-child")
		parent, err := net.FileConn(parentFile)
		closeFixture(t, parentFile.Close)
		t.Cleanup(func() { closeFixture(t, childControl.Close) })
		if err != nil {
			t.Fatalf("fixture setup: transfer connection failed: %v", err)
		}
		control = parent.(*net.UnixConn)
		t.Cleanup(func() { closeFixture(t, control.Close) })
		if err := control.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("fixture setup: transfer deadline failed: %v", err)
		}
		command.ExtraFiles = []*os.File{childControl}
	}
	if err := command.Start(); err != nil {
		t.Fatalf("fixture setup: child could not start: %v", err)
	}
	f.command = command
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("fixture setup: accept failed: %v", err)
	}
	f.conn = conn
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("fixture setup: peer deadline failed: %v", err)
	}
	ready := make([]byte, 5)
	if n, err := io.ReadFull(conn, ready); err != nil {
		t.Fatalf("fixture setup: child readiness failed: %v", err)
	} else if n != len(ready) || string(ready) != "ready" {
		t.Fatalf("fixture setup: child readiness count=%d marker=%q, want 5 and ready", n, ready)
	}
	verified, err := v.Verify(context.Background(), conn, boundFixtureConn(conn).Binding())
	if err != nil {
		t.Fatalf("fixture setup: authentic peer failed: %v", err)
	}
	f.peer = verified.(*nativePeer)
	facts, err := verified.Facts(context.Background())
	if err != nil {
		t.Fatalf("fixture setup: child facts failed: %v", err)
	}
	if facts.HostPID != command.Process.Pid {
		t.Fatal("fixture setup: observed host PID differs from the actual child")
	}
	if facts.HostUID != uint32(os.Getuid()) {
		t.Fatal("fixture setup: observed host UID differs from the actual child")
	}
	if facts.HostGID != uint32(os.Getgid()) {
		t.Fatal("fixture setup: observed host GID differs from the actual child")
	}
	if facts.ProcessGeneration == "" {
		t.Fatal("fixture setup: child process generation is empty")
	}
	if facts.ContainmentID != "fixture-group" {
		t.Fatal("fixture setup: observed containment differs from the pinned fixture group")
	}
	if control != nil {
		data, ancillary := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
		n, count, flags, _, err := control.ReadMsgUnix(data, ancillary)
		if err != nil {
			t.Fatalf("fixture setup: descriptor recvmsg: data=%d control=%d flags=%#x: %v", n, count, flags, err)
		}
		if n < 0 || n > len(data) || count < 0 || count > len(ancillary) {
			t.Fatalf("fixture setup: recvmsg returned out-of-bound counts: data=%d control=%d", n, count)
		}
		file, err := takeFixtureDescriptor(data[:n], ancillary[:count], flags)
		if err != nil {
			t.Fatalf("fixture setup: descriptor transfer: data=%d control=%d flags=%#x: %v", n, count, flags, err)
		}
		f.passed = file
		t.Logf("fixture transfer: data=%d control=%d flags=%#x descriptors=1 cloexec=verified", n, count, flags)
	}
	return f
}

func fixtureChild(t *testing.T, path, mode string) {
	t.Helper()
	if mode == "detached" {
		if _, err := unix.Setsid(); err != nil {
			t.Fatalf("fixture setup: detach failed: %v", err)
		}
	}
	if mode == "writer" {
		file := os.NewFile(3, "fixture-writer")
		defer file.Close()
		if n, err := file.Write([]byte("other")); err != nil {
			t.Fatalf("fixture setup: passed writer failed: %v", err)
		} else if n != 5 {
			t.Fatalf("fixture setup: passed writer wrote %d bytes, want 5", n)
		}
		return
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("fixture setup: child connect failed: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("fixture setup: child deadline failed: %v", err)
	}
	if n, err := conn.Write([]byte("ready")); err != nil {
		t.Fatalf("fixture setup: readiness write failed: %v", err)
	} else if n != 5 {
		t.Fatalf("fixture setup: readiness write count=%d, want 5", n)
	}
	if mode == "transfer" {
		controlFile := os.NewFile(3, "fixture-transfer")
		control, err := net.FileConn(controlFile)
		closeFixture(t, controlFile.Close)
		if err != nil {
			t.Fatalf("fixture setup: child transfer failed: %v", err)
		}
		defer control.Close()
		file, err := conn.File()
		if err != nil {
			t.Fatalf("fixture setup: child duplicate failed: %v", err)
		}
		defer file.Close()
		if err := control.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("fixture setup: transfer write deadline failed: %v", err)
		}
		rights := unix.UnixRights(int(file.Fd()))
		n, count, err := control.(*net.UnixConn).WriteMsgUnix([]byte("f"), rights, nil)
		if err != nil {
			t.Fatalf("fixture setup: child transfer write failed: %v", err)
		}
		if n != 1 || count != len(rights) {
			t.Fatalf("fixture setup: child transfer wrote data=%d control=%d, want 1 and %d", n, count, len(rights))
		}
	}
	one := make([]byte, 1)
	if n, err := io.ReadFull(conn, one); err != nil {
		t.Fatalf("fixture cleanup: child exit handshake failed: %v", err)
	} else if n != 1 || one[0] != 'x' {
		t.Fatalf("fixture cleanup: exit handshake count=%d marker=%#x, want 1 and x", n, one[0])
	}
}

func TestPeerChecksFixture(t *testing.T) {
	if len(os.Args) >= 4 && os.Args[len(os.Args)-3] == "fixture-child" {
		fixtureChild(t, os.Args[len(os.Args)-2], os.Args[len(os.Args)-1])
		return
	}
	for _, rule := range []string{"live", "detached", "generation", "containment", "uid", "gid", "lifetime", "closed"} {
		t.Run(rule, func(t *testing.T) {
			mode := "ordinary"
			if rule == "detached" {
				mode = rule
			}
			f := startNativeFixture(t, mode)
			switch rule {
			case "live", "detached":
				if err := f.peer.Alive(context.Background()); err != nil {
					t.Fatalf("fixture check: authentic child was refused: %v", err)
				}
			case "generation":
				f.peer.initial.ProcessGeneration += ":contradiction"
				requireCode(t, f.peer.Alive(context.Background()), api.CodeUnauthenticated)
			case "containment":
				if err := f.verifier.registry.RevokeContainment(context.Background(), "fixture-group"); err != nil {
					t.Fatalf("fixture setup: unbind failed: %v", err)
				}
				requireCode(t, f.peer.Alive(context.Background()), api.CodeContainmentUnknown)
			case "uid":
				_, err := readProcess(f.peer.pid, f.peer.uid^1, f.peer.gid)
				requireCode(t, err, api.CodeUnauthenticated)
			case "gid":
				_, err := readProcess(f.peer.pid, f.peer.uid, f.peer.gid^1)
				requireCode(t, err, api.CodeUnauthenticated)
			case "lifetime":
				f.end(t)
				requireCode(t, liveFD(f.peer.fd), api.CodeUnauthenticated)
			case "closed":
				if err := f.peer.Close(); err != nil {
					t.Fatalf("fixture setup: handle close failed: %v", err)
				}
				requireCode(t, f.peer.Alive(context.Background()), api.CodeUnauthenticated)
			}
			f.end(t)
		})
	}
}

// This canary demonstrates the connector-only scope of socket credentials; it
// is not a claim that PeerVerifier can authenticate every writer of a passed FD.
func TestPassedSocketFixture(t *testing.T) {
	f := startNativeFixture(t, "transfer")
	writer := exec.Command(os.Args[0], "-test.run=^TestPeerChecksFixture$",
		"--", "fixture-child", "unused", "writer")
	writer.ExtraFiles = []*os.File{f.passed}
	if err := writer.Start(); err != nil {
		t.Fatalf("fixture setup: passed writer could not start: %v", err)
	}
	if err := writer.Wait(); err != nil {
		t.Fatalf("fixture setup: passed writer did not complete: %v", err)
	}
	data := make([]byte, 5)
	if n, err := io.ReadFull(f.conn, data); err != nil {
		t.Fatalf("fixture setup: passed writer bytes not observed: %v", err)
	} else if n != len(data) || string(data) != "other" {
		t.Fatalf("fixture setup: passed writer count=%d marker=%q, want 5 and other", n, data)
	}
	facts, err := f.peer.Facts(context.Background())
	if err != nil {
		t.Fatalf("fixture check: connector facts failed after transfer: %v", err)
	}
	if writer.Process.Pid == f.command.Process.Pid {
		t.Fatal("fixture check: passed writer and original connector have the same PID")
	}
	if facts.HostPID != f.command.Process.Pid || facts.HostPID == writer.Process.Pid {
		t.Fatal("fixture check: socket credentials no longer identify the original connector")
	}
	f.end(t)
	if n, err := f.passed.Write([]byte("again")); err != nil {
		t.Fatalf("fixture setup: inherited connection did not remain writable: %v", err)
	} else if n != 5 {
		t.Fatalf("fixture setup: inherited connection wrote %d bytes, want 5", n)
	}
	if n, err := io.ReadFull(f.conn, data); err != nil {
		t.Fatalf("fixture setup: post-exit writer bytes not observed: %v", err)
	} else if n != len(data) || string(data) != "again" {
		t.Fatalf("fixture setup: post-exit writer count=%d marker=%q, want 5 and again", n, data)
	}
	requireCode(t, f.peer.Alive(context.Background()), api.CodeUnauthenticated)
}
