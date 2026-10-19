//go:build linux && laneboss_gate_integration

package wire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "wire-pidns-service" {
		os.Exit(pidnsServiceFixture(os.Args[2], []byte(os.Args[3])))
	}
	if len(os.Args) == 5 && os.Args[1] == "wire-pidns-client" {
		os.Exit(pidnsClientFixture(os.Args[2], os.Args[3], []byte(os.Args[4])))
	}
}

func pidnsServiceFixture(path string, marker []byte) int {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil || os.Chmod(path, 0666) != nil {
		return 91
	}
	defer listener.Close()
	ready := os.NewFile(3, "peer-fixture-ready")
	if _, err := ready.Write([]byte{1}); err != nil || ready.Close() != nil {
		return 92
	}
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return 93
	}
	connection, err := listener.AcceptUnix()
	if err != nil {
		return 94
	}
	if connection.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		return 95
	}
	data := make([]byte, len(marker))
	if _, err := io.ReadFull(connection, data); err != nil || string(data) != string(marker) {
		return 96
	}
	if err := writeAll(connection, data); err != nil || connection.Close() != nil {
		return 97
	}
	return 0
}

func pidnsClientFixture(config, version string, marker []byte) int {
	binding, err := ReadBinding(LaneBindingPath, config, version)
	if err != nil {
		return 101
	}
	digest, err := ArtifactDigest()
	if err != nil || binding.ArtifactSHA256 != digest {
		return 102
	}
	endpoint, err := PinEndpoint(LaneBindingPath, binding)
	if err != nil {
		return 103
	}
	defer endpoint.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := endpoint.DialContext(ctx, &net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error { return EnableRawCredentials(raw) }})
	if err != nil {
		return 104
	}
	socket := connection.(*net.UnixConn)
	peer, err := endpoint.PeerCredentials(socket)
	if err != nil {
		return 105
	}
	if peer.PID != 0 || peer.UID != binding.MappedServiceUID || peer.GID != binding.MappedServiceGID {
		return 106
	}
	if _, err := PeerCredentials(socket); err == nil {
		return 107 // The service-side visible-connector rule must stay strict.
	}
	if err := socket.SetDeadline(time.Now().Add(3 * time.Second)); err != nil || writeAll(socket, marker) != nil {
		return 108
	}
	data := make([]byte, len(marker))
	if _, err := io.ReadFull(&credentialReader{connection: socket, expected: peer}, data); err != nil || string(data) != string(marker) {
		return 109
	}
	if socket.Close() != nil {
		return 110
	}
	return 0
}

// This native canary needs the disposable installed Linux test environment:
// root, the enrolled bwrap-only AppArmor allowance and real user/PID namespaces.
// It measures mapped server IDs, PID zero and per-message credentials. It does
// not stand in for the helper's cgroup/lease/job authentication or installed E2E.
func TestProjectedServerPIDNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native namespace peer canary requires the disposable root test kit")
	}
	stage, err := os.MkdirTemp("/run", "lb-v2-serve2b-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(stage, 0755); err != nil {
		t.Fatal(err)
	}
	const serviceUID, laneUID = 61100, 61101
	serviceDirectory := filepath.Join(stage, "service")
	if err := os.Mkdir(serviceDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(serviceDirectory, serviceUID, serviceUID); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(stage, "peer-test")
	output, err := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if err != nil {
		t.Fatal(errors.Join(err, input.Close()))
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, output.Close(), input.Close()); err != nil {
		t.Fatal(err)
	}
	marker, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	path := filepath.Join(serviceDirectory, "service.sock")
	service := exec.CommandContext(ctx, binary, "wire-pidns-service", path, string(marker))
	service.Env = []string{"PATH=/usr/bin:/bin"}
	service.ExtraFiles = []*os.File{readyWrite}
	service.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: serviceUID, Gid: serviceUID, Groups: []uint32{}}}
	if err := service.Start(); err != nil {
		t.Fatal(errors.Join(err, readyWrite.Close()))
	}
	serviceWaited := false
	t.Cleanup(func() {
		if serviceWaited {
			return
		}
		cancel()
		waitErr := service.Wait()
		var exited *exec.ExitError
		if errors.As(waitErr, &exited) {
			status, ok := exited.Sys().(syscall.WaitStatus)
			if ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
				return // Expected collection after a preceding failed canary step.
			}
		}
		if waitErr != nil {
			t.Error("native service fixture failed during collection", waitErr)
		}
	})
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 1 {
		t.Fatal("native service fixture did not create its actual endpoint", err)
	}
	socketFD, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(socketFD), "native-peer-socket")
	defer socket.Close()
	binding := laneBindingFixture()
	binding.ServiceUID, binding.ServiceGID = serviceUID, serviceUID
	binding.MappedServiceUID, binding.MappedServiceGID, err = NamespaceServiceIDs()
	if err != nil {
		t.Fatal(err)
	}
	binding.ArtifactSHA256, err = ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	proof := projectionMemfd(t, raw, 0444, projectionSeals)
	null, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	args := []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-net", "--cap-drop", "ALL", "--clearenv",
		"--proc", "/proc", "--dev", "/dev", "--dir", "/run/laneboss", "--dir", "/runtime", "--tmpfs", "/tmp",
		"--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib"}
	if _, err := os.Lstat("/lib64"); err == nil {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	args = append(args, "--ro-bind", binary, "/runtime/test", "--symlink", "/proc/self/fd/6", LaneBindingPath,
		"--symlink", "/proc/self/fd/7", LaneSocketPath, "--remount-ro", "/", "--", "/runtime/test", "wire-pidns-client", binding.Config, binding.ServiceVersion, string(marker))
	command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.ExtraFiles = []*os.File{null, null, null, proof, socket}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: laneUID, Gid: laneUID, Groups: []uint32{}}}
	if err := command.Run(); err != nil {
		t.Fatal("native namespace peer canary failed; require the reached fixture exit, not a setup refusal", err)
	}
	serviceErr := service.Wait()
	serviceWaited = true
	if serviceErr != nil {
		t.Fatal("native service did not measure the actual challenge/response", serviceErr)
	}
}
