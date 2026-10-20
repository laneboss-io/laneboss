//go:build linux

package service_test

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The root box clears groups before dropping to the unprivileged fixture UID.
// Build as the queue user, then run the complete listener/actor test as that UID.
func relayRoot(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Keep the fixture's real AF_UNIX pathname within the kernel bound.
	dir, err := os.MkdirTemp("/home", "rb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "testbin")
	if err := os.WriteFile(binary, raw, 0555); err != nil {
		t.Fatal(err)
	}
	actor := filepath.Join(dir, "actor")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", actor, "./scripts/v2-serve/grants_actor")
	build.Dir = filepath.Join("..", "..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("real relay build: %v\n%s", err, output)
	}
	cmd := exec.CommandContext(ctx, binary, "-test.v", "-test.run=^TestRelayBootstrap$", "--", "relay-boot-child", actor)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "TMPDIR=/tmp"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "--- PASS: TestRelayBootstrap") {
		t.Fatalf("unprivileged real relay bootstrap: %v\n%s", err, output)
	}
	t.Log(string(output))
}

// Run the real descriptor-only bootstrap before the actual relay executable.
// Runtime/identity/mailbox inputs remain the existing component fixture. No
// helper privilege is acquired, and the production confinement is unmodified.
func relayBootstrap(t *testing.T, cmd *exec.Cmd, actor, config string, uid, gid int, binding, socket *os.File) {
	boundary := -1
	for i, arg := range cmd.Args {
		if arg == actor {
			boundary = i
			break
		}
	}
	if boundary < 1 {
		t.Fatal("native relay lacks its actual executable")
	}
	token := string(fx.ID(t))
	path := func(name string, dir, write, execute bool) map[string]any {
		return map[string]any{"path": name, "directory": dir, "writable": write, "executable": execute}
	}
	payload := map[string]any{"config": config, "mode": "prepared-gate", "gate_id": string(fx.ID(t)),
		"token": token, "uid": uid, "gid": gid, "argv": append([]string{}, cmd.Args[boundary:]...),
		"cwd": "/tmp", "budget": api.Budget{}, "environment": []string{"HOME=/tmp", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", "GOMAXPROCS=1"},
		"paths": []map[string]any{path(actor, false, false, true), path(wire.LaneClientPath, false, false, true),
			path("/usr/lib", true, false, true), path("/proc", true, false, false), path("/tmp", true, true, true),
			path("/dev/null", false, true, false), path("/dev/urandom", false, true, false)},
		"inherited": []map[string]any{{"fd": 6, "target": wire.LaneBindingPath, "socket": false}, {"fd": 7, "target": wire.LaneSocketPath, "socket": true}}}
	fd, err := unix.MemfdCreate("relay-bootstrap", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	sealed := os.NewFile(uintptr(fd), "bootstrap-input")
	t.Cleanup(func() { sealed.Close() })
	if _, err := sealed.Write(fx.JSON(t, payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(sealed.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { read.Close(); write.Close() })
	if _, err := write.WriteString(token); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	owner, child := os.NewFile(uintptr(pair[0]), "readiness-owner"), os.NewFile(uintptr(pair[1]), "readiness-child")
	t.Cleanup(func() { owner.Close(); child.Close() })
	connection, err := net.FileConn(owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	cmd.ExtraFiles = []*os.File{sealed, read, child, binding, socket}
	cmd.Args = append(cmd.Args[:boundary], "--setenv", "GOMAXPROCS", "1", wire.LaneClientPath, admin.FixedBootstrapEntry, "prepared-gate", "--config", config)
	ready := make(chan error, 1)
	go func() {
		if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			ready <- err
			return
		}
		data := make([]byte, 256)
		n, err := connection.Read(data)
		if err == nil && string(data[:n]) != token {
			err = unix.EPROTO
		}
		ready <- err
	}()
	t.Cleanup(func() {
		if err := <-ready; err != nil {
			t.Error("real bootstrap did not attest its confinement", err)
		}
	})
}
