//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestCodexAuthBeforeExec(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("credential authentication canary requires the disposable Linux root box")
	}
	id, err := randomID("lb-v2-cx-auth2-")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join("/run", string(id))
	if err := os.Mkdir(stage, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(stage); err != nil {
			t.Error(err)
		}
	})
	socket := filepath.Join(stage, "authenticate.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	// Capture the first sender's credentials even if it writes before Accept.
	// The production credential metadata listener enables this before launch.
	control, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	if err := control.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil || socketErr != nil {
		t.Fatal("authentication listener cannot capture native message credentials", err, socketErr)
	}
	if err := os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	var group, lanes, unit string
	t.Cleanup(func() {
		for _, path := range []string{group, lanes, unit} {
			if path != "" {
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
			}
		}
	})
	gate, reader, boot, uid, gid, _ := descriptorGateAuthentication(t, [2]*os.File{}, socket)
	manager, registration, _, _, store := retainedGateFromNative(t, gate, reader, boot, uid, gid)
	manager, registration, _, _, _, _, _ = stopCredentialsForGate(t, false, manager, registration, gate, reader, store)
	records, err := manager.records()
	if err != nil || len(records) != 1 {
		t.Fatal("credential authentication journal is unavailable", err)
	}
	record := records[0]
	if record.Spec.Handoff.Spec.Runner.Driver != api.DriverCodex || record.Credentials == nil || record.Credentials.State != "held" {
		t.Fatal("authentication canary did not retain the credentialed Codex gate")
	}
	lanes = manager.binding.cgroupPath()
	unit = filepath.Dir(lanes)
	group = filepath.Join(lanes, string(record.Lease.ContainmentID))
	for _, path := range []string{unit, lanes, group} {
		if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal("cannot create real authentication containment", err)
		}
	}
	if err := os.Chmod(group, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperCallTimeout)
	defer cancel()
	membership := strings.TrimPrefix(group, "/sys/fs/cgroup")
	facts := api.PeerFacts{HostPID: gate.PID(), HostUID: uid, HostGID: gid, ProcessGeneration: gate.Generation()}
	if err := verifyContainedProcess(ctx, facts, boot, membership); err == nil {
		t.Fatal("outside-cgroup native control authenticated before placement")
	}
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(gate.PID())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyContainedProcess(ctx, facts, boot, membership); err != nil {
		t.Fatal("native child did not enter its actual registered containment", err)
	}
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	opened := make(chan error, 1)
	guard := &credentialGuardFixture{}
	go func() {
		openCtx, unlock := manager.lockHelperOperation(ctx, false)
		defer unlock()
		_, err := manager.withCredentialGuard(openCtx, guard, func() (api.ProcessHandle, error) {
			return manager.openGate(openCtx, registration)
		})
		opened <- err
	}()
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("released credential bootstrap did not request native authentication", err)
	}
	defer connection.Close()
	peer, err := pinPeer(connection, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer closePeer(peer)
	if int(peer.credentials.Pid) != gate.PID() {
		t.Fatal("pre-exec authentication arrived from another process")
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := readUnixFrame(connection, peer)
	if err != nil {
		t.Fatal(err)
	}
	metadataCtx, unlock := manager.lockHelperOperation(ctx, true)
	if manager.helperMu.TryLock() {
		manager.helperMu.Unlock()
		unlock()
		t.Fatal("authentication did not reach the real pending open_gate operation")
	}
	proof, err := gate.execAck.SyscallConn()
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	var pending bool
	if err := proof.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := pollHelperLifetime(fds, unix.Poll)
		pending = err == nil && count == 0 && fds[0].Revents == 0
	}); err != nil || !pending {
		unlock()
		t.Fatal("authentication did not reach the native credential-exec wait", err)
	}
	result, authErr := manager.dispatch(metadataCtx, "containment_live", raw)
	if authErr == nil {
		current, readErr := store.Records()
		if readErr != nil || len(current) != 1 || current[0].Gate.State != "opening" || openedContainment(current[0]) {
			authErr = errors.New("authentication promoted the pending exec to opened")
		} else if err := verifyContainedProcess(metadataCtx, facts, boot, membership); err != nil {
			authErr = err
		} else if err := peer.alive(); err != nil {
			authErr = err
		}
	}
	unlock()
	if authErr != nil {
		t.Errorf("released Codex peer could not authenticate before credential exec: %v", authErr)
	} else if err := writeFrame(connection, result); err != nil {
		t.Error("native authentication reply failed", err)
	}
	if err := connection.Close(); err != nil {
		t.Error(err)
	}
	select {
	case err := <-opened:
		if err != nil {
			t.Fatal("credential exec did not complete after native authentication", err)
		}
	case <-ctx.Done():
		t.Fatal("credential exec did not complete within the existing helper deadline")
	}
	if authErr != nil {
		return
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(gate.token))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != gate.token {
		t.Fatal("authenticated bootstrap did not exec the pinned real runner", err)
	}
	records, err = manager.records()
	if err != nil || len(records) != 1 || records[0].Gate.State != "opened" || guard.checks != 2 || guard.closes != 1 {
		t.Fatal("credential exec proof or guard did not complete the original gate", err)
	}
	t.Log("pre-exec native authentication passed through containment_live; gate stayed opening until EOF and executable hash proof")
}
