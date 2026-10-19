//go:build linux

package admin

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "admin-gate-authentication-fixture" {
		if err := authenticationBeforeExec(os.Args[2], os.Args[3]); err != nil {
			os.Exit(101)
		}
		os.Exit(102)
	}
	if len(os.Args) == 4 && os.Args[1] == "admin-gate-authentication-client" {
		if err := authenticationClient(os.Args[2], api.ID(os.Args[3])); err != nil {
			os.Exit(103)
		}
		os.Exit(0)
	}
	if len(os.Args) == 6 && os.Args[1] == "admin-gate-post-exec-vendor" {
		if err := authenticationVendor(os.Args[2], os.Args[3], api.ID(os.Args[4]), os.Args[5]); err != nil {
			os.Exit(104)
		}
		os.Exit(0)
	}
}

// The deliberately early caller models a released wrapper. Credential source
// authority is synthetic; release, bootstrap-only exec proof, native peer
// credentials, helper dispatch and cgroup verification are production paths.
func authenticationBeforeExec(socket, mode string) error {
	payload, err := readBootstrapInput()
	if err != nil {
		return err
	}
	if err := establishCredentialUmask(); err != nil {
		return err
	}
	ack, err := attestGateReadiness(payload)
	if err != nil {
		return err
	}
	defer refuseExecProof(ack)
	if err := waitForGateRelease(payload.Token); err != nil {
		return err
	}
	// This file-login fixture has no environment targets or transferred FDs.
	// Consume and validate the actual helper packet before asking to authenticate.
	packet := make([]byte, 64<<10)
	n, _, flags, _, err := unix.Recvmsg(5, packet, nil, 0)
	if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n <= 4 || int(binary.BigEndian.Uint32(packet[:4])) != n-4 {
		return unix.EIO
	}
	var delivery credentialExecPacket
	if err := decodeStrict(packet[4:n], &delivery); err != nil || len(delivery.Objects) != 0 ||
		delivery.Record.Authority.Request.Prepared.ID != payload.PreparedID ||
		delivery.Record.Authority.Request.Prepared.GateID != payload.GateID {
		return unix.EINVAL
	}
	if mode != "before-exec" {
		payload.Argv = []string{payload.Argv[0], "admin-gate-post-exec-vendor", payload.Token, socket,
			string(delivery.Record.Authority.Request.Lease.ID), mode}
	} else if err := authenticationClient(socket, delivery.Record.Authority.Request.Lease.ID); err != nil {
		return err
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err
	}
	return unix.Exec(payload.Argv[0], payload.Argv, payload.Environment)
}

func authenticationClient(socket string, lease api.ID) error {
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	peer, err := pinPeer(connection, 0, 0)
	if err != nil {
		return err
	}
	defer closePeer(peer)
	if err := writeFrame(connection, containmentQuery{LeaseID: lease, Opened: true}); err != nil {
		return err
	}
	raw, err := readUnixFrame(connection, peer)
	if err != nil {
		return err
	}
	var ticket containmentTicket
	if err := decodeStrict(raw, &ticket); err != nil || ticket.Lease.ID != lease {
		return unix.EINVAL
	}
	if err := connection.Close(); err != nil {
		return err
	}
	return nil
}

func authenticationVendor(token, socket string, lease api.ID, mode string) error {
	if strings.HasPrefix(mode, "after-opened") {
		var allow [1]byte
		if n, err := os.Stdin.Read(allow[:]); err != nil || n != 1 || allow[0] != 'a' {
			return unix.EIO
		}
	}
	limit := 5 * time.Second
	if strings.HasPrefix(mode, "after-opened-concurrent") {
		// Each CLI keeps its own unchanged five-second deadline. This bounds
		// only the parent runner's fork/wait and collection of all children.
		limit = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	// The installed actor's first connector is its CLI child, after runner exec.
	if strings.HasPrefix(mode, "after-opened-concurrent") {
		results := make(chan error, 20)
		var children sync.WaitGroup
		for range 20 {
			children.Add(1)
			go func() {
				defer children.Done()
				client := exec.CommandContext(ctx, "/proc/self/exe", "admin-concurrent-identity-client", socket, string(lease))
				client.Env = []string{}
				results <- client.Run()
			}()
		}
		children.Wait()
		close(results)
		for err := range results {
			if err != nil {
				return err
			}
		}
	} else {
		client := exec.CommandContext(ctx, "/proc/self/exe", "admin-gate-authentication-client", socket, string(lease))
		client.Env = []string{}
		if err := client.Run(); err != nil {
			return err
		}
	}
	if n, err := os.Stdout.WriteString(token); err != nil || n != len(token) {
		return unix.EIO
	}
	var hold [1]byte
	if n, err := os.Stdin.Read(hold[:]); n != 0 || !errors.Is(err, io.EOF) {
		return unix.EIO
	}
	return nil
}

func authenticationReadiness(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(pair[0]), "authentication-readiness"), os.NewFile(uintptr(pair[1]), "authentication-bootstrap")
}

func authenticationGateReady(t *testing.T, gate *nativeGate, read, write *os.File) {
	t.Helper()
	connection, err := net.FileConn(read)
	if err != nil {
		t.Fatal(err)
	}
	gate.control = connection.(*net.UnixConn)
	if err := gate.control.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, controls := make([]byte, 256), make([]byte, 4096)
	n, count, flags, err := receiveNativeReadiness(gate.control, data, controls)
	if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || string(data[:n]) != gate.token {
		t.Fatal("credential authentication bootstrap did not attest readiness", err)
	}
	peer, ack, err := nativeReadinessPeer(controls[:count], true)
	if err != nil || peer.Pid != int32(gate.PID()) {
		t.Fatal("credential authentication readiness lost its exact native child", err)
	}
	gate.execAck, gate.innerPID, gate.innerGeneration = ack, int(peer.Pid), gate.Generation()
	gate.innerFD, err = unix.PidfdOpen(gate.innerPID, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(gate.innerFD)
	// Root-created helper metadata delivery checks this actual process umask.
	mask, err := measureProcessUmask(strconv.Itoa(gate.innerPID))
	if err != nil {
		t.Fatal(err)
	}
	gate.bootstrapUmask = &mask
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := gate.control.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		if err := gate.execAck.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		if err := unix.Close(gate.innerFD); err != nil {
			t.Error(err)
		}
	})
}
