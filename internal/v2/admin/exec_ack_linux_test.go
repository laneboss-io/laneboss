//go:build linux

package admin

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExecProofRefusal(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(pair[0]), "exec-proof-refusal-reader")
	connection, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	refuseExecProof(pair[1])
	var data [1]byte
	n, err := connection.Read(data[:])
	if err != nil || n != 1 || data[0] != 1 {
		t.Fatal("acceptance: bootstrap refusal became success-shaped exec EOF", err)
	}
	if n, err := connection.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("exec refusal did not close its original proof end", err)
	}
}

func TestExecProofPeer(t *testing.T) {
	previous := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previous)
	for _, name := range []string{"valid", "missing", "extra", "type", "unexpected"} {
		t.Run(name, func(t *testing.T) {
			sender, receiver := credentialSocketPair(t)
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			file := os.NewFile(uintptr(pair[1]), "exec-proof-source")
			defer file.Close()
			before := credentialAliasCount(t, file)
			rights := []int{pair[1]}
			switch name {
			case "missing":
				rights = nil
			case "extra":
				rights = append(rights, pair[1])
			case "type":
				other, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				rights[0] = int(other.Fd())
			}
			const token = "native-exec-proof-canary"
			var ancillary []byte
			if len(rights) != 0 {
				ancillary = unix.UnixRights(rights...)
			}
			if n, _, err := sender.WriteMsgUnix([]byte(token), ancillary, nil); err != nil || n != len(token) {
				t.Fatal(err)
			}
			controls, err := readNativeReadiness(receiver, token, &nativeGate{})
			if err != nil {
				t.Fatal("real native readiness transport failed", err)
			}
			peer, ack, err := nativeReadinessPeer(controls, name != "unexpected")
			if name == "valid" {
				if err != nil || ack == nil || peer == nil || int(peer.Pid) != os.Getpid() || credentialAliasCount(t, file) != before+1 {
					t.Fatal("acceptance: native readiness lost the exact bootstrap exec proof", err)
				}
			} else if err == nil || ack != nil {
				if ack != nil {
					ack.Close()
				}
				t.Fatal("acceptance: native readiness accepted a missing or foreign exec proof")
			}
			if ack != nil {
				if err := ack.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if credentialAliasCount(t, file) != before {
				t.Fatal("acceptance: native readiness leaked a received exec proof")
			}
		})
	}
}
