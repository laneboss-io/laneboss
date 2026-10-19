//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type unusedEnrollmentPeer struct{ calls int }

func (p *unusedEnrollmentPeer) Facts(context.Context) (api.PeerFacts, error) {
	p.calls++
	return api.PeerFacts{}, errors.New("component peer must not precede the native UID gate")
}
func (p *unusedEnrollmentPeer) Alive(context.Context) error {
	p.calls++
	return errors.New("component peer must not precede the native UID gate")
}
func (p *unusedEnrollmentPeer) Close() error { p.calls++; return nil }

type unusedEnrollmentFrame struct{ calls int }

func (f *unusedEnrollmentFrame) Bytes() []byte { return nil }
func (f *unusedEnrollmentFrame) Verify(context.Context, api.ConnectionContext) error {
	f.calls++
	return errors.New("component frame must not precede the native UID gate")
}

func TestEnrollmentSharedVerifier(t *testing.T) {
	if os.Geteuid() == 0 {
		// The deciding input is a real nonroot socket peer. Preserve that input
		// when the surrounding root-canary package runs as administrator.
		executable, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		defer executable.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestEnrollmentSharedVerifier$", "-test.v")
		command.Env, command.ExtraFiles = []string{}, []*os.File{executable}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestEnrollmentSharedVerifier ")) {
			t.Fatalf("unprivileged verifier child did not run and pass: %v\n%s", err, output)
		}
		return
	}
	_, _, _, _, endpoint := initialEnrollmentFixture(t)
	endpoint.Socket = filepath.Join(privateTestDir(t), "admin.sock")
	if err := api.ValidateAdminEnrollmentEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	socket, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	peer, frame := &unusedEnrollmentPeer{}, &unusedEnrollmentFrame{}
	connection := &enrollmentConnection{socket: socket, peer: peer}
	err = connection.verify(context.Background(), endpoint, frame)
	if err == nil || api.AdminEnrollmentFailedField(err) != "peer_uid" || peer.calls != 0 || frame.calls != 0 {
		t.Fatal("enrollment lost shared administrator proof", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := connection.verify(ctx, endpoint, frame); !errors.Is(err, context.Canceled) || api.AdminEnrollmentFailedField(err) != "deadline" {
		t.Fatal("enrollment verifier lost its cancellation cause", err)
	}
}
