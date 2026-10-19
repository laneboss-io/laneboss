//go:build linux

package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	nativepeer "laneboss.io/laneboss/internal/v2/peer/linux"
)

func init() {
	if len(os.Args) != 3 || os.Args[1] != "cli-ordinary-peer-fixture" {
		return
	}
	args := []string{"org", "validate", "--config", "ordinary-fixture"}
	// Exercise both the executable's early check and RunContext's early check.
	if handled, _ := RunBootstrapEntry(context.Background(), args); handled {
		os.Exit(91)
	}
	// Only this subprocess replaces the operation adapter. Native connection,
	// connector credentials, pidfd, lifetime and dispatch are all real. It
	// claims no org validation, human session or installed service authority.
	integrateCommands["org validate"] = integrateCommand{run: func(context.Context, Invocation) error {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Args[2], Net: "unix"})
		if err != nil {
			return err
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if _, err := connection.Write([]byte("ready")); err != nil {
			return err
		}
		for {
			var message [1]byte
			if _, err := io.ReadFull(connection, message[:]); err != nil {
				return err
			}
			if message[0] == 'x' {
				return nil
			}
			if _, err := connection.Write(message[:]); err != nil {
				return err
			}
		}
	}}
	os.Exit(RunContext(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard))
}

type noOrdinaryContainment struct{}

func (*noOrdinaryContainment) RegisterContainment(context.Context, api.ContainmentBinding) error {
	return api.NotImplemented("fixture", "ordinary peer has no containment authority")
}
func (*noOrdinaryContainment) ResolveContainment(context.Context, api.PeerFacts, api.InstalledBinding) (api.ContainmentBinding, error) {
	return api.ContainmentBinding{}, api.NotImplemented("fixture", "ordinary peer has no containment authority")
}
func (*noOrdinaryContainment) RevokeContainment(context.Context, api.ID) error {
	return api.NotImplemented("fixture", "ordinary peer has no containment authority")
}

func TestOrdinaryBootstrapPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("ordinary peer listener unavailable")
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("ordinary peer deadline unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "cli-ordinary-peer-fixture", path)
	cmd.Env = []string{}
	if err := cmd.Start(); err != nil {
		t.Fatal("ordinary CLI fixture did not start")
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	waited := false
	t.Cleanup(func() {
		if !waited {
			cancel()
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Error("ordinary CLI fixture was not collected")
			}
		}
	})
	type accepted struct {
		connection *net.UnixConn
		err        error
	}
	incoming := make(chan accepted, 1)
	go func() { connection, err := listener.AcceptUnix(); incoming <- accepted{connection, err} }()
	var connection *net.UnixConn
	select {
	case result := <-incoming:
		if result.err != nil {
			t.Fatal("acceptance: ordinary bootstrap entry changed or ended its native peer")
		}
		connection = result.connection
	case <-finished:
		waited = true
		t.Fatal("acceptance: ordinary bootstrap entry changed or ended its native peer")
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("ordinary socket deadline unavailable")
	}
	var ready [5]byte
	if _, err := io.ReadFull(connection, ready[:]); err != nil || string(ready[:]) != "ready" {
		t.Fatal("ordinary CLI connection did not become ready")
	}
	verifier, err := nativepeer.New(&noOrdinaryContainment{})
	if err != nil {
		t.Fatal("native socket verifier unavailable")
	}
	defer verifier.Close()
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "ordinary-fixture", Class: api.EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 61000, ServiceGID: 61000,
		Socket: path, ArtifactSHA256: api.Digest(strings.Repeat("a", 64)), ServiceVersion: "fixture", Backend: "linux-bwrap-landlock"}
	peer, err := verifier.Verify(context.Background(), connection, binding)
	if err != nil {
		t.Fatal("acceptance: ordinary bootstrap entry changed or ended its native peer")
	}
	defer peer.Close()
	first, err := peer.Facts(context.Background())
	if err != nil || first.HostPID != cmd.Process.Pid || first.HostUID != uint32(os.Getuid()) || first.HostGID != uint32(os.Getgid()) || first.ProcessGeneration == "" {
		t.Fatal("acceptance: ordinary bootstrap entry changed or ended its native peer")
	}
	for iteration := 0; iteration < 32; iteration++ {
		if _, err := connection.Write([]byte{'p'}); err != nil {
			t.Fatal("ordinary peer ping failed")
		}
		var reply [1]byte
		if _, err := io.ReadFull(connection, reply[:]); err != nil || reply[0] != 'p' {
			t.Fatal("ordinary peer reply failed")
		}
		facts, err := peer.Facts(context.Background())
		if err != nil || facts != first || peer.Alive(context.Background()) != nil {
			t.Fatal("acceptance: ordinary bootstrap entry changed or ended its native peer")
		}
	}
	if _, err := connection.Write([]byte{'x'}); err != nil {
		t.Fatal("ordinary peer exit handshake failed")
	}
	if err := <-finished; err != nil {
		t.Fatal("ordinary CLI did not exit successfully")
	}
	waited = true
	var typed *api.Error
	if err := peer.Alive(context.Background()); !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
		t.Fatal("acceptance: ordinary peer stayed authenticated after its actual exit")
	}
}
