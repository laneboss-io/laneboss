//go:build linux

package service

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
)

func privateHostDirectory(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".lb-v2-service-host-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	return directory
}

func TestInstalledListenerProtection(t *testing.T) {
	directory := privateHostDirectory(t)
	binding := api.InstalledBinding{Config: "service-fixture", Socket: filepath.Join(directory, "rpc.sock"),
		ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid())}
	listener, err := listenInstalled(context.Background(), binding)
	if err != nil {
		t.Fatal("protected listener control failed", err)
	}
	defer listener.Close()
	before, err := os.Lstat(binding.Socket)
	if err != nil || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0660 {
		t.Fatal("installed listener mode was not protected", err)
	}
	server := fixtureServer(t)
	server.verified, server.bound, server.deps.Binding = true, true, binding
	if err := server.ServeInstalled(context.Background()); err == nil {
		t.Fatal("existing installed socket was replaced")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
	after, err := os.Lstat(binding.Socket)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("refused host start removed existing socket", err)
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: binding.Socket, Net: "unix"})
	if err != nil {
		t.Fatal("preserved listener stopped accepting", err)
	}
	defer client.Close()
	if err := listener.(*net.UnixListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.(*net.UnixListener).AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if err := accepted.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data := []byte(fixtureID(t))
	if err := wire.WriteFrame(client, data); err != nil {
		t.Fatal(err)
	}
	peer, err := wire.PeerCredentials(accepted)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := wire.ReadPinnedFrame(accepted, peer)
	if err != nil || !bytes.Equal(frame.Bytes(), data) {
		t.Fatal("listener failed native credential frame control", err)
	}
}

func TestCloseCollectsOwnedStore(t *testing.T) {
	directory := privateHostDirectory(t)
	deps := store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}}
	state, err := store.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	server := fixtureServer(t)
	server.deps.Store = state
	if err := server.Close(); err != nil {
		t.Fatal("host did not close owned state", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal("repeated host close changed result", err)
	}
	reopened, err := store.New(deps)
	if err != nil {
		t.Fatal("host retained the collected writer lock", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
