//go:build darwin

package identityd

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// This test is intentionally Darwin-only. It exercises LOCAL_PEERCRED,
// LOCAL_PEERPID and the sysctl start time through a real Unix listener and the
// same handler as production. It makes no cross-account isolation claim.
func TestDarwinPeerCredentials(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "lb-svc-core-darwin-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(base, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	// Retain the private journal as evidence; the service collects its socket.
	t.Logf("retained fixture: %s", base)
	for _, name := range []string{"state", "runtime"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	server, err := Open(Options{Config: "peer", StateRoot: filepath.Join(base, "state"), RuntimeRoot: filepath.Join(base, "runtime")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-ended:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the Darwin listener missed its collection deadline")
		}
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		if _, err := os.Lstat(server.Socket()); !os.IsNotExist(err) {
			t.Error("the Darwin service did not collect its socket")
		}
	})
	t.Setenv("LANEBOSS_ROLE", "invented")
	t.Setenv("LANEBOSS_SESSION", "2")
	t.Setenv("LANEBOSS_PROCESSES", "portable")
	current, err := nativeProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if current.UID != uint32(os.Geteuid()) || current.GID != uint32(os.Getegid()) || current.Parent != os.Getppid() || current.Start == "" {
		t.Fatalf("sysctl disagrees with the actual test process: %+v", current)
	}
	for _, claim := range []json.RawMessage{nil, json.RawMessage([]byte(`{"pid":` + strconv.Itoa(os.Getppid()) + `,"uid":0,"start":"invented","actor":"supervisor:invented"}`))} {
		conn, err := net.DialTimeout("unix", server.Socket(), requestTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		request := Request{Version: Version, Config: "peer", Op: "whoami", Claim: claim}
		if err := json.NewEncoder(conn).Encode(request); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		line, err := bufio.NewReaderSize(conn, MaxResponseBytes+1).ReadSlice('\n')
		closeError := conn.Close()
		if err != nil || closeError != nil || len(line) > MaxResponseBytes {
			t.Fatalf("Darwin peer response failed: %v, %v", err, closeError)
		}
		var response Response
		if err := json.Unmarshal(line, &response); err != nil {
			t.Fatal(err)
		}
		if !response.OK || response.Peer == nil {
			t.Fatalf("the real Darwin peer was refused: %s", response.Error)
		}
		if *response.Peer != current.Peer {
			t.Fatalf("caller-sent pid replaced kernel peer identity: got %+v, want %+v", response.Peer, current.Peer)
		}
		if response.Identified || response.Principal != nil {
			t.Fatal("a caller-supplied Darwin role label acquired authority")
		}
	}
}
