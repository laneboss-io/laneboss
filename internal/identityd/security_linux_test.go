//go:build linux

package identityd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPeerLifetime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "python3", "../../e2e-rows/identityd_peer.py", path)
	in, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	child.Stderr = &diagnostic
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		in.Close()
		if !waited {
			if err := child.Wait(); err != nil {
				t.Errorf("peer collection failed: %v: %s", err, diagnostic.String())
			}
		}
	})
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := socketPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.lifetime.close()
	line, err := bufio.NewReader(out).ReadBytes('\n')
	var hello struct {
		PID int `json:"pid"`
	}
	if err != nil || json.Unmarshal(line, &hello) != nil || hello.PID != child.Process.Pid || peer.PID != child.Process.Pid {
		t.Fatal("the kernel and actual child PID disagree")
	}
	if err := peer.check(); err != nil {
		t.Fatal("the live connecting child was refused: ", err)
	}
	if _, err := in.Write([]byte{'q'}); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("the peer did not exit cleanly: %v: %s", err, diagnostic.String())
	}
	waited = true
	if err := peer.check(); err == nil {
		t.Fatal("an exited connecting process retained its lifetime proof")
	}
}

type heldVerifier struct {
	config  string
	peer    Peer
	entered chan struct{}
	release chan struct{}
}

func (v *heldVerifier) Verify(ctx context.Context, config string, peer Peer, ticket json.RawMessage) (Grant, error) {
	if config != v.config || peer != v.peer || !json.Valid(ticket) {
		return Grant{}, fmt.Errorf("the held verifier received an unexpected request")
	}
	close(v.entered)
	select {
	case <-v.release:
		return Grant{}, fmt.Errorf("the held verification was released without authorizing a ticket")
	case <-ctx.Done():
		return Grant{}, ctx.Err()
	}
}

func TestVerifyOutsideLock(t *testing.T) {
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := openStore(root, "held", 0600)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	defer func() {
		if err := journal.close(); err != nil {
			t.Error(err)
		}
	}()
	path := filepath.Join(base, "held.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.UnixConn, 1)
	acceptError := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			acceptError <- err
		} else {
			accepted <- conn
		}
	}()
	client, err := net.DialTimeout("unix", path, requestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var conn *net.UnixConn
	select {
	case conn = <-accepted:
	case err := <-acceptError:
		t.Fatal(err)
	case <-time.After(requestTimeout):
		t.Fatal("the real verifier test connection was not accepted")
	}
	defer conn.Close()
	peer, err := socketPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.lifetime.close()
	current, err := nativeProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	verifier := &heldVerifier{config: "held", peer: peer.Peer, entered: make(chan struct{}), release: make(chan struct{})}
	server := &Server{options: Options{Config: "held", Verifier: verifier}, process: current.Peer, store: journal}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registration := make(chan Response, 1)
	go func() {
		registration <- server.dispatch(ctx, peer, Request{Version: Version, Config: "held", Op: "register", Ticket: json.RawMessage(`{"intent":"canary"}`)})
	}()
	select {
	case <-verifier.entered:
	case <-time.After(requestTimeout):
		t.Fatal("the verifier was not reached with the real peer")
	}
	who := make(chan Response, 1)
	whoFinished := false
	go func() { who <- server.dispatch(ctx, peer, Request{Version: Version, Config: "held", Op: "whoami"}) }()
	select {
	case response := <-who:
		whoFinished = true
		if !response.OK || response.Peer == nil || *response.Peer != peer.Peer {
			t.Error("the independent whoami lost its kernel identity")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("verification blocked an independent whoami")
	}
	close(verifier.release)
	select {
	case response := <-registration:
		if response.OK || response.Record != nil || journal.seq != 0 {
			t.Error("the held refusal wrote a registration record")
		}
	case <-time.After(requestTimeout):
		t.Fatal("the released verification did not finish")
	}
	if !whoFinished {
		select {
		case <-who:
		case <-time.After(requestTimeout):
			t.Fatal("the independent whoami did not finish after verification was released")
		}
	}
}

func TestClosedReply(t *testing.T) {
	current, err := nativeProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{options: Options{Config: "closed", UIDConnectionLimit: 1}, process: current.Peer}
	refusal := Response{
		Version: Version,
		Code:    2,
		Service: server.Info(),
		Error:   fmt.Sprintf("refused: the service per-UID connection limit of %d was reached\nInstead: finish an existing request.", server.options.uidConnectionLimit()),
	}
	foreign := refusal
	foreign.Service.Peer.Start += "-changed"
	success := Response{Version: Version, OK: true, Service: server.Info()}
	cases := []struct {
		name    string
		reply   *Response
		code    int
		message string
	}{
		{"queued-refusal", &refusal, 2, refusal.Error},
		{"empty-close", nil, 2, "refused: the service closed the connection before reading the request\nInstead: retry within your deadline; the request was not processed."},
		{"foreign-peer", &foreign, 3, "integrity problem: the service response disagrees with its kernel peer identity"},
		{"unsent-success", &success, 3, "integrity problem: the service returned success for an incomplete request"},
	}
	data, err := json.Marshal(Request{Version: Version, Config: server.options.Config, Op: "whoami"})
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	for index, item := range cases {
		path := filepath.Join(t.TempDir(), "closed.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := listener.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
			t.Fatal(err)
		}
		connection, err := net.DialTimeout("unix", path, requestTimeout)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		client, ok := connection.(*net.UnixConn)
		if !ok {
			t.Fatal("the closed-reply test did not obtain a Unix socket")
		}
		accepted, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		defer accepted.Close()
		peer, err := socketPeer(client)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.lifetime.close()
		if !samePeer(current.Peer, peer.Peer) {
			t.Fatal("the closed-reply test lost its real kernel service peer")
		}
		if err := client.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
			t.Fatal(err)
		}
		// The real rejection path returns only after closing accepted. No
		// request is read, and there is no timing sleep or synthetic errno.
		if item.reply != nil {
			server.rejectConnection(accepted, *item.reply)
		} else if err := accepted.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte{'?'}); !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("%s: the service did not close before the real write: %v", item.name, err)
		}
		response, err := exchangeResponse(client, server.options.Config, peer, data)
		var problem *failure
		if index == 0 && (response.Code != refusal.Code || response.Error != refusal.Error || !errors.As(err, &problem) || problem.code != refusal.Code || problem.text != refusal.Error) {
			t.Fatalf("an early service refusal was lost: response=%+v error=%v", response, err)
		}
		if !errors.As(err, &problem) || problem.code != item.code || problem.text != item.message {
			t.Fatalf("%s: the closed reply returned %v; want code %d and %q", item.name, err, item.code, item.message)
		}
		if response.OK || response.Record != nil {
			t.Fatalf("%s: an incomplete request acquired a successful response", item.name)
		}
	}
}
