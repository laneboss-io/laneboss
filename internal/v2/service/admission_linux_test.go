//go:build linux

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type admissionCaller struct {
	scope api.Scope
	facts api.PeerFacts
}

// Trusted fixture registrations classify actual accepted sockets. Request
// bytes cannot select a containment, and unregistered sockets have no authority.
// This tests admission, not the helper's real cgroup/enrollment implementation.
type admissionAuth struct {
	api.Authenticator
	mu      sync.Mutex
	callers map[net.Conn]admissionCaller
}

func (a *admissionAuth) Authenticate(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	return a.registeredScope(ctx, connection)
}

func (a *admissionAuth) CurrentConnectionScope(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	if connection == nil || connection.Peer() == nil {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "admission recheck requires its existing peer")
	}
	return a.registeredScope(ctx, connection)
}

func (a *admissionAuth) registeredScope(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	a.mu.Lock()
	caller, found := a.callers[connection.Conn()]
	a.mu.Unlock()
	if !found {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "socket has no fixture containment registration")
	}
	if connection.Peer() == nil {
		if err := connection.BindPeer(&peerFixture{facts: caller.facts}); err != nil {
			return api.Scope{}, err
		}
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return api.Scope{}, err
	}
	caller.scope.Connection = connection
	return caller.scope, nil
}

func (a *admissionAuth) Authorize(_ context.Context, scope api.Scope, request api.Request) error {
	if scope.Connection == nil {
		return serviceError(api.CodeForbidden, "admission fixture requires its connection")
	}
	a.mu.Lock()
	caller, found := a.callers[scope.Connection.Conn()]
	a.mu.Unlock()
	if !found || caller.scope.Actor != scope.Actor || request.Method != "identity.self" || request.Config != caller.scope.Config {
		return serviceError(api.CodeForbidden, "request differs from its admission fixture registration")
	}
	return nil
}

func TestContainmentAdmissionIsolation(t *testing.T) {
	server := fixtureServer(t)
	auth := &admissionAuth{callers: make(map[net.Conn]admissionCaller)}
	server.deps.Authenticator = auth
	var dispatched atomic.Int64
	if err := server.Register("identity.self", func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		dispatched.Add(1)
		return identityHandler(ctx, scope, raw)
	}); err != nil {
		t.Fatal(err)
	}
	server.verified, server.bound = true, true
	path := filepath.Join(t.TempDir(), "admission.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.EnableCredentials(listener); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	var clients []*net.UnixConn
	var workers []<-chan struct{}
	t.Cleanup(func() {
		cancel()
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		for _, client := range clients {
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		}
		for _, done := range workers {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("containment admission worker was not collected")
			}
		}
		server.mu.RLock()
		defer server.mu.RUnlock()
		if len(server.admissions) != 0 || len(server.connections) != 0 {
			t.Error("containment admission retained slots or connections")
		}
	})
	makeCaller := func() admissionCaller {
		return admissionCaller{
			scope: api.Scope{Config: server.options.Config, Actor: api.Actor{Kind: "lane", ID: fixtureID(t), LifeID: fixtureID(t), Level: 3, Role: "executor"},
				LaunchID: fixtureID(t), EndpointGeneration: 1, PolicyGeneration: 1},
			facts: api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(),
				ProcessGeneration: "admission-fixture-lifetime", ContainmentID: fixtureID(t)},
		}
	}
	first, sibling := makeCaller(), makeCaller()
	connect := func(caller admissionCaller) (*net.UnixConn, <-chan struct{}) {
		client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
		accepted, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		peer, err := wire.PeerCredentials(accepted)
		if err != nil || peer.UID != first.facts.HostUID || peer.GID != first.facts.HostGID || peer.PID != first.facts.HostPID {
			accepted.Close()
			t.Fatal("same-UID native admission control differs", err)
		}
		if err := client.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			accepted.Close()
			t.Fatal(err)
		}
		auth.mu.Lock()
		auth.callers[accepted] = caller
		auth.mu.Unlock()
		done := make(chan struct{})
		workers = append(workers, done)
		go func() { defer close(done); server.serveConnection(ctx, accepted) }()
		return client, done
	}
	call := func(client *net.UnixConn, caller admissionCaller, failure string) {
		request := requestFor(t, "identity.self", api.Empty{})
		if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
			t.Fatal(failure, err)
		}
		data, err := wire.ReadFrame(client)
		if err != nil {
			t.Fatal(failure, err)
		}
		response, err := wire.DecodeResponse(data, request)
		if err != nil || response.Error != nil {
			t.Fatal(failure, err, response.Error)
		}
		var observed api.Scope
		if err := json.Unmarshal(response.Result, &observed); err != nil || observed.Actor != caller.scope.Actor || observed.LaunchID != caller.scope.LaunchID {
			t.Fatal("admission returned another lane's authority", err)
		}
	}
	for index := 0; index < 8; index++ {
		client, _ := connect(first)
		call(client, first, "first containment failed before its admission limit")
	}
	other, _ := connect(sibling)
	call(other, sibling, "same-UID sibling lane was starved")
	// A second RPC also proves the sibling retained its own live connection.
	call(other, sibling, "same-UID sibling connection did not remain live")
	uid := "uid:" + fmt.Sprint(first.facts.HostUID)
	server.mu.RLock()
	firstCount := server.admissions[uid+":"+string(first.facts.ContainmentID)]
	siblingCount := server.admissions[uid+":"+string(sibling.facts.ContainmentID)]
	publicCount := server.admissions[uid]
	server.mu.RUnlock()
	if firstCount != 8 || siblingCount != 1 || publicCount != 0 {
		t.Fatal("authenticated connections did not move to containment admission")
	}
	ninth, done := connect(first)
	request := requestFor(t, "identity.self", api.Empty{})
	if err := wire.WriteFrame(ninth, publicFrame(t, request)); err != nil {
		t.Fatal(err)
	}
	data, err := wire.ReadFrame(ninth)
	if err != nil {
		t.Fatal("over-limit containment lost its correlated admission refusal", err)
	}
	response, err := wire.DecodeResponse(data, request)
	if err != nil || response.Error == nil || response.Error.Code != api.CodeUnavailable ||
		response.Error.Owner != "lb-v2-service" || len(response.Result) != 0 ||
		response.Error.Message != "service connection refused at admission" {
		t.Fatal("over-limit containment lost its correlated admission refusal", err, response.Error)
	}
	waitHealthClosed(t, ninth, done)
	if dispatched.Load() != 10 {
		t.Fatal("over-limit containment reached dispatch")
	}
}
