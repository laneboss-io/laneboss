package service

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
)

var _ connectionScopeSource = (*identity.Service)(nil)

type freshOnlyAuth struct {
	api.Authenticator
	calls int
}

func (a *freshOnlyAuth) Authenticate(context.Context, api.ConnectionContext) (api.Scope, error) {
	a.calls++
	return api.Scope{}, serviceError(api.CodeConflict, "component fresh authentication was incorrectly called")
}

func TestBoundScopeRequiresPort(t *testing.T) {
	s := fixtureServer(t)
	auth := &freshOnlyAuth{}
	s.deps.Authenticator = auth
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// net.Pipe refuses deadline changes once the remote end has closed.
	if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := newConnection(a, s.deps.Binding, s.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	peer := &peerFixture{facts: api.PeerFacts{HostPID: 42, ProcessGeneration: "component-lifetime"}}
	if err := connection.BindPeer(peer); err != nil {
		t.Fatal(err)
	}
	_, err = s.authenticateConnection(context.Background(), connection)
	var refusal *api.Error
	if auth.calls != 0 || !errors.As(err, &refusal) || refusal.Code != api.CodePrerequisite {
		t.Fatal("bound connection attempted fresh authentication", err, auth.calls)
	}
	var one [1]byte
	if _, err := b.Read(one[:]); !errors.Is(err, io.EOF) {
		t.Fatal("missing current-scope capability left the transport open", err)
	}
}

func TestAuthClosePropagation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := newConnection(a, api.InstalledBinding{}, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	entry := &authenticationConnection{ConnectionContext: connection}
	if err := entry.Close(); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := b.Read(one[:]); !errors.Is(err, io.EOF) || !entry.closeRequested.Load() {
		t.Fatal("authentication close did not reach the transport", err)
	}
}
