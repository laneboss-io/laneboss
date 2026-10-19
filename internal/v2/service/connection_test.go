package service

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type peerFixture struct {
	mu     sync.Mutex
	facts  api.PeerFacts
	closed bool
}

func (p *peerFixture) Facts(context.Context) (api.PeerFacts, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.facts, nil
}
func (p *peerFixture) Alive(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return serviceError(api.CodeUnauthenticated, "closed fixture peer")
	}
	return nil
}
func (p *peerFixture) Close() error { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; return nil }

func TestConnectionLifetime(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	binding := api.InstalledBinding{Config: "service-fixture", Class: api.EndpointHuman, EndpointGeneration: 2}
	c, err := newConnection(a, binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	p := &peerFixture{facts: api.PeerFacts{HostUID: 123, HostGID: 124, HostPID: 125, ProcessGeneration: "one"}}
	if err := c.BindPeer(p); err != nil {
		t.Fatal(err)
	}
	if err := c.BindPeer(p); err == nil {
		t.Fatal("connection accepted replacement peer")
	}
	authority := api.ReadAuthority{SessionID: fixtureID(t), PrincipalID: fixtureID(t), CredentialID: fixtureID(t),
		ConnectionID: c.ID(), Generation: 1,
		Config: binding.Config, EndpointGeneration: 2,
		IdleExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)),
		ExpiresAt:     api.Timestamp(time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano))}
	if err := c.BindReadAuthority(authority); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadAuthority(context.Background())
	if err != nil || got.SessionID != authority.SessionID {
		t.Fatal("connection lost read authority", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadAuthority(context.Background()); err == nil {
		t.Fatal("closed connection kept read authority")
	}
	if !p.closed {
		t.Fatal("connection did not collect pinned peer")
	}
}
