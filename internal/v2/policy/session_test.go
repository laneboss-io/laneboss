package policy

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// A unit port for an already verified human session, not native peer or
// WebAuthn evidence. Unused native transport methods remain unimplemented.
type testReadConnection struct {
	api.ConnectionContext
	id        api.ID
	binding   api.InstalledBinding
	authority api.ReadAuthority
	clock     *testClock
	closed    bool
	revoked   bool
}

func (c *testReadConnection) ID() api.ID                    { return c.id }
func (c *testReadConnection) Binding() api.InstalledBinding { return c.binding }
func (c *testReadConnection) Close() error                  { c.closed = true; return nil }
func (c *testReadConnection) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	if err := ctx.Err(); err != nil {
		return api.ReadAuthority{}, err
	}
	idle, idleErr := time.Parse(time.RFC3339Nano, string(c.authority.IdleExpiresAt))
	absolute, absoluteErr := time.Parse(time.RFC3339Nano, string(c.authority.ExpiresAt))
	if c.closed || c.revoked || c.authority.ConnectionID != c.id || c.authority.SessionID == "" ||
		idleErr != nil || absoluteErr != nil || !c.clock.Now().Before(idle) || !c.clock.Now().Before(absolute) {
		return api.ReadAuthority{}, forbiddenTarget()
	}
	return c.authority, nil
}

func newReadConnection(scope api.Scope, clock *testClock) (*testReadConnection, error) {
	id, err := newID("connection")
	if err != nil {
		return nil, err
	}
	session, err := newID("session")
	if err != nil {
		return nil, err
	}
	return &testReadConnection{id: id, clock: clock,
		binding: api.InstalledBinding{Config: scope.Config, Class: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration},
		authority: api.ReadAuthority{ConnectionID: id, SessionID: session, CredentialID: "fixture-key",
			PrincipalID: scope.Actor.ID, Config: scope.Config, EndpointGeneration: scope.EndpointGeneration,
			IdleExpiresAt: api.Timestamp(clock.Now().Add(5 * time.Minute).Format(time.RFC3339Nano)),
			ExpiresAt:     api.Timestamp(clock.Now().Add(30 * time.Minute).Format(time.RFC3339Nano))}}, nil
}
