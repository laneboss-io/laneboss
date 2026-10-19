//go:build linux

package store

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These identity fixtures isolate the store's current-session checks. Native
// socket evidence is exercised separately; no installed acceptance uses them.
type scopePeer struct{}

func (*scopePeer) Facts(context.Context) (api.PeerFacts, error) {
	return api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: "fixture-process"}, nil
}
func (*scopePeer) Alive(context.Context) error { return nil }
func (*scopePeer) Close() error                { return nil }

type scopeConnection struct {
	id        api.ID
	conn      net.Conn
	binding   api.InstalledBinding
	peer      api.VerifiedPeer
	authority *api.ReadAuthority
}

func (c *scopeConnection) ID() api.ID                                  { return c.id }
func (c *scopeConnection) Conn() net.Conn                              { return c.conn }
func (c *scopeConnection) Binding() api.InstalledBinding               { return c.binding }
func (c *scopeConnection) Peer() api.VerifiedPeer                      { return c.peer }
func (c *scopeConnection) BindPeer(p api.VerifiedPeer) error           { c.peer = p; return nil }
func (c *scopeConnection) BindReadAuthority(a api.ReadAuthority) error { c.authority = &a; return nil }
func (c *scopeConnection) Close() error                                { return c.conn.Close() }
func (c *scopeConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	if c.authority == nil {
		return api.ReadAuthority{}, fault(api.CodeUnauthenticated, "fixture connection has no authority")
	}
	return *c.authority, nil
}

func fixtureProjection(t *testing.T, s *Service, kind string, id api.ID, generation api.Generation, value any) {
	t.Helper()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := put(context.Background(), tx, kind, id, generation, value); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			t.Error(rollbackErr)
		}
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestHumanReadRequiresCurrentSession(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	principal, credential, sessionID := testID(t), testID(t), testID(t)
	connection := &scopeConnection{id: testID(t), conn: a, peer: &scopePeer{},
		binding: api.InstalledBinding{Config: input.Scope.Config, Class: api.EndpointHuman, EndpointGeneration: 7}}
	end := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	idle := api.Timestamp(time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano))
	authority := api.ReadAuthority{SessionID: sessionID, PrincipalID: principal, CredentialID: credential, Config: input.Scope.Config,
		ConnectionID: connection.id, Generation: 1, EndpointGeneration: 7, ExpiresAt: end, IdleExpiresAt: idle}
	connection.authority = &authority
	session := api.StoredReadSession{Session: api.HumanSession{ID: sessionID, Config: input.Scope.Config, ExpiresAt: end, IdleExpiresAt: idle},
		PrincipalID: principal, CredentialID: credential, ConnectionID: connection.id, EndpointGeneration: 7, Generation: 1}
	enrollment := api.HumanEnrollment{Config: input.Scope.Config, PrincipalID: principal, Generation: 1,
		Credentials: []api.HumanCredential{{ID: credential, Generation: 1}}}
	fixtureProjection(t, s, "enrollment", principal, 1, enrollment)
	fixtureProjection(t, s, "read_session", sessionID, 1, session)
	query := api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 200}
	scope := api.Scope{Config: input.Scope.Config, Actor: api.Actor{Kind: "human", ID: principal}, Connection: connection, EndpointGeneration: 7,
		Request: testRequest(t, "records.query", query), Source: "cli"}
	control, err := s.Records(context.Background(), scope, query)
	if err != nil || len(control.Records) != 1 {
		t.Fatal("current human read-session control failed", err)
	}
	connection.authority = nil
	if page, err := s.Records(context.Background(), scope, query); err == nil || len(page.Records) != 0 {
		t.Fatal("human read without authority exposed state")
	} else {
		expectCode(t, err, api.CodeUnauthenticated)
	}
	connection.authority = &authority
	session.Revoked, session.Generation = true, 2
	fixtureProjection(t, s, "read_session", sessionID, 2, session)
	if page, err := s.Records(context.Background(), scope, query); err == nil || len(page.Records) != 0 {
		t.Fatal("revoked human read session exposed state")
	}
	session.Revoked, session.Generation = false, 3
	// A local connection timer cannot revive an expired durable session.
	session.Session.IdleExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
	fixtureProjection(t, s, "read_session", sessionID, 3, session)
	if _, err := s.ReadSession(context.Background(), scope, sessionID); err == nil {
		t.Fatal("read-session getter revived an uncommitted local idle refresh")
	}
	session.Generation = 4
	session.Session.IdleExpiresAt = idle
	authority.Generation = 4
	fixtureProjection(t, s, "read_session", sessionID, 4, session)
	enrollment.Generation, enrollment.Credentials[0].Revoked = 2, true
	fixtureProjection(t, s, "enrollment", principal, 2, enrollment)
	if page, err := s.Records(context.Background(), scope, query); err == nil || len(page.Records) != 0 {
		t.Fatal("revoked human credential exposed state")
	}
}
