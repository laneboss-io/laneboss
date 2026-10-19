package messaging

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type boundPeer struct {
	facts  api.PeerFacts
	closed bool
}

func (p *boundPeer) Alive(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p.closed {
		return problem(api.CodeUnauthenticated, "fixture peer closed")
	}
	return nil
}
func (p *boundPeer) Facts(ctx context.Context) (api.PeerFacts, error) { return p.facts, p.Alive(ctx) }
func (p *boundPeer) Close() error                                     { p.closed = true; return nil }

type boundConnection struct {
	id        api.ID
	binding   api.InstalledBinding
	peer      api.VerifiedPeer
	authority *api.ReadAuthority
	closed    bool
}

func (c *boundConnection) ID() api.ID                    { return c.id }
func (c *boundConnection) Conn() net.Conn                { return nil } // No OS identity claim in this component fixture.
func (c *boundConnection) Binding() api.InstalledBinding { return c.binding }
func (c *boundConnection) Peer() api.VerifiedPeer        { return c.peer }
func (c *boundConnection) BindPeer(p api.VerifiedPeer) error {
	if c.closed || c.peer != nil || p == nil {
		return problem(api.CodeConflict, "fixture peer already bound or closed")
	}
	c.peer = p
	return nil
}
func (c *boundConnection) BindReadAuthority(a api.ReadAuthority) error {
	if c.closed || a.ConnectionID != c.id {
		return problem(api.CodeForbidden, "fixture session belongs to another connection")
	}
	c.authority = &a
	return nil
}
func (c *boundConnection) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	if c.closed || c.authority == nil {
		return api.ReadAuthority{}, problem(api.CodeForbidden, "fixture has no live read session")
	}
	if err := c.peer.Alive(ctx); err != nil {
		return api.ReadAuthority{}, err
	}
	return *c.authority, nil
}
func (c *boundConnection) Close() error { c.closed = true; return c.peer.Close() }

type boundFrame struct {
	raw        []byte
	connection api.ID
}

func (f boundFrame) Bytes() []byte { return append([]byte{}, f.raw...) }
func (f boundFrame) Verify(ctx context.Context, c api.ConnectionContext) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.ID() != f.connection || !json.Valid(f.raw) {
		return problem(api.CodeUnauthenticated, "fixture frame is not bound to this connection")
	}
	return c.Peer().Alive(ctx)
}

func (m *memoryStore) Proof(_ context.Context, scope api.Scope, id api.ID) (api.VerifiedHumanProof, error) {
	proof, ok := m.proofs[id]
	if !ok || proof.Config != scope.Config || proof.PrincipalID != scope.Actor.ID {
		return api.VerifiedHumanProof{}, problem(api.CodeNotFound, "fixture proof not found")
	}
	return proof, nil
}
func (m *memoryStore) Enrollment(_ context.Context, scope api.Scope) (api.HumanEnrollment, error) {
	row, ok := m.enrollments[scope.Actor.ID]
	if !ok || row.Config != scope.Config {
		return api.HumanEnrollment{}, problem(api.CodeNotFound, "fixture enrollment not found")
	}
	return row, nil
}

func (f *fixture) bindScope(t *testing.T, scope api.Scope) api.Scope {
	t.Helper()
	c := &boundConnection{id: randomID(t), binding: api.InstalledBinding{Config: scope.Config, ContractRevision: api.ContractRevision, EndpointGeneration: scope.EndpointGeneration}}
	peer := &boundPeer{facts: api.PeerFacts{HostUID: 24001, ProcessGeneration: string(randomID(t)), ContainmentID: randomID(t)}}
	if scope.Actor.Kind == "lane" {
		launch := f.store.launches[scope.LaunchID]
		launch.HostUID, launch.ContainmentID = peer.facts.HostUID, peer.facts.ContainmentID
		f.store.launches[launch.ID] = launch
		c.binding.Class, c.binding.LaunchID, c.binding.Target = api.EndpointLane, scope.LaunchID, &launch.Target
	} else {
		c.binding.Class = api.EndpointHuman
		credential := randomID(t)
		if scope.Request.Proof != nil {
			credential = f.store.proofs[scope.Request.Proof.ID].CredentialID
		}
		f.store.enrollments[scope.Actor.ID] = api.HumanEnrollment{Config: scope.Config, PrincipalID: scope.Actor.ID, Generation: 1, Credentials: []api.HumanCredential{{ID: credential, Generation: 1}}}
		if err := c.BindReadAuthority(api.ReadAuthority{ConnectionID: c.id, SessionID: randomID(t), CredentialID: credential, PrincipalID: scope.Actor.ID, Config: scope.Config, EndpointGeneration: scope.EndpointGeneration,
			ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano)), IdleExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.BindPeer(peer); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Connection, scope.Frame = c, boundFrame{raw: raw, connection: c.id}
	return scope
}

func TestContractDependencies(t *testing.T) {
	f := newFixture(t)
	service, err := New(Dependencies{Store: f.store, Clock: f.clock})
	if err != nil {
		t.Fatalf("contracted construction failed: %v", err)
	}
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Contracted dependency input\n"))}
	scope := f.bindScope(t, f.scope(t, "a3", "mail.send", request))
	mail, err := service.MailSend(context.Background(), scope, request)
	if err != nil || mail.Sender != scope.Actor {
		t.Fatalf("canonical store authority path failed: %v", err)
	}
	grants := f.store.grants[f.store.lanes[scope.Actor.LifeID].GrantSetID]
	grants.Revoked = true
	f.store.grants[grants.ID] = grants
	_, err = service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeForbidden)
	if len(f.store.events) != 1 {
		t.Fatal("revoked replay duplicated an event")
	}
}

func TestHumanStoreProof(t *testing.T) {
	f := newFixture(t)
	service, err := New(Dependencies{Store: f.store, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	request := api.MailSendRequest{RecipientLifeID: "a3", Content: f.blob(t, []byte("Canonical verified proof input\n"))}
	scope := f.scope(t, "reviewer", "mail.send", request)
	scope.Request.Proof = &api.ProofRef{ID: randomID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	f.confirmProof(t, scope)
	scope = f.bindScope(t, scope)
	first, err := service.MailSend(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.MailSend(context.Background(), scope, request)
	if err != nil || second.ID != first.ID || len(f.store.events) != 1 {
		t.Fatalf("canonical proof replay failed: %v", err)
	}
	enrollment := f.store.enrollments[scope.Actor.ID]
	enrollment.Credentials[0].Revoked = true
	f.store.enrollments[scope.Actor.ID] = enrollment
	_, err = service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeUnauthenticated)
}

func TestParentTurnPrivacy(t *testing.T) {
	for _, cell := range []string{"parent", "sibling"} {
		t.Run(cell, func(t *testing.T) {
			f := newFixture(t)
			mail := f.send(t, "a4", "peer4")
			observer, request := f.delivery(t, mail)
			requester := request.Lease.Record.Effect.Context.RequestedBy
			parentScope := f.scope(t, requester.LifeID, "lane.turn", api.TurnRequest{Target: request.Target, ExpectedGeneration: request.ExpectedGeneration, MailIDs: request.MailIDs})
			page, err := f.store.Mail(context.Background(), parentScope, api.ListRequest{LifeID: request.Target.LifeID, Limit: 200})
			if err != nil || len(page.Messages) != 0 {
				t.Fatal("parent fixture unexpectedly owns the child's private mail")
			}
			if cell == "sibling" {
				sibling := f.store.lanes["a4"]
				request.Lease.Record.Effect.Context.RequestedBy = api.Actor{Kind: "lane", ID: sibling.LifeID, LifeID: sibling.LifeID, Level: sibling.Level, Role: sibling.Role}
			}
			batch, err := f.service.BeginDelivery(context.Background(), observer, request)
			if cell == "sibling" {
				wantCode(t, err, api.CodeForbidden)
				return
			}
			if err != nil || len(batch.Mail) != 1 || batch.Mail[0].Sender != mail.Sender || batch.Intent.RequestedBy != requester || batch.Intent.Actor != observer.Actor || requester == mail.Sender {
				t.Fatalf("parent's leased turn lost privacy or causality: %v", err)
			}
		})
	}
}
