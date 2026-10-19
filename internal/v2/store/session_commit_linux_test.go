//go:build linux

package store

import (
	"bytes"
	"context"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
)

type sessionCommitFrame struct {
	raw   []byte
	check func()
	err   error
}

func (f *sessionCommitFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }
func (f *sessionCommitFrame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	if f.check != nil {
		f.check()
	}
	if f.err != nil {
		return f.err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if connection == nil || connection.Peer() == nil {
		return fault(api.CodeUnauthenticated, "fixture session frame has no bound peer")
	}
	return connection.Peer().Alive(ctx)
}

type sessionCommitConnection struct {
	*scopeConnection
	reads int
	binds int
}

func (c *sessionCommitConnection) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	c.reads++
	return c.scopeConnection.ReadAuthority(ctx)
}
func (c *sessionCommitConnection) BindReadAuthority(authority api.ReadAuthority) error {
	c.binds++
	return c.scopeConnection.BindReadAuthority(authority)
}

type sessionCommitClock struct{ now time.Time }

func (c sessionCommitClock) Now() time.Time { return c.now }

type sessionPeerTripwire struct{ calls int }

func (p *sessionPeerTripwire) Verify(context.Context, net.Conn, api.InstalledBinding) (api.VerifiedPeer, error) {
	p.calls++
	return nil, api.NotImplemented("lb-v2-identity", "fixture native admission precedes finalization")
}

type sessionRegistryTripwire struct{ calls int }

func (r *sessionRegistryTripwire) RegisterContainment(context.Context, api.ContainmentBinding) error {
	r.calls++
	return api.NotImplemented("lb-v2-identity", "fixture human finalization has no containment")
}
func (r *sessionRegistryTripwire) ResolveContainment(context.Context, api.PeerFacts, api.InstalledBinding) (api.ContainmentBinding, error) {
	r.calls++
	return api.ContainmentBinding{}, api.NotImplemented("lb-v2-identity", "fixture human finalization has no containment")
}
func (r *sessionRegistryTripwire) RevokeContainment(context.Context, api.ID) error {
	r.calls++
	return api.NotImplemented("lb-v2-identity", "fixture human finalization has no containment")
}

// Enrollment and the previously verified assertion are explicit component
// inputs. The session, consumed proof, receipt and operation use real Transact.
func committedSessionFixture(t *testing.T) (*Service, api.Scope, api.StoredReadSession, api.Commit) {
	t.Helper()
	s, _ := testStore(t)
	ctx := context.Background()
	install := validatedEnrollmentInput(t, s)
	if _, err := commitEnrollmentFixture(ctx, s, install); err != nil {
		t.Fatal(err)
	}
	enrollment := install.Writes.Enrollments[0].Enrollment
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	connection := &sessionCommitConnection{scopeConnection: &scopeConnection{id: testID(t), conn: a, peer: &scopePeer{},
		binding: api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion,
			ContractRevision: api.ContractRevision, Config: s.deps.Config, Class: api.EndpointHuman,
			EndpointGeneration: 7, InstallationGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()),
			Socket: "/run/fixture/session.sock", ArtifactSHA256: testDigest([]byte("installed session fixture")),
			ServiceVersion: "fixture", Backend: "linux-bwrap-landlock"}}}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "human", ID: enrollment.PrincipalID},
		Connection: connection, EndpointGeneration: 7, PolicyGeneration: 1, Source: "cli"}
	request := testRequest(t, "human.session", api.HumanSessionRequest{})
	now := s.deps.Clock.Now().UTC()
	ref := api.ProofRef{ID: testID(t), RequestSHA256: request.RequestSHA256,
		ExpiresAt: api.Timestamp(now.Add(90 * time.Second).Format(time.RFC3339Nano))}
	request.Proof = &ref
	scope.Request = request
	scope.Frame = &sessionCommitFrame{raw: enrollmentJSON(t, request)}
	confirmation := api.HumanConfirmRequest{ChallengeID: testID(t), CredentialID: enrollment.Credentials[0].ID,
		ClientDataJSON: []byte(`{"type":"webauthn.get"}`), AuthenticatorData: []byte("verified authenticator fixture"), Signature: []byte("verified signature fixture")}
	assertion := enrollmentJSON(t, confirmation)
	object := api.ObjectWrite{ObjectKey: testID(t), Class: "artifact", Bytes: assertion, SHA256: testDigest(assertion), Origin: "identity",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "private", Generation: 1}}
	seed, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Rollback()
	confirmationScope := scope
	confirmationScope.Request.Method = "human.confirm"
	evidence, err := s.retain(ctx, seed, confirmationScope, object, testID(t), api.Timestamp(now.Format(time.RFC3339Nano)))
	if err != nil {
		t.Fatal(err)
	}
	proof := api.VerifiedHumanProof{Ref: ref, Config: scope.Config, PrincipalID: scope.Actor.ID, CredentialID: confirmation.CredentialID,
		NonceID: confirmation.ChallengeID, ConnectionID: testID(t), EndpointClass: api.EndpointHuman, EndpointGeneration: 7,
		AssertionEvidence: evidence, VerifiedAt: api.Timestamp(now.Add(-time.Second).Format(time.RFC3339Nano)),
		Target: api.HumanChallengeRequest{Method: request.Method, TargetID: scope.Actor.ID, RequestSHA256: request.RequestSHA256}}
	if err := put(ctx, seed, "proof", ref.ID, 1, proof); err != nil {
		t.Fatal(err)
	}
	if err := put(ctx, seed, "policy", api.ID(scope.Config), 1, api.EffectivePolicy{Generation: 1, SHA256: testDigest([]byte("session policy"))}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(); err != nil {
		t.Fatal(err)
	}
	stored := api.StoredReadSession{Session: api.HumanSession{ID: testID(t), Config: scope.Config,
		ExpiresAt: api.Timestamp(now.Add(20 * time.Minute).Format(time.RFC3339Nano)), IdleExpiresAt: api.Timestamp(now.Add(4 * time.Minute).Format(time.RFC3339Nano))},
		PrincipalID: scope.Actor.ID, CredentialID: proof.CredentialID, ConnectionID: connection.ID(), EndpointGeneration: 7, Generation: 1}
	payload := enrollmentJSON(t, stored.Session)
	input := api.Transaction{Scope: scope, RawRequest: scope.Frame.Bytes(), Reply: &api.RPCReply{Result: payload},
		Writes: api.StateWrites{ReadSessions: []api.StoredReadSession{stored}}, Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: ref, Target: proof.Target}}},
		Events: []api.Event{{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "human.session", Actor: scope.Actor,
			RequestedBy: scope.Actor, Origin: "service", StarterChain: []api.ID{}, Payload: payload}}}
	commit, err := s.Transact(ctx, input)
	if err != nil {
		t.Fatal("fixture session did not commit through the actual writer", err)
	}
	return s, scope, stored, commit
}

func TestSessionCommitReadback(t *testing.T) {
	s, scope, stored, commit := committedSessionFixture(t)
	ctx := context.Background()
	connection := scope.Connection.(*sessionCommitConnection)
	if _, err := s.ReadSession(ctx, scope, stored.Session.ID); err == nil {
		t.Fatal("public session read accepted an unbound connection")
	}
	connection.reads = 0
	scope.Frame.(*sessionCommitFrame).check = func() {
		if !s.mu.TryLock() {
			t.Fatal("private session read called transport under the store lock")
		}
		s.mu.Unlock()
	}
	snapshot, err := s.ReadSessionCommit(ctx, scope)
	if err != nil || snapshot.Session != stored || snapshot.Receipt.Operation.ID != commit.Operation.ID ||
		snapshot.Proof.ConsumedBy != commit.Operation.ID || !bytes.Equal(snapshot.Receipt.RawRequest, scope.Frame.Bytes()) {
		t.Fatal("private session read did not resolve its actual durable commit", err)
	}
	if connection.reads != 0 || connection.binds != 0 || connection.authority != nil {
		t.Fatal("private session read used or granted public read authority")
	}
	publicKey := append([]byte(nil), snapshot.Enrollment.Credentials[0].PublicKeyDER...)
	snapshot.Receipt.RawRequest[0] ^= 1
	snapshot.Receipt.Reply.Result[0] ^= 1
	snapshot.Enrollment.Credentials[0].PublicKeyDER[0] ^= 1
	again, err := s.ReadSessionCommit(ctx, scope)
	if err != nil || !bytes.Equal(again.Receipt.RawRequest, scope.Frame.Bytes()) || again.Session != stored ||
		!bytes.Equal(again.Receipt.Reply.Result, enrollmentJSON(t, stored.Session)) || !bytes.Equal(again.Enrollment.Credentials[0].PublicKeyDER, publicKey) {
		t.Fatal("private session snapshot returned shared mutable bytes", err)
	}
}

func TestSessionCommitIdentityFinalize(t *testing.T) {
	s, scope, stored, _ := committedSessionFixture(t)
	peers, registry := &sessionPeerTripwire{}, &sessionRegistryTripwire{}
	identities, err := identity.New(identity.Dependencies{Peers: peers, Registry: registry, Store: s, Sessions: s, Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	result, err := identities.FinalizeHumanSession(ctx, scope)
	connection := scope.Connection.(*sessionCommitConnection)
	if err != nil || result != stored.Session || connection.binds != 1 || peers.calls != 0 || registry.calls != 0 {
		t.Fatal("real identity and store did not finalize the committed connection", err)
	}
	read, err := s.ReadSession(ctx, scope, result.ID)
	if err != nil || read != stored {
		t.Fatal("real identity finalization left the public session unreadable", err)
	}
	if replay, err := identities.FinalizeHumanSession(ctx, scope); err != nil || replay != result || connection.binds != 1 {
		t.Fatal("real finalization replay rebound or lost the initial authority", err)
	}
}

func TestSessionCommitProofTime(t *testing.T) {
	s, scope, stored, _ := committedSessionFixture(t)
	s.deps.Clock = sessionCommitClock{s.deps.Clock.Now().Add(2 * time.Minute)}
	snapshot, err := s.ReadSessionCommit(context.Background(), scope)
	if err != nil || snapshot.Session != stored {
		t.Fatal("committed session required a renewed expired proof", err)
	}
}

func TestSessionCommitRefusals(t *testing.T) {
	for _, rule := range []string{"foreign_socket", "raw", "proof_used", "proof_target", "credential", "revoked", "revision", "column", "expired", "policy", "operation", "evidence", "frame", "presence", "proof_use"} {
		t.Run(rule, func(t *testing.T) {
			s, scope, session, commit := committedSessionFixture(t)
			ctx := context.Background()
			var proof api.VerifiedHumanProof
			if err := storedProjection(ctx, s.db, "proof", scope.Request.Proof.ID, &proof); err != nil {
				t.Fatal(err)
			}
			switch rule {
			case "foreign_socket":
				scope.Connection.(*sessionCommitConnection).id = testID(t)
			case "raw":
				frame := scope.Frame.(*sessionCommitFrame)
				frame.raw = append(frame.raw, ' ')
			case "proof_used":
				proof.ConsumedBy = testID(t)
			case "proof_target":
				proof.Target.TargetID = testID(t)
			case "credential":
				var enrollment api.HumanEnrollment
				if err := storedProjection(ctx, s.db, "enrollment", scope.Actor.ID, &enrollment); err != nil {
					t.Fatal(err)
				}
				enrollment.Credentials[0].Revoked = true
				fixtureProjection(t, s, "enrollment", scope.Actor.ID, enrollment.Generation, enrollment)
			case "revoked":
				session.Revoked = true
			case "revision":
				session.Generation++
			case "expired":
				s.deps.Clock = sessionCommitClock{s.deps.Clock.Now().Add(6 * time.Minute)}
			case "policy":
				fixtureProjection(t, s, "policy", api.ID(scope.Config), 2, api.EffectivePolicy{Generation: 2})
			case "operation":
				operation := commit.Operation
				operation.Status = "pending"
				if _, err := s.db.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", enrollmentJSON(t, operation), string(operation.ID)); err != nil {
					t.Fatal(err)
				}
			case "evidence":
				proof.AssertionEvidence.ID = testID(t)
			case "frame":
				scope.Frame.(*sessionCommitFrame).err = fault(api.CodeUnauthenticated, "fixture frame refused")
			case "presence":
				proof.SimulatedPresence = true
			case "proof_use":
				var used api.ProofUseReceipt
				if err := storedProjection(ctx, s.db, "proof_use", proof.Ref.ID, &used); err != nil {
					t.Fatal(err)
				}
				used.OperationID = testID(t)
				fixtureProjection(t, s, "proof_use", proof.Ref.ID, 1, used)
			}
			fixtureProjection(t, s, "proof", proof.Ref.ID, 1, proof)
			revision := session.Generation
			if rule == "column" {
				revision++
			}
			fixtureProjection(t, s, "read_session", session.Session.ID, revision, session)
			result, err := s.ReadSessionCommit(ctx, scope)
			if err == nil || !reflect.DeepEqual(result, identity.SessionCommit{}) {
				t.Fatal("private session read accepted " + rule)
			}
			connection := scope.Connection.(*sessionCommitConnection)
			if connection.reads != 0 || connection.binds != 0 || connection.authority != nil {
				t.Fatal("refused private session read reached public authority")
			}
		})
	}
}
