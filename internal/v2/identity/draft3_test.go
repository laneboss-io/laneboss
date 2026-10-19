package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type fixturePeer struct {
	facts  api.PeerFacts
	err    error
	closes int
}

func (p *fixturePeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	if err := ctx.Err(); err != nil {
		return api.PeerFacts{}, err
	}
	if p.err != nil {
		return api.PeerFacts{}, p.err
	}
	if p.closes > 0 {
		return api.PeerFacts{}, refusal(api.CodeUnauthenticated, "fixture peer is closed")
	}
	return p.facts, nil
}
func (p *fixturePeer) Alive(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.closes > 0 {
		return refusal(api.CodeUnauthenticated, "fixture peer is closed")
	}
	return p.err
}
func (p *fixturePeer) Close() error {
	if p.closes == 0 {
		p.closes++
	}
	return nil
}

type fixtureConnection struct {
	raw              net.Conn
	binding          api.InstalledBinding
	peer             api.VerifiedPeer
	id               api.ID
	authority        api.ReadAuthority
	closes           int
	binds            int
	readBinds        int
	readBindAttempts int
	readBindApply    func(api.ReadAuthority) error
	bindErr          error
	refreshErr       error
	refreshes        int
	refreshApply     func(api.ReadAuthorityUpdate) error
}

func (c *fixtureConnection) ID() api.ID {
	if c.id != "" {
		return c.id
	}
	return "fixture-connection"
}
func (c *fixtureConnection) Binding() api.InstalledBinding { return c.binding }
func (c *fixtureConnection) Conn() net.Conn                { return c.raw }
func (c *fixtureConnection) Peer() api.VerifiedPeer        { return c.peer }
func (c *fixtureConnection) BindPeer(peer api.VerifiedPeer) error {
	if c.bindErr != nil {
		return c.bindErr
	}
	if c.closes > 0 || nilDependency(peer) {
		return refusal(api.CodeUnauthenticated, "fixture connection cannot bind peer")
	}
	if c.peer != nil {
		return refusal(api.CodeConflict, "fixture peer is already bound")
	}
	c.peer, c.binds = peer, c.binds+1
	return nil
}
func (c *fixtureConnection) BindReadAuthority(authority api.ReadAuthority) error {
	c.readBindAttempts++
	if c.closes > 0 || c.peer == nil || authority.ConnectionID == "" || authority.ConnectionID != c.ID() ||
		authority.Config != c.binding.Config || authority.EndpointGeneration != c.binding.EndpointGeneration {
		return refusal(api.CodeUnauthenticated, "fixture connection cannot bind read authority")
	}
	if c.authority.SessionID != "" {
		return refusal(api.CodeConflict, "fixture read authority is already bound")
	}
	if c.readBindApply != nil {
		return c.readBindApply(authority)
	}
	c.authority, c.readBinds = authority, c.readBinds+1
	return nil
}
func (c *fixtureConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	if c.closes > 0 || c.authority.SessionID == "" {
		return api.ReadAuthority{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	return c.authority, nil
}

func (c *fixtureConnection) RefreshReadAuthority(_ context.Context, update api.ReadAuthorityUpdate) error {
	if c.refreshErr != nil {
		return c.refreshErr
	}
	if c.closes > 0 {
		return refusal(api.CodeUnauthenticated, "fixture connection is closed")
	}
	if c.refreshApply != nil {
		return c.refreshApply(update)
	}
	if err := api.ValidateReadAuthorityUpdate(c.authority, update); err != nil {
		return err
	}
	c.authority = update.After
	c.refreshes++
	return nil
}
func (c *fixtureConnection) Close() error {
	if c.closes > 0 {
		return nil
	}
	c.closes++
	var err error
	if !nilDependency(c.peer) {
		err = c.peer.Close()
	}
	if c.raw != nil {
		err = errors.Join(err, c.raw.Close())
	}
	return err
}

func fixtureUnboundConnection(t *testing.T, binding api.InstalledBinding) *fixtureConnection {
	t.Helper()
	client, server := net.Pipe()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	connection := &fixtureConnection{raw: server, binding: binding, id: api.ID(hex.EncodeToString(nonce[:]))}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return connection
}

type fixtureFrame struct {
	raw      []byte
	err      error
	verifies int
}

type fixtureReadView struct {
	snapshot api.ReadSnapshot
	closed   bool
}

func (v *fixtureReadView) Snapshot() api.ReadSnapshot { return v.snapshot }
func (v *fixtureReadView) Close() error               { v.closed = true; return nil }

func (f *fixtureFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }
func (f *fixtureFrame) Verify(context.Context, api.ConnectionContext) error {
	f.verifies++
	return f.err
}

func fixtureHumanBinding() api.InstalledBinding {
	return api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "fixture", Class: api.EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 1234, ServiceGID: 1234,
		Socket: "/run/fixture/socket", ArtifactSHA256: api.Digest(strings.Repeat("a", 64)),
		ServiceVersion: "fixture-version", Backend: "linux-bwrap-landlock"}
}

func fixtureLaunchBinding(t *testing.T, record api.LaunchRecord) api.LaunchBindingRequest {
	t.Helper()
	return plannedFixtureBinding(t, record, fixtureLaunchPlan(t, record))
}

func fixtureHumanScope(t *testing.T, s *Service, store *fixtureStore) api.Scope {
	t.Helper()
	store.enrollment = &api.HumanEnrollment{Config: "fixture", PrincipalID: "human", Origin: "https://fixture.example",
		RPID: "fixture.example", Generation: 1, Credentials: []api.HumanCredential{{ID: "credential", Generation: 1}}}
	connection := fixtureUnboundConnection(t, fixtureHumanBinding())
	s.deps.Peers = &fixturePeers{peer: &fixturePeer{
		facts: api.PeerFacts{HostUID: 1234, HostGID: 1234, HostPID: 42, ProcessGeneration: "boot:1"}}}
	scope, err := s.Authenticate(context.Background(), connection)
	if err != nil {
		t.Fatalf("fixture setup: human context failed: %v", err)
	}
	return scope
}

func fixtureRequest(t *testing.T, scope api.Scope, method api.Method, body any) api.Scope {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config,
		Method: method, Params: raw, RequestID: api.ID(strings.Repeat("r", 32)), IdempotencyKey: api.ID(strings.Repeat("k", 32))}
	digest, err := api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.RequestSHA256 = digest
	frame, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request, scope.Frame, scope.Source = request, &fixtureFrame{raw: frame}, "cli"
	return scope
}

func fixtureOperationProof(t *testing.T, s *Service, store *fixtureStore, scope api.Scope) api.Scope {
	t.Helper()
	target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: "root",
		RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: 1}
	proof := api.ProofRef{ID: "proof", RequestSHA256: target.RequestSHA256, ExpiresAt: timestamp(s.deps.Clock.Now().Add(time.Minute))}
	store.proof = &api.VerifiedHumanProof{EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration,
		AssertionEvidence: api.BlobRef{ID: "assertion", SHA256: api.Digest(strings.Repeat("c", 64)), Bytes: 1, Class: "artifact"},
		Ref:               proof, Config: scope.Config, PrincipalID: scope.Actor.ID, CredentialID: "credential", NonceID: "nonce",
		Target: target, ConnectionID: "original-confirmation", VerifiedAt: timestamp(s.deps.Clock.Now())}
	scope.Request.Proof = &proof
	frame, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = &fixtureFrame{raw: frame}
	return scope
}

func TestCommittedLaunchFixture(t *testing.T) {
	for _, rule := range []string{"valid", "prepared", "gate", "spec", "sequence", "digest"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			request := fixtureLaunchBinding(t, store.record)
			retainFixturePlan(t, store, request)
			stored := cloneLaunchValue(t, request)
			store.binding = &stored
			want := api.ErrorCode("")
			switch rule {
			case "prepared":
				request.Prepared.ID, want = "different-gate", api.CodeConflict
			case "gate":
				request.Prepared.GateID, want = "", api.CodeInvalid
			case "spec":
				request.Prepared.SpecSHA256, want = api.Digest(strings.Repeat("c", 64)), api.CodeConflict
			case "sequence":
				request.Identity.CommittedSeq++
				want = api.CodeConflict
			case "digest":
				request.Identity.RecordSHA256, want = api.Digest(strings.Repeat("d", 64)), api.CodeConflict
			}
			permit, err := s.BindLaunch(context.Background(), request)
			if want != "" {
				errorCode(t, err, want)
				if permit != (api.LaunchPermit{}) {
					t.Fatal("fixture check: refused binding returned a permit")
				}
				return
			}
			if err != nil || permit.LaunchID != stored.Record.ID || permit.PreparedID != stored.Prepared.ID ||
				permit.PreparedID == permit.LaunchID || permit.CommittedSeq != stored.Identity.CommittedSeq ||
				permit.RecordSHA256 != stored.Identity.RecordSHA256 {
				t.Fatalf("fixture check: committed gate receipt was not preserved: %v", err)
			}
		})
	}
}

func TestBorrowedConnectionFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	scope := fixtureHumanScope(t, s, store)
	connection := scope.Connection.(*fixtureConnection)
	peer := connection.peer.(*fixturePeer)
	if scope.Actor.ID != store.enrollment.PrincipalID || scope.Actor.Kind != "human" ||
		connection.closes != 0 || peer.closes != 0 || connection.binds != 1 {
		t.Fatal("fixture check: authentication lost or closed the borrowed connection")
	}
	before := scope
	peer.facts.ProcessGeneration = ""
	err := s.verifyScope(context.Background(), scope)
	errorCode(t, err, api.CodeUnauthenticated)
	if before.Connection != connection || connection.closes != 0 || peer.closes != 0 {
		t.Fatal("fixture check: refused authentication closed the transport lifetime")
	}
}

func TestStoredProofFixture(t *testing.T) {
	for _, rule := range []string{"valid", "consumed", "principal", "config", "endpoint", "target", "credential", "future"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureHumanScope(t, s, store)
			scope = fixtureRequest(t, scope, "human.session", api.HumanSessionRequest{})
			scope = fixtureOperationProof(t, s, store, scope)
			ref, target := *scope.Request.Proof, store.proof.Target
			switch rule {
			case "consumed":
				store.proof.ConsumedBy = "other-operation"
			case "principal":
				store.proof.PrincipalID = "other-human"
			case "config":
				store.proof.Config = "other"
			case "endpoint":
				store.proof.EndpointGeneration++
			case "target":
				store.proof.Target.BaseGeneration++
			case "credential":
				store.enrollment.Credentials[0].Revoked = true
			case "future":
				store.proof.VerifiedAt = timestamp(s.deps.Clock.Now().Add(time.Second))
			}
			before := *store.proof
			verified, err := s.CheckProof(context.Background(), scope, ref, target)
			if rule != "valid" {
				errorCode(t, err, api.CodeUnauthenticated)
				return
			}
			if err != nil || verified != before || *store.proof != before || store.transaction != nil {
				t.Fatalf("fixture check: proof read changed state or lost verification facts: %v", err)
			}
			again, err := s.CheckProof(context.Background(), scope, ref, target)
			if err != nil || !reflect.DeepEqual(again, verified) {
				t.Fatal("fixture check: nonconsuming proof read was not repeatable")
			}
		})
	}
}

func TestScopedFrameFixture(t *testing.T) {
	for _, rule := range []string{"valid", "writer", "changed-frame", "missing"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureRequest(t, fixtureHumanScope(t, s, store), "health", api.HealthRequest{ClientVersion: "fixture-version", ArtifactSHA256: store.record.GrantsSHA256})
			want := api.ErrorCode("")
			switch rule {
			case "writer":
				scope.Frame.(*fixtureFrame).err, want = &api.Error{Code: api.CodeUnauthenticated}, api.CodeUnauthenticated
			case "changed-frame":
				other := scope.Request
				other.RequestID = "other-frame-request"
				raw, err := json.Marshal(other)
				if err != nil {
					t.Fatal(err)
				}
				scope.Frame.(*fixtureFrame).raw, want = raw, api.CodeIntegrity
			case "missing":
				scope.Frame, want = nil, api.CodeNotImplemented
			}
			err := s.Authorize(context.Background(), scope, scope.Request)
			if want != "" {
				errorCode(t, err, want)
				return
			}
			if err != nil || scope.Frame.(*fixtureFrame).verifies == 0 {
				t.Fatalf("fixture check: valid frame was not verified: %v", err)
			}
		})
	}
}

func TestHumanWritesFixture(t *testing.T) {
	// This observes the real module's transaction handoff. The callback below
	// is a receipt fixture, not an implementation of durable one-use state.
	for _, operation := range []string{"challenge", "confirm", "ticket", "session"} {
		t.Run(operation, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureHumanScope(t, s, store)
			f := newAssertion(t, nil)
			store.enrollment.Origin, store.enrollment.RPID = f.challenge.Origin, f.challenge.RPID
			store.enrollment.Credentials = []api.HumanCredential{{ID: "credential", RawCredentialID: []byte("browser-credential"),
				Algorithm: "ES256", PublicKeyDER: f.public, Counter: 10, Generation: 3}}
			store.challenge = &api.StoredChallenge{EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration,
				Challenge: f.challenge, PrincipalID: scope.Actor.ID, ConnectionID: "prior-connection", Generation: 2}
			var body any
			method := api.Method("")
			switch operation {
			case "challenge":
				method = "human.challenge"
				body = api.HumanChallengeRequest{Method: "ticket.issue", TargetID: "root", RequestSHA256: store.record.GrantsSHA256, BaseGeneration: 1}
			case "confirm":
				method, body = "human.confirm", f.request
			case "ticket":
				method = "ticket.issue"
				body = api.TicketIssueRequest{Level: 6, Role: "supervisor", GrantSetID: "root-grants", ExpiresAt: timestamp(s.deps.Clock.Now().Add(time.Minute))}
				store.grants = &api.GrantSet{ID: "root-grants", Generation: 1, ExpiresAt: timestamp(s.deps.Clock.Now().Add(time.Hour))}
			case "session":
				method, body = "human.session", api.HumanSessionRequest{}
			}
			scope = fixtureRequest(t, scope, method, body)
			if operation == "ticket" || operation == "session" {
				scope = fixtureOperationProof(t, s, store, scope)
			}
			calls := 0
			store.transact = func(transaction api.Transaction) (api.Commit, error) {
				calls++
				if transaction.Scope.Request.Method != method || !reflect.DeepEqual(transaction.RawRequest, scope.Frame.Bytes()) ||
					transaction.Reply == nil || len(transaction.Events) != 1 || transaction.Internal != nil {
					t.Fatal("fixture check: human transaction lost its request, reply or causal event")
				}
				if err := api.ValidateTransactionShape(transaction); err != nil {
					t.Fatalf("fixture check: invalid human transaction: %v", err)
				}
				writes := transaction.Writes
				switch operation {
				case "challenge":
					if len(writes.Challenges) != 1 || writes.Challenges[0].Consumed || len(writes.Challenges[0].Challenge.Challenge) != 32 ||
						writes.Challenges[0].PrincipalID != scope.Actor.ID || writes.Challenges[0].ConnectionID != scope.Connection.ID() {
						t.Fatal("fixture check: challenge handoff lost its nonce or principal binding")
					}
				case "confirm":
					if len(writes.Challenges) != 1 || !writes.Challenges[0].Consumed || len(writes.Proofs) != 1 || len(writes.Counters) != 1 || len(writes.Objects) != 1 {
						t.Fatal("fixture check: assertion was not handed off with challenge, counter, proof and evidence")
					}
					proof, counter, object := writes.Proofs[0], writes.Counters[0], writes.Objects[0]
					if counter.Before != 10 || counter.After != 11 || counter.ExpectedGeneration != 3 || counter.CredentialID != f.request.CredentialID ||
						proof.NonceID != f.challenge.ID || proof.PrincipalID != scope.Actor.ID || proof.Ref.RequestSHA256 != f.challenge.RequestSHA256 ||
						proof.AssertionEvidence.ID != object.ObjectKey || proof.AssertionEvidence.SHA256 != object.SHA256 ||
						proof.AssertionEvidence.Bytes != int64(len(object.Bytes)) || object.ACL.Audience != "private" || object.ACL.Owner != scope.Actor {
						t.Fatal("fixture check: assertion handoff lost verified facts or private evidence")
					}
					sum := sha256.Sum256(object.Bytes)
					if api.Digest(hex.EncodeToString(sum[:])) != object.SHA256 {
						t.Fatal("fixture check: assertion evidence digest differs from its bytes")
					}
				case "ticket", "session":
					if len(transaction.Guards) != 1 || transaction.Guards[0].Proof == nil ||
						transaction.Guards[0].Proof.Proof != *scope.Request.Proof || transaction.Guards[0].Proof.Target != store.proof.Target {
						t.Fatal("fixture check: human mutation omitted its atomic proof-use guard")
					}
					if operation == "ticket" {
						request := body.(api.TicketIssueRequest)
						if len(writes.Tickets) != 1 || writes.Tickets[0].Level != request.Level || writes.Tickets[0].Role != request.Role ||
							writes.Tickets[0].GrantSetID != request.GrantSetID || writes.Tickets[0].Redeemed ||
							writes.Tickets[0].PrincipalID != scope.Actor.ID || writes.Tickets[0].Config != scope.Config ||
							writes.Tickets[0].EndpointGeneration != scope.EndpointGeneration {
							t.Fatal("fixture check: ticket scope was not persisted exactly")
						}
					} else {
						if len(writes.ReadSessions) != 1 {
							t.Fatal("fixture check: read session was not persisted")
						}
						session := writes.ReadSessions[0]
						store.readSession = &session
						if session.ConnectionID != scope.Connection.ID() || session.CredentialID != store.proof.CredentialID ||
							session.Session.ExpiresAt != timestamp(s.deps.Clock.Now().Add(30*time.Minute)) ||
							session.Session.IdleExpiresAt != timestamp(s.deps.Clock.Now().Add(5*time.Minute)) {
							t.Fatal("fixture check: read session lost its exact connection or lifetime")
						}
					}
				}
				return api.Commit{Reply: transaction.Reply, Operation: api.Operation{ID: "fixture-operation", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
			}
			var err error
			var returned any
			switch operation {
			case "challenge":
				var result api.HumanChallenge
				result, err = s.Challenge(context.Background(), scope, body.(api.HumanChallengeRequest))
				returned = result
				if err == nil && (result.ID == "" || result.RequestSHA256 != body.(api.HumanChallengeRequest).RequestSHA256) {
					t.Fatal("fixture check: challenge reply lost its intent")
				}
			case "confirm":
				var result api.ProofRef
				result, err = s.Confirm(context.Background(), scope, f.request)
				returned = result
				if err == nil && (result.ID == "" || result.RequestSHA256 != f.challenge.RequestSHA256) {
					t.Fatal("fixture check: confirmation reply lost its proof")
				}
			case "ticket":
				var result api.Ticket
				result, err = s.TicketIssue(context.Background(), scope, body.(api.TicketIssueRequest))
				returned = result
			case "session":
				var result api.HumanSession
				result, err = s.HumanSession(context.Background(), scope, api.HumanSessionRequest{})
				returned = result
			}
			if err != nil || calls != 1 {
				t.Fatalf("fixture check: human transaction did not complete exactly one handoff: %v", err)
			}
			if operation == "session" {
				connection := scope.Connection.(*fixtureConnection)
				if connection.readBinds != 1 || connection.authority.SessionID != returned.(api.HumanSession).ID {
					t.Fatal("fixture check: committed session did not bind read authority on its connection")
				}
			}
			encoded, err := json.Marshal(returned)
			if err != nil || !bytes.Equal(encoded, store.transaction.Reply.Result) {
				t.Fatal("fixture check: human reply differs from its committed receipt")
			}
		})
	}
}

func TestReadSessionFixture(t *testing.T) { readSessionFixture(t, false) }

func TestReadSessionPreflightFixture(t *testing.T) { readSessionFixture(t, true) }

func readSessionFixture(t *testing.T, preflight bool) {
	for _, rule := range []string{"valid", "snapshot-current", "connection", "authority-connection", "snapshot", "idle", "absolute", "revoked", "credential", "principal", "endpoint"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureHumanScope(t, s, store)
			scope = fixtureRequest(t, scope, "dashboard.tree", api.DashboardQuery{Limit: 1})
			session := api.HumanSession{ID: "session", Config: scope.Config, ExpiresAt: timestamp(s.deps.Clock.Now().Add(30 * time.Minute)), IdleExpiresAt: timestamp(s.deps.Clock.Now().Add(5 * time.Minute))}
			store.readSession = &api.StoredReadSession{Session: session, PrincipalID: scope.Actor.ID, CredentialID: "credential",
				ConnectionID: scope.Connection.ID(), EndpointGeneration: scope.EndpointGeneration, Generation: 1}
			connection := scope.Connection.(*fixtureConnection)
			connection.authority = api.ReadAuthority{Generation: 1, ConnectionID: scope.Connection.ID(), SessionID: session.ID, PrincipalID: scope.Actor.ID, CredentialID: "credential",
				Config: scope.Config, EndpointGeneration: scope.EndpointGeneration, ExpiresAt: session.ExpiresAt, IdleExpiresAt: session.IdleExpiresAt}
			switch rule {
			case "snapshot-current", "snapshot":
				snapshot := connection.authority
				if rule == "snapshot" {
					snapshot.SessionID = "stale-session"
				}
				scope.ReadAuthority = &snapshot
			case "authority-connection":
				connection.authority.ConnectionID = "another-connection"
			case "connection":
				store.readSession.ConnectionID = "other-connection"
			case "idle":
				store.readSession.Session.IdleExpiresAt = timestamp(s.deps.Clock.Now())
				connection.authority.IdleExpiresAt = store.readSession.Session.IdleExpiresAt
			case "absolute":
				store.readSession.Session.ExpiresAt = timestamp(s.deps.Clock.Now())
				connection.authority.ExpiresAt = store.readSession.Session.ExpiresAt
			case "revoked":
				store.readSession.Revoked = true
			case "credential":
				store.enrollment.Credentials[0].Revoked = true
			case "principal":
				store.readSession.PrincipalID = "another-human"
				connection.authority.PrincipalID = store.readSession.PrincipalID
			case "endpoint":
				store.readSession.EndpointGeneration++
				connection.authority.EndpointGeneration = store.readSession.EndpointGeneration
			}
			var err error
			if preflight {
				err = s.checkReadSession(context.Background(), scope)
			} else {
				err = s.Authorize(context.Background(), scope, scope.Request)
			}
			if rule != "valid" && rule != "snapshot-current" {
				errorCode(t, err, api.CodeUnauthenticated)
				return
			}
			if err != nil {
				t.Fatalf("fixture check: current connection-bound session was refused: %v", err)
			}
		})
	}
}

func TestLaneConnectionFixture(t *testing.T) {
	for _, rule := range []string{"descendant", "uid", "containment", "lease", "endpoint", "grants", "policy"} {
		t.Run(rule, func(t *testing.T) {
			s, store, expected := serviceFixture(t)
			binding := fixtureHumanBinding()
			binding.Class, binding.LaunchID = api.EndpointLane, store.record.ID
			target := store.record.Target
			binding.Target = &target
			connection := fixtureUnboundConnection(t, binding)
			peer := &fixturePeer{facts: api.PeerFacts{
				HostPID: 42, HostUID: store.record.HostUID, HostGID: 1234,
				ContainmentID: store.record.ContainmentID, ProcessGeneration: "boot:descendant"}}
			s.deps.Peers = &fixturePeers{peer: peer}
			registry := s.deps.Registry.(*fixtureContainmentRegistry)
			registry.binding = api.ContainmentBinding{Config: store.record.Config, Target: target, Backend: binding.Backend,
				BootID: "boot", Generation: 1, Lease: api.HelperLease{ID: store.record.UIDLeaseID, UID: store.record.HostUID,
					GID: 1234, ContainmentID: store.record.ContainmentID, EndpointGeneration: store.record.EndpointGeneration}}
			want := api.CodeUnauthenticated
			switch rule {
			case "uid":
				peer.facts.HostUID++
			case "containment":
				peer.facts.ContainmentID = "another-containment"
			case "lease":
				registry.binding.Lease.ID, want = "other-lease", api.CodeContainmentUnknown
			case "endpoint":
				connection.binding.EndpointGeneration++
			case "grants":
				grants, err := store.Grants(context.Background(), store.record.GrantSetID)
				if err != nil {
					t.Fatal(err)
				}
				grants.Revoked, store.grants, want = true, &grants, api.CodeForbidden
			case "policy":
				store.policy = &api.EffectivePolicy{}
			}
			scope, err := s.Authenticate(context.Background(), connection)
			if rule != "descendant" {
				errorCode(t, err, want)
				return
			}
			if err != nil || scope.Actor != expected.Actor || scope.LaunchID != expected.LaunchID ||
				scope.Connection != connection || peer.facts.ProcessGeneration == store.record.ProcessGeneration {
				t.Fatalf("fixture check: authentic descendant was not bound to its own lifetime: %v", err)
			}
		})
	}
}

func TestHumanReceiptFixture(t *testing.T) {
	for _, rule := range []string{"retained", "error", "missing", "mixed", "sequence", "pending"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureRequest(t, fixtureHumanScope(t, s, store), "human.session", api.HumanSessionRequest{})
			scope = fixtureOperationProof(t, s, store, scope)
			proposed := api.HumanSession{ID: "new-proposal", Config: scope.Config,
				ExpiresAt: timestamp(s.deps.Clock.Now().Add(30 * time.Minute)), IdleExpiresAt: timestamp(s.deps.Clock.Now().Add(5 * time.Minute))}
			durable := proposed
			durable.ID = "retained-original"
			raw, err := json.Marshal(durable)
			if err != nil {
				t.Fatal(err)
			}
			store.commit = &api.Commit{Reply: &api.RPCReply{Result: raw}, Operation: api.Operation{ID: "original-operation", Status: "succeeded"},
				FirstSeq: 4, LastSeq: 4, Replayed: true}
			want := api.CodeIntegrity
			sentinel := &api.Error{Code: api.CodeConflict, Message: "fixture committed refusal"}
			switch rule {
			case "error":
				store.commit.Reply, store.commit.Operation.Status, want = &api.RPCReply{Error: sentinel}, "failed", api.CodeConflict
			case "missing":
				store.commit.Reply = nil
			case "mixed":
				store.commit.Reply.Error = sentinel
			case "sequence":
				store.commit.FirstSeq = 0
			case "pending":
				store.commit.Operation.Status = "pending"
			}
			var result api.HumanSession
			guard := api.TransactionGuard{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: store.proof.Target}}
			err = s.commitHuman(context.Background(), scope, "human.session", proposed, api.StateWrites{}, []api.TransactionGuard{guard}, &result)
			if rule != "retained" {
				errorCode(t, err, want)
				return
			}
			if err != nil || result != durable || result.ID == proposed.ID || store.transaction == nil {
				t.Fatalf("fixture check: original durable reply was replaced by a new proposal: %v", err)
			}
		})
	}
}
