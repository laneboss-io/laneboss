package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type fixtureClock struct{ now time.Time }

func (c fixtureClock) Now() time.Time { return c.now }

type fixtureStore struct {
	api.StateStore
	record             api.LaunchRecord
	lane               api.Lane
	err                error
	binding            *api.LaunchBindingRequest
	proof              *api.VerifiedHumanProof
	enrollment         *api.HumanEnrollment
	challenge          *api.StoredChallenge
	readSession        *api.StoredReadSession
	sessionCommit      *SessionCommit
	sessionRead        func(context.Context, api.Scope) (SessionCommit, error)
	strictReads        bool
	publicReads        int
	privateReads       int
	clockNow           func() time.Time
	transaction        *api.Transaction
	commit             *api.Commit
	transact           func(api.Transaction) (api.Commit, error)
	grants             *api.GrantSet
	policy             *api.EffectivePolicy
	plan               *api.LaunchPlanRecord
	planErr            error
	planReads          int
	planScope          api.Scope
	planID             api.ID
	events             *api.EventPage
	eventErr           error
	eventQuery         api.EventTailRequest
	refresh            func(context.Context, api.Scope, api.ReadSessionRefreshRequest) (api.StoredReadSession, error)
	ceremony           *api.EnrollmentChallenge
	ceremonyConfig     string
	ceremonyID         api.ID
	worker             *api.WorkerPrincipal
	revocation         *api.LaunchRevocation
	projection         *api.CredentialProjectionRecord
	projectionErr      error
	projectionRead     func(int)
	projectionReads    int
	projectionConfig   string
	projectionPrepared api.ID
	projectionEffect   *api.EffectRecord
}

func (s *fixtureStore) LaunchPlan(_ context.Context, scope api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	s.planReads++
	s.planScope, s.planID = scope, id
	if s.planErr != nil {
		return api.LaunchPlanRecord{}, s.planErr
	}
	if s.plan == nil {
		return api.LaunchPlanRecord{}, api.NotImplemented("lb-v2-service", "fixture launch plan")
	}
	// Deliberately return the selected projection even if its reservation ID
	// changed. Identity, rather than fixture filtering, must detect that drift.
	return *s.plan, nil
}

func (s *fixtureStore) Events(_ context.Context, _ api.Scope, query api.EventTailRequest) (api.EventPage, error) {
	s.eventQuery = query
	if s.eventErr != nil {
		return api.EventPage{}, s.eventErr
	}
	if s.events == nil {
		return api.EventPage{}, api.NotImplemented("lb-v2-service", "fixture identity event")
	}
	return *s.events, nil
}

func (s *fixtureStore) LaunchBinding(_ context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	if s.err != nil {
		return api.LaunchBindingRequest{}, s.err
	}
	if s.binding == nil {
		return api.LaunchBindingRequest{}, api.NotImplemented("lb-v2-service", "fixture launch binding")
	}
	if id != s.binding.Record.ID {
		return api.LaunchBindingRequest{}, &api.Error{Code: api.CodeNotFound}
	}
	return *s.binding, nil
}

func (s *fixtureStore) Proof(_ context.Context, _ api.Scope, id api.ID) (api.VerifiedHumanProof, error) {
	if s.err != nil {
		return api.VerifiedHumanProof{}, s.err
	}
	if s.proof == nil {
		return api.VerifiedHumanProof{}, api.NotImplemented("lb-v2-service", "fixture proof store")
	}
	if id != s.proof.Ref.ID {
		return api.VerifiedHumanProof{}, &api.Error{Code: api.CodeNotFound}
	}
	return *s.proof, nil
}

func (s *fixtureStore) Enrollment(context.Context, api.Scope) (api.HumanEnrollment, error) {
	if s.err != nil {
		return api.HumanEnrollment{}, s.err
	}
	if s.enrollment == nil {
		return api.HumanEnrollment{}, api.NotImplemented("lb-v2-service", "fixture enrollment")
	}
	return *s.enrollment, nil
}

func (s *fixtureStore) Challenge(_ context.Context, _ api.Scope, id api.ID) (api.StoredChallenge, error) {
	if s.err != nil {
		return api.StoredChallenge{}, s.err
	}
	if s.challenge == nil {
		return api.StoredChallenge{}, api.NotImplemented("lb-v2-service", "fixture challenge store")
	}
	if id != s.challenge.Challenge.ID {
		return api.StoredChallenge{}, &api.Error{Code: api.CodeNotFound}
	}
	return *s.challenge, nil
}

func (s *fixtureStore) ReadSession(ctx context.Context, scope api.Scope, id api.ID) (api.StoredReadSession, error) {
	s.publicReads++
	if s.strictReads {
		if _, err := scope.Connection.ReadAuthority(ctx); err != nil {
			return api.StoredReadSession{}, err
		}
	}
	if s.err != nil {
		return api.StoredReadSession{}, s.err
	}
	if s.readSession == nil {
		return api.StoredReadSession{}, api.NotImplemented("lb-v2-service", "fixture session store")
	}
	if id != s.readSession.Session.ID {
		return api.StoredReadSession{}, &api.Error{Code: api.CodeNotFound}
	}
	return *s.readSession, nil
}

func (s *fixtureStore) AuthorizationTarget(_ context.Context, _ api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	if s.err != nil {
		return api.HumanChallengeRequest{}, s.err
	}
	if s.proof == nil {
		return api.HumanChallengeRequest{}, api.NotImplemented("lb-v2-service", "fixture authorization target")
	}
	return s.proof.Target, nil
}

func (s *fixtureStore) Transact(_ context.Context, transaction api.Transaction) (api.Commit, error) {
	s.transaction = &transaction
	if s.err != nil {
		return api.Commit{}, s.err
	}
	started := time.Now().UTC()
	if s.clockNow != nil {
		started = s.clockNow()
	}
	var commit api.Commit
	var err error
	if s.transact != nil {
		commit, err = s.transact(transaction)
	} else if s.commit != nil {
		commit = *s.commit
	} else {
		return api.Commit{}, api.NotImplemented("lb-v2-service", "fixture transaction")
	}
	if err == nil && transaction.Scope.Request.Method == "human.session" && commit.Reply != nil && commit.Reply.Error == nil &&
		commit.Operation.Status == "succeeded" && s.readSession != nil && s.proof != nil && s.enrollment != nil {
		// Controlled durable projection of the actual transaction and returned
		// receipt. The store contract consumes the checked proof atomically.
		proof := *s.proof
		proof.ConsumedBy = commit.Operation.ID
		operation := commit.Operation
		operation.FirstSeq, operation.LastSeq = commit.FirstSeq, commit.LastSeq
		s.sessionCommit = &SessionCommit{Session: *s.readSession, Enrollment: *s.enrollment, Proof: proof,
			Receipt: api.MutationReceipt{Config: transaction.Scope.Config, Actor: transaction.Scope.Actor,
				PolicyGeneration: transaction.Scope.PolicyGeneration, SimulatedPresence: commit.Operation.SimulatedPresence,
				Key:        api.RequestKey{Method: transaction.Scope.Request.Method, IdempotencyKey: transaction.Scope.Request.IdempotencyKey, RequestSHA256: transaction.Scope.Request.RequestSHA256},
				RawRequest: append([]byte(nil), transaction.RawRequest...), Operation: operation, Reply: commit.Reply,
				FirstSeq: commit.FirstSeq, LastSeq: commit.LastSeq, RecordedAt: timestamp(started)}}
	}
	return commit, err
}

func (s *fixtureStore) ReadSessionCommit(ctx context.Context, scope api.Scope) (SessionCommit, error) {
	s.privateReads++
	if s.sessionRead != nil {
		return s.sessionRead(ctx, scope)
	}
	if s.sessionCommit == nil {
		return SessionCommit{}, api.NotImplemented("lb-v2-service", "fixture committed session")
	}
	return *s.sessionCommit, nil
}

func (s *fixtureStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	if s.err != nil {
		return api.GrantSet{}, s.err
	}
	if s.grants != nil {
		if id != s.grants.ID {
			return api.GrantSet{}, &api.Error{Code: api.CodeNotFound}
		}
		return *s.grants, nil
	}
	if id != s.record.GrantSetID {
		return api.GrantSet{}, &api.Error{Code: api.CodeNotFound}
	}
	return api.GrantSet{ID: id, LifeID: s.record.Target.LifeID, SHA256: s.record.GrantsSHA256,
		PolicyGeneration: s.record.PolicyGeneration, Generation: 1, ExpiresAt: timestamp(time.Now().Add(time.Hour))}, nil
}

func (s *fixtureStore) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	if s.err != nil {
		return api.EffectivePolicy{}, s.err
	}
	if s.policy != nil {
		return *s.policy, nil
	}
	return api.EffectivePolicy{Generation: s.record.PolicyGeneration}, nil
}

func (s *fixtureStore) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	return s.Policy(ctx, api.Scope{Config: scope.Config, Actor: scope.Actor})
}

func (s *fixtureStore) HumanPolicyGeneration(ctx context.Context, connection api.ConnectionContext, principal api.ID) (api.Generation, error) {
	if connection == nil || connection.Peer() == nil || connection.Binding().Class != api.EndpointHuman ||
		s.enrollment == nil || connection.Binding().Config != s.enrollment.Config || principal != s.enrollment.PrincipalID || s.enrollment.Generation == 0 {
		return 0, refusal(api.CodeUnauthenticated, "fixture private policy lookup has a foreign connection or principal")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return 0, err
	}
	policy, err := s.Policy(ctx, api.Scope{Connection: connection, Config: s.enrollment.Config,
		Actor: api.Actor{Kind: "human", ID: principal}})
	return policy.Generation, err
}

func (s *fixtureStore) WorkerPolicyGeneration(ctx context.Context, connection api.ConnectionContext, actor api.ID) (api.Generation, error) {
	if connection == nil || connection.Peer() == nil || connection.Binding().Class != api.EndpointWorker || s.worker == nil || actor != s.worker.Record.Actor.ID {
		return 0, refusal(api.CodeUnauthenticated, "fixture worker policy requires its native principal")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return 0, err
	}
	policy, err := s.Policy(ctx, api.Scope{Connection: connection, Config: connection.Binding().Config, Actor: s.worker.Record.Actor})
	return policy.Generation, err
}

type fixtureContainmentRegistry struct {
	binding api.ContainmentBinding
	err     error
}

func (r *fixtureContainmentRegistry) RegisterContainment(_ context.Context, binding api.ContainmentBinding) error {
	if r.err != nil {
		return r.err
	}
	r.binding = binding
	return nil
}
func (r *fixtureContainmentRegistry) ResolveContainment(context.Context, api.PeerFacts, api.InstalledBinding) (api.ContainmentBinding, error) {
	if r.err != nil {
		return api.ContainmentBinding{}, r.err
	}
	return r.binding, nil
}
func (r *fixtureContainmentRegistry) RevokeContainment(_ context.Context, id api.ID) error {
	if r.err != nil {
		return r.err
	}
	if id != r.binding.Lease.ContainmentID {
		return &api.Error{Code: api.CodeNotFound}
	}
	r.binding.Revoked = true
	return nil
}

func (s *fixtureStore) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	if s.err != nil {
		return api.LaunchRecord{}, s.err
	}
	if id != s.record.ID {
		return api.LaunchRecord{}, &api.Error{Code: api.CodeNotFound, Message: "fixture launch absent"}
	}
	return s.record, nil
}

func (s *fixtureStore) Lane(_ context.Context, _ api.Scope, ref api.LifeRef) (api.Lane, error) {
	if s.err != nil {
		return api.Lane{}, s.err
	}
	// Return the current life projection even for an older run reference. This
	// deliberate fixture boundary makes identity's own run check observable;
	// a fixture NotFound must not mask an omitted identity comparison.
	if ref.LifeID != s.lane.LifeID {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound, Message: "fixture life absent"}
	}
	return s.lane, nil
}

type fixturePeers struct {
	err        error
	peer       api.VerifiedPeer
	calls      int
	connection net.Conn
	binding    api.InstalledBinding
}

func (p *fixturePeers) Verify(_ context.Context, connection net.Conn, binding api.InstalledBinding) (api.VerifiedPeer, error) {
	p.calls++
	p.connection, p.binding = connection, binding
	if p.err == nil && p.peer == nil {
		return nil, &api.Error{Code: api.CodeUnauthenticated, Message: "no fixture peer"}
	}
	return p.peer, p.err
}

func serviceFixture(t *testing.T) (*Service, *fixtureStore, api.Scope) {
	t.Helper()
	record := api.LaunchRecord{Kind: "agent", ID: "launch", Config: "fixture",
		Target: api.LifeRef{LifeID: "life", Run: 1}, RootLifeID: "life",
		StarterChain: []api.ID{}, StarterEventSeq: 0,
		Actor:      api.Actor{Kind: "lane", ID: "instance", LifeID: "life", Level: 5, Role: "supervisor"},
		UIDLeaseID: "uid-lease", HostUID: 1234, ProcessGeneration: "generation",
		ContainmentID: "containment", GrantSetID: "grants", GrantsSHA256: api.Digest(strings.Repeat("a", 64)),
		PolicyGeneration: 1, EndpointGeneration: 1}
	store := &fixtureStore{record: record, lane: api.Lane{LifeID: "life", LaunchID: record.ID, Run: 1,
		RootLifeID: record.RootLifeID, StarterChain: []api.ID{}, StarterEventSeq: record.StarterEventSeq,
		Level: 5, Role: "supervisor", GrantSetID: "grants", PolicyGeneration: 1}}
	s, err := New(Dependencies{Peers: &fixturePeers{}, Registry: &fixtureContainmentRegistry{}, Store: store, Clock: fixtureClock{time.Now().UTC()},
		Attestation: fixtureAttestationPolicy(t), Sessions: store})
	if err != nil {
		t.Fatal(err)
	}
	store.clockNow = func() time.Time { return s.deps.Clock.Now() }
	store.refresh = func(ctx context.Context, scope api.Scope, request api.ReadSessionRefreshRequest) (api.StoredReadSession, error) {
		if store.readSession == nil || request.SessionID != store.readSession.Session.ID || request.ExpectedGeneration != store.readSession.Generation {
			return api.StoredReadSession{}, refusal(api.CodeConflict, "fixture refresh revision changed")
		}
		before := *store.readSession
		after := before
		after.Generation++
		now := s.deps.Clock.Now()
		deadline := now.Add(5 * time.Minute)
		absolute, err := utcTime(before.Session.ExpiresAt)
		if err != nil {
			return api.StoredReadSession{}, err
		}
		if absolute.Before(deadline) {
			deadline = absolute
		}
		after.Session.IdleExpiresAt = timestamp(deadline)
		if err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {
			return api.StoredReadSession{}, err
		}
		store.readSession = &after
		return after, nil
	}
	scope := api.Scope{Config: record.Config, Actor: record.Actor, LaunchID: record.ID,
		EndpointGeneration: record.EndpointGeneration, PolicyGeneration: record.PolicyGeneration}
	return s, store, scope
}

func TestSelfDerivesLaunch(t *testing.T) {
	s, store, scope := serviceFixture(t)
	scope.Source = "scheduler"
	scope.Request = api.Request{RequestID: "private-metadata"}
	scope.Connection = &fixtureConnection{}
	scope.Frame = &fixtureFrame{raw: []byte("private-frame")}
	scope.ReadView = &fixtureReadView{snapshot: api.ReadSnapshot{ID: "private-snapshot"}}
	got, err := s.IdentitySelf(context.Background(), scope, api.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Actor != store.record.Actor || got.LaunchID != store.record.ID || got.Source != "" ||
		!reflect.DeepEqual(got.Request, api.Request{}) || got.Connection != nil || got.Frame != nil || got.ReadView != nil {
		t.Fatal("self projection was not derived from the durable launch")
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-metadata") || strings.Contains(string(data), "scheduler") {
		t.Fatal("internal request metadata escaped into self")
	}
}

func TestSelfRefusesDrift(t *testing.T) {
	for _, field := range []string{"actor", "level", "role", "config", "endpoint", "policy", "revoked", "cleaned", "run", "launch", "lineage"} {
		t.Run(field, func(t *testing.T) {
			s, store, scope := serviceFixture(t)
			switch field {
			case "actor":
				scope.Actor.Kind = "human"
			case "level":
				scope.Actor.Level = 6
			case "role":
				scope.Actor.Role = "owner"
			case "config":
				scope.Config = "other"
			case "endpoint":
				scope.EndpointGeneration++
			case "policy":
				scope.PolicyGeneration++
			case "revoked":
				store.record.Revoked = true
			case "cleaned":
				store.lane.Cleaned = true
			case "run":
				store.record.Target.Run++
			case "launch":
				store.lane.LaunchID = "other-launch"
			case "lineage":
				store.lane.RootLifeID = "other-root"
			}
			got, err := s.IdentitySelf(context.Background(), scope, api.Empty{})
			if err == nil || !reflect.DeepEqual(got, api.Scope{}) {
				t.Fatal("stale or forged scope produced a self projection")
			}
		})
	}
}

func TestDependencyErrors(t *testing.T) {
	s, store, scope := serviceFixture(t)
	sentinel := api.NotImplemented("lb-v2-service", "fixture store")
	store.err = sentinel
	if _, err := s.IdentitySelf(context.Background(), scope, api.Empty{}); !errors.Is(err, sentinel) {
		t.Fatal("store failure was not preserved")
	}
	connection := fixtureUnboundConnection(t, fixtureHumanBinding())
	s.deps.Peers = &fixturePeers{err: sentinel}
	if _, err := s.Authenticate(context.Background(), connection); !errors.Is(err, sentinel) {
		t.Fatal("peer failure was not preserved")
	}
	if _, err := New(Dependencies{}); err == nil {
		t.Fatal("missing dependencies were accepted")
	}
	var absent *fixtureStore
	_, err := New(Dependencies{Peers: &fixturePeers{}, Registry: &fixtureContainmentRegistry{}, Store: absent, Clock: fixtureClock{time.Now()}})
	errorCode(t, err, api.CodePrerequisite)
}

func TestClosedContractGaps(t *testing.T) {
	s, store, scope := serviceFixture(t)
	ctx := context.Background()
	permit, err := s.BindLaunch(ctx, fixtureLaunchBinding(t, store.record))
	errorCode(t, err, api.CodeNotImplemented)
	if permit.LaunchID != "" || permit.CommittedSeq != 0 {
		t.Fatal("missing committed binding produced a launch permit")
	}
	errorCode(t, s.RevokeLaunch(ctx, store.record.ID), api.CodeNotImplemented)
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: scope.Config, Method: "identity.self", Params: json.RawMessage("{}")}
	errorCode(t, s.Authorize(ctx, scope, request), api.CodeNotImplemented)
	intent := api.HumanChallengeRequest{Method: "ticket.issue", TargetID: "root",
		RequestSHA256: store.record.GrantsSHA256, BaseGeneration: 1}
	human := api.Scope{Config: "fixture", Actor: api.Actor{Kind: "human", ID: "human"}}
	challenge, err := s.Challenge(ctx, human, intent)
	errorCode(t, err, api.CodeNotImplemented)
	if challenge.ID != "" {
		t.Fatal("missing enrollment produced a challenge")
	}
	f := newAssertion(t, nil)
	proof, err := s.Confirm(ctx, human, f.request)
	errorCode(t, err, api.CodeNotImplemented)
	if proof.ID != "" {
		t.Fatal("missing enrollment produced a proof")
	}
	proof = api.ProofRef{ID: "proof", RequestSHA256: intent.RequestSHA256,
		ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).Format(time.RFC3339Nano))}
	_, err = s.CheckProof(ctx, human, proof, intent)
	errorCode(t, err, api.CodeNotImplemented)
	_, err = s.HumanSession(ctx, human, api.HumanSessionRequest{})
	errorCode(t, err, api.CodeNotImplemented)
	ticketRequest := api.TicketIssueRequest{Level: 6, Role: "supervisor", GrantSetID: "root-grants",
		ExpiresAt: proof.ExpiresAt}
	_, err = s.TicketIssue(ctx, human, ticketRequest)
	errorCode(t, err, api.CodeUnauthenticated)
	human.Request = api.Request{Method: "ticket.issue", Proof: &proof}
	ticket, err := s.TicketIssue(ctx, human, ticketRequest)
	errorCode(t, err, api.CodeNotImplemented)
	if ticket.ID != "" {
		t.Fatal("unconsumed proof produced a ticket")
	}
}

func TestAgentCannotUseProof(t *testing.T) {
	s, _, scope := serviceFixture(t)
	for _, method := range []api.Method{"ticket.issue", "human.challenge", "dashboard.tree", "identity.self"} {
		request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
			Config: scope.Config, Method: method, Proof: &api.ProofRef{ID: "stolen"}}
		errorCode(t, s.Authorize(context.Background(), scope, request), api.CodeForbidden)
	}
}

func TestStrictInputs(t *testing.T) {
	for _, raw := range []string{"null", "[]", "{} {}", `{"actor":"human"}`,
		`{"actor":null}`, `{"actor":1,"actor":2}`, `{"actor":{},"actor":[]}`} {
		var empty api.Empty
		errorCode(t, strictObject([]byte(raw), &empty), api.CodeInvalid)
	}
	for _, raw := range []string{`{"Method":"ticket.issue"}`, `{"method":null}`,
		`{"method":"ticket.issue","method":"lane.start"}`} {
		var request api.HumanChallengeRequest
		errorCode(t, strictObject([]byte(raw), &request), api.CodeInvalid)
	}
	var empty api.Empty
	if err := strictObject([]byte(" { } \n"), &empty); err != nil {
		t.Fatal(err)
	}
}

type fixtureRegistry struct {
	methods map[api.Method]api.Handler
	err     error
}

func (r *fixtureRegistry) Register(method api.Method, handler api.Handler) error {
	if r.err != nil {
		return r.err
	}
	if _, exists := r.methods[method]; exists {
		return &api.Error{Code: api.CodeConflict, Message: "duplicate fixture method"}
	}
	r.methods[method] = handler
	return nil
}

func (*fixtureRegistry) RegisterStream(api.Method, api.StreamHandler) error {
	return &api.Error{Code: api.CodeInvalid, Message: "no identity stream"}
}

func TestRegisterExactMethods(t *testing.T) {
	s, _, _ := serviceFixture(t)
	r := &fixtureRegistry{methods: make(map[api.Method]api.Handler)}
	if err := s.Register(r); err != nil {
		t.Fatal(err)
	}
	if len(r.methods) != 5 {
		t.Fatalf("registered %d methods", len(r.methods))
	}
	for method, handler := range r.methods {
		if api.Methods[method].Owner != "lb-v2-identity" {
			t.Fatal("registered another module's method")
		}
		_, err := handler(context.Background(), api.Scope{}, json.RawMessage(`{"actor":"human"}`))
		errorCode(t, err, api.CodeInvalid)
	}
	sentinel := &api.Error{Code: api.CodeUnavailable, Message: "fixture registrar unavailable"}
	r.err = sentinel
	if err := s.Register(r); !errors.Is(err, sentinel) {
		t.Fatal("registration failure was swallowed")
	}
}
