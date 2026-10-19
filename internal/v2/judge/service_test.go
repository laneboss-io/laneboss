package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type scopedStore struct {
	api.StateStore
	policy      api.EffectivePolicy
	lane        api.Lane
	grants      api.GrantSet
	fail        error
	turn        api.TurnSnapshot
	task        []byte
	decisions   []api.DecisionCandidate
	badMetadata bool
	badBytes    bool
}

type scopeConnection struct {
	binding api.InstalledBinding
	read    api.ReadAuthority
	readErr error
	conn    net.Conn
	peer    api.VerifiedPeer
	closed  bool
}

func (c *scopeConnection) ID() api.ID             { return "connection-a" }
func (c *scopeConnection) Conn() net.Conn         { return c.conn }
func (c *scopeConnection) Peer() api.VerifiedPeer { return c.peer }
func (c *scopeConnection) BindPeer(peer api.VerifiedPeer) error {
	if c.closed || c.peer != nil || wire.Nil(peer) {
		return problem(api.CodeUnauthenticated, "fixture peer rebind")
	}
	c.peer = peer
	return nil
}
func (c *scopeConnection) BindReadAuthority(read api.ReadAuthority) error {
	if c.closed || c.read.SessionID != "" {
		return problem(api.CodeUnauthenticated, "fixture read rebind")
	}
	c.read = read
	return nil
}
func (c *scopeConnection) Close() error {
	c.closed = true
	return c.conn.Close()
}
func (c *scopeConnection) Binding() api.InstalledBinding { return c.binding }
func (c *scopeConnection) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	if c.readErr != nil {
		return api.ReadAuthority{}, c.readErr
	}
	return c.read, nil
}

type scopePeer struct{ err error }

func (p *scopePeer) Alive(ctx context.Context) error {
	if p.err != nil {
		return p.err
	}
	return ctx.Err()
}
func (p *scopePeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	return api.PeerFacts{HostUID: 1234, HostGID: 1234, HostPID: 4321, ProcessGeneration: "fixture-generation"}, p.Alive(ctx)
}
func (p *scopePeer) Close() error { return nil }

type scopeFrame struct{ err error }

func (f *scopeFrame) Bytes() []byte { return nil }
func (f *scopeFrame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	if f.err != nil {
		return f.err
	}
	if ctx.Err() != nil {
		return problem(api.CodeCancelled, "fixture frame cancelled")
	}
	if connection == nil || connection.Binding().Schema != "laneboss.binding.v2" {
		return problem(api.CodeUnauthenticated, "fixture binding differs")
	}
	return nil
}

func (s *scopedStore) Turn(ctx context.Context, scope api.Scope, target api.LifeRef, id api.ID) (api.TurnSnapshot, error) {
	if target != s.turn.Target || id != s.turn.LogicalTurnID {
		return api.TurnSnapshot{}, problem(api.CodeNotFound, "fixture turn differs")
	}
	return s.turn, nil
}

func (s *scopedStore) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	if id != s.turn.Task.ID {
		return api.ObjectMetadata{}, problem(api.CodeNotFound, "fixture object differs")
	}
	ref := s.turn.Task
	if s.badMetadata {
		ref.Class = "another-class"
	}
	return api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: scope.Config, LifeID: s.lane.LifeID}}, nil
}

func (s *scopedStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if request.ObjectID != s.turn.Task.ID || request.Offset != 0 || request.Limit < len(s.task) {
		return api.BlobChunk{}, problem(api.CodeInvalid, "fixture blob request differs")
	}
	data := bytes.Clone(s.task)
	if s.badBytes {
		data = append(data, 'x')
	}
	return api.BlobChunk{ObjectID: request.ObjectID, Data: data, SHA256: wire.Digest(data)}, nil
}

func (s *scopedStore) DecisionCandidates(ctx context.Context, scope api.Scope, query api.DecisionQuery) (api.DecisionPage, error) {
	if query.Target != s.turn.Target || query.Cursor != "" || query.SnapshotID != "" && query.SnapshotID != "snapshot-a" {
		return api.DecisionPage{}, problem(api.CodeInvalid, "fixture decision query differs")
	}
	page := api.DecisionPage{SnapshotID: "snapshot-a", PolicyGeneration: s.policy.Generation, Complete: true}
	for _, decision := range s.decisions {
		if decision.Binding == (query.Kind == "binding") {
			page.Candidates = append(page.Candidates, decision)
		}
	}
	return page, nil
}

func (s *scopedStore) Policy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if s.fail != nil {
		return api.EffectivePolicy{}, s.fail
	}
	if scope.Config != "example" {
		return api.EffectivePolicy{}, problem(api.CodeForbidden, "fixture config differs")
	}
	return s.policy, nil
}

func (s *scopedStore) Lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	if target.LifeID != s.lane.LifeID {
		return api.Lane{}, problem(api.CodeNotFound, "fixture target differs")
	}
	return s.lane, nil
}

func (s *scopedStore) Grants(ctx context.Context, id api.ID) (api.GrantSet, error) {
	if id != s.grants.ID {
		return api.GrantSet{}, problem(api.CodeNotFound, "fixture grants differ")
	}
	return s.grants, nil
}

func serviceFixture(t *testing.T) (*Service, *scopedStore, *countingJudge, api.Scope, api.JudgeRequest) {
	t.Helper()
	r := testRequest()
	r.Purpose, r.Rules, r.Config, r.Context = "preview", []api.JudgeRule{}, api.JudgeConfig{}, api.JudgeContext{}
	clock := &testClock{now: time.Now()}
	store := &scopedStore{
		policy: api.EffectivePolicy{Generation: 1, Judge: testConfig(),
			Context: api.RoleContext{Level: 3, Role: "executor"},
			Rules: []api.Rule{{ID: "rule-a", Text: "Do not publish artifacts.",
				Source: api.SourceRef{ID: "source-a", SHA256: wire.Digest([]byte("source")), Generation: 1}}}},
		lane: api.Lane{LifeID: "life-a", Run: 1, Level: 3, Role: "executor",
			LaunchID: "launch-a", Generation: 1,
			GrantSetID: "grants-a", LogicalTurnID: "turn-a", PolicyGeneration: 1,
			Workspace: api.Workspace{LogicalCWD: "/work"}},
		grants: api.GrantSet{ID: "grants-a", LifeID: "life-a", SHA256: wire.Digest([]byte("grants")),
			PolicyGeneration: 1, Generation: 1,
			ExpiresAt: api.Timestamp(clock.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}}
	store.task = []byte("Review the complete build plan.")
	store.turn = api.TurnSnapshot{Target: api.LifeRef{LifeID: "life-a", Run: 1}, LogicalTurnID: "turn-a", Generation: 1, PolicyGeneration: 1,
		Task: api.BlobRef{ID: "task-a", Class: "task", Bytes: int64(len(store.task)), SHA256: wire.Digest(store.task)}}
	provider := &countingJudge{}
	s, err := New(Dependencies{Clef: provider, Store: store, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: "example", Actor: api.Actor{Kind: "agent", ID: "actor-a", LifeID: "life-a"},
		EndpointGeneration: 1, PolicyGeneration: 1, LaunchID: "launch-a", Frame: &scopeFrame{}}
	local, remote := net.Pipe()
	t.Cleanup(func() {
		if err := local.Close(); err != nil {
			t.Error(err)
		}
		if err := remote.Close(); err != nil {
			t.Error(err)
		}
	})
	scope.Connection = &scopeConnection{conn: local, peer: &scopePeer{}, binding: api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: scope.Config, Class: api.EndpointLane,
		EndpointGeneration: 1, LaunchID: scope.LaunchID, Target: &api.LifeRef{LifeID: "life-a", Run: 1}}}
	return s, store, provider, scope, r
}

func errorCode(t *testing.T, err error, expected api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != expected {
		t.Fatalf("expected typed %s: %v", expected, err)
	}
}

func TestServiceScopesAndWorkerGate(t *testing.T) {
	for _, name := range []string{"worker", "identity", "provider", "role", "life", "generation", "revoked", "store"} {
		t.Run(name, func(t *testing.T) {
			s, store, provider, scope, request := serviceFixture(t)
			want := api.CodeNotImplemented
			switch name {
			case "identity":
				scope.Actor.ID, want = "", api.CodeUnauthenticated
			case "provider":
				request.Config, want = testConfig(), api.CodeForbidden
				request.Config.Provider = "typesafe"
				request.Config.Model = "jev-1.14.0"
			case "role":
				request.Context.Role.Level, want = 6, api.CodeForbidden
			case "life":
				request.Context.Target.LifeID, want = "sibling", api.CodeForbidden
			case "generation":
				scope.PolicyGeneration, want = 2, api.CodeConflict
			case "revoked":
				store.grants.Revoked, want = true, api.CodeForbidden
			case "store":
				store.fail = api.NotImplemented("lb-v2-service", "store.Policy")
			}
			_, err := s.JudgeAsk(context.Background(), scope, request)
			errorCode(t, err, want)
			if provider.calls.Load() != 0 {
				t.Fatal("service executed a provider")
			}
		})
	}
}

type registry struct {
	handlers map[api.Method]api.Handler
	fail     api.Method
}

func (r *registry) Register(method api.Method, handler api.Handler) error {
	if method == r.fail || r.handlers[method] != nil {
		return problem(api.CodeConflict, "fixture registration rejected")
	}
	r.handlers[method] = handler
	return nil
}

func (r *registry) RegisterStream(api.Method, api.StreamHandler) error {
	return problem(api.CodeUnsupported, "fixture has no streams")
}

func TestRegisterStrictRPCAndErrors(t *testing.T) {
	s, _, _, scope, request := serviceFixture(t)
	r := &registry{handlers: map[api.Method]api.Handler{}}
	if err := s.Register(r); err != nil || len(r.handlers) != 2 || r.handlers["judge.ask"] == nil || r.handlers["judge.list"] == nil {
		t.Fatal("judge methods not registered")
	}
	if _, err := r.handlers["judge.list"](context.Background(), scope, []byte(`{"extra":1}`)); err == nil {
		t.Fatal("unknown list field accepted")
	}
	_, err := r.handlers["judge.list"](context.Background(), scope, []byte("{}"))
	errorCode(t, err, api.CodeNotImplemented)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.handlers["judge.ask"](context.Background(), scope, raw)
	errorCode(t, err, api.CodeNotImplemented)
	r = &registry{handlers: map[api.Method]api.Handler{}, fail: "judge.list"}
	errorCode(t, s.Register(r), api.CodeConflict)
}

func TestInternalLeaseCannotBeAnArg(t *testing.T) {
	errorCode(t, RunInternal(context.Background(), "example", []string{"--job", "arbitrary"}), api.CodeInvalid)
	errorCode(t, RunInternal(context.Background(), "example", nil), api.CodeInvalid)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	errorCode(t, RunInternal(ctx, "example", []string{"--binding", "/runtime/laneboss-worker.json", "--lease", "judge-lease"}), api.CodeCancelled)
	if _, err := New(Dependencies{}); err == nil {
		t.Fatal("missing dependencies accepted")
	}
}
