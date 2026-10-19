package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Authentication fixtures isolate transport behavior. They prove no kernel,
// human-presence, installed-binding or production-service acceptance claim.
type authFixture struct {
	mu          sync.Mutex
	scope       api.Scope
	denied      bool
	drift       bool
	policyDrift bool
	calls       int
	store       api.Store
}

func (a *authFixture) Authenticate(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	return a.fixtureScope(ctx, connection)
}

func (a *authFixture) CurrentConnectionScope(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	if connection == nil || connection.Peer() == nil {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "fixture current scope requires its bound peer")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return api.Scope{}, err
	}
	return a.fixtureScope(ctx, connection)
}

func (a *authFixture) fixtureScope(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	result := a.scope
	result.Connection = connection
	if connection != nil && connection.Peer() == nil {
		facts := api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: "fixture-process"}
		if a.store != nil {
			launch, err := a.store.Launch(ctx, a.scope.LaunchID)
			if err != nil {
				return result, err
			}
			facts.ProcessGeneration, facts.ContainmentID = launch.ProcessGeneration, launch.ContainmentID
		}
		if err := connection.BindPeer(&peerFixture{facts: facts}); err != nil {
			return result, err
		}
	}
	if a.drift && a.calls > 1 {
		result.EndpointGeneration++
	}
	if a.policyDrift && a.calls > 1 {
		result.PolicyGeneration++
	}
	return result, nil
}
func (a *authFixture) Authorize(_ context.Context, scope api.Scope, request api.Request) error {
	if a.denied || scope.Config != request.Config {
		return serviceError(api.CodeForbidden, "fixture refuses scope")
	}
	return nil
}
func (*authFixture) BindLaunch(context.Context, api.LaunchBindingRequest) (api.LaunchPermit, error) {
	return api.LaunchPermit{}, api.NotImplemented("lb-v2-identity", "fixture bind")
}
func (*authFixture) RevokeLaunch(context.Context, api.ID) error {
	return api.NotImplemented("lb-v2-identity", "fixture revoke")
}

type unusedStore struct{ api.StateStore }

func (*unusedStore) LookupReceipt(context.Context, api.Scope, api.RequestKey) (api.MutationReceipt, error) {
	return api.MutationReceipt{}, api.NotImplemented("lb-v2-service", "fixture receipt")
}
func (*unusedStore) BeginRead(context.Context, api.Scope) (api.ReadView, error) {
	return receiptView{snapshot: api.ReadSnapshot{Config: "service-fixture"}}, nil
}

type fixtureClock struct{}

func (fixtureClock) Now() time.Time { return time.Now() }

func fixtureID(t *testing.T) api.ID {
	t.Helper()
	id, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func requestFor(t *testing.T, method api.Method, params any) api.Request {
	t.Helper()
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "service-fixture",
		Method: method, RequestID: fixtureID(t), IdempotencyKey: fixtureID(t), Params: data}
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func fixtureServer(t *testing.T) *Server {
	t.Helper()
	auth := &authFixture{scope: api.Scope{Config: "service-fixture", Actor: api.Actor{Kind: "lane",
		ID: fixtureID(t), LifeID: fixtureID(t), Level: 3, Role: "executor"}, LaunchID: fixtureID(t), EndpointGeneration: 1}}
	return &Server{options: Options{Config: auth.scope.Config}, handlers: make(map[api.Method]api.Handler),
		streams: make(map[api.Method]api.StreamHandler), deps: Dependencies{Authenticator: auth,
			Store: &unusedStore{}, Clock: fixtureClock{}, Binding: api.InstalledBinding{Config: auth.scope.Config, Class: api.EndpointLane,
				EndpointGeneration: 1, LaunchID: auth.scope.LaunchID, Target: &api.LifeRef{LifeID: auth.scope.Actor.LifeID, Run: 1}}}, watchers: make(chan struct{}, 32)}
}

func codeIs(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func identityHandler(_ context.Context, scope api.Scope, _ json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(scope)
}

func TestClosedRegistrar(t *testing.T) {
	s := fixtureServer(t)
	codeIs(t, s.Register("invented.method", identityHandler), api.CodeInvalid)
	codeIs(t, s.Register("identity.self", nil), api.CodeInvalid)
	if err := s.Register("identity.self", identityHandler); err != nil {
		t.Fatal(err)
	}
	codeIs(t, s.Register("identity.self", identityHandler), api.CodeConflict)
	codeIs(t, s.RegisterStream("health", nil), api.CodeInvalid)
	stream := func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) {
		return nil, api.NotImplemented("lb-v2-lifecycle", "fixture producer")
	}
	if err := s.RegisterStream("event.tail", stream); err != nil {
		t.Fatal(err)
	}
	codeIs(t, s.RegisterStream("event.tail", stream), api.CodeConflict)
}

func TestAuthorityBeforeAndAfterRead(t *testing.T) {
	for _, mode := range []string{"denied", "drift", "policy-drift", "valid"} {
		t.Run(mode, func(t *testing.T) {
			s := fixtureServer(t)
			auth := s.deps.Authenticator.(*authFixture)
			auth.denied, auth.drift = mode == "denied", mode == "drift"
			auth.policyDrift = mode == "policy-drift"
			called := 0
			if err := s.Register("identity.self", func(ctx context.Context, scope api.Scope, data json.RawMessage) (json.RawMessage, error) {
				called++
				return identityHandler(ctx, scope, data)
			}); err != nil {
				t.Fatal(err)
			}
			result, _, err := s.dispatch(context.Background(), nil, requestFor(t, "identity.self", api.Empty{}))
			switch mode {
			case "denied":
				codeIs(t, err, api.CodeForbidden)
				if called != 0 {
					t.Fatal("unauthorized read handler ran")
				}
			case "drift", "policy-drift":
				codeIs(t, err, api.CodeUnauthenticated)
				if len(result) != 0 {
					t.Fatal("revoked reader received data")
				}
			case "valid":
				if err != nil {
					t.Fatal(err)
				}
				var scope api.Scope
				if err := wire.Decode(result, &scope); err != nil {
					t.Fatal(err)
				}
				if scope.Actor != auth.scope.Actor || auth.calls != 2 {
					t.Fatal("peer authority was not rechecked")
				}
			}
		})
	}
}

func TestMutationCannotBypassReceipt(t *testing.T) {
	s := fixtureServer(t)
	called := false
	if err := s.Register("blob.begin", func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
		called = true
		return nil, serviceError(api.CodeIntegrity, "mutation handler should not run")
	}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	request := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "task", SHA256: api.Digest(hex.EncodeToString(sum[:]))})
	_, _, err := s.dispatch(context.Background(), nil, request)
	codeIs(t, err, api.CodeNotImplemented)
	if called {
		t.Fatal("mutation ran without durable exact-reply contract")
	}
}

func TestUnverifiedServerStaysClosed(t *testing.T) {
	s := fixtureServer(t)
	_, err := NewServer(s.options, s.deps)
	codeIs(t, err, api.CodeInvalid)
	codeIs(t, s.Serve(context.Background(), nil), api.CodeNotImplemented)
}

func TestSelectedEnd(t *testing.T) {
	life := fixtureID(t)
	request := api.EventTailRequest{LifeID: life, Run: 2, Until: "lane.ended"}
	event := api.Event{LifeID: life, Run: 1, Kind: "lane.ended", Origin: "service"}
	event.Seq = 2
	if selectedEnd(request, event) {
		t.Fatal("old run ended follow")
	}
	event.Run, event.Origin = 2, "observation"
	if selectedEnd(request, event) {
		t.Fatal("observation ended follow")
	}
	event.Origin, event.LifeID = "service", fixtureID(t)
	if selectedEnd(request, event) {
		t.Fatal("sibling ended follow")
	}
	event.LifeID = life
	if !selectedEnd(request, event) {
		t.Fatal("authentic selected run did not end follow")
	}
}

type floodFixture struct {
	mu     sync.Mutex
	count  int
	ready  chan struct{}
	closed chan struct{}
	digest api.Digest
}

func (f *floodFixture) Next(ctx context.Context) (api.StreamFrame, error) {
	f.mu.Lock()
	f.count++
	if f.count == 1 {
		close(f.ready)
	}
	f.mu.Unlock()
	select {
	case <-ctx.Done():
		return api.StreamFrame{}, ctx.Err()
	default:
	}
	return api.StreamFrame{Cursor: "fixture-cursor", Chunk: &api.BlobChunk{ObjectID: "fixture-object", Data: []byte{}, SHA256: f.digest}}, nil
}
func (f *floodFixture) Close() error { close(f.closed); return nil }

func TestStalledWatcherIsolation(t *testing.T) {
	s := fixtureServer(t)
	sum := sha256.Sum256(nil)
	flood := &floodFixture{ready: make(chan struct{}), closed: make(chan struct{}), digest: api.Digest(hex.EncodeToString(sum[:]))}
	if err := s.RegisterStream("lane.attach", func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) { return flood, nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Register("identity.self", identityHandler); err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, "lane.attach", api.AttachRequest{Target: api.LifeRef{LifeID: s.deps.Authenticator.(*authFixture).scope.Actor.LifeID, Run: 1}, Mode: "output"})
	initial, err := json.Marshal(api.StreamFrame{RequestID: request.RequestID, Index: 1, Cursor: "fixture-cursor",
		Chunk: &api.BlobChunk{ObjectID: "fixture-object", Data: []byte{}, SHA256: flood.digest}})
	if err != nil {
		t.Fatal(err)
	}
	inside, outside := net.Pipe()
	defer outside.Close()
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		defer close(done)
		defer inside.Close()
		s.serveStream(ctx, inside, s.deps.Authenticator.(*authFixture).scope, request, initial)
	}()
	select {
	case <-flood.ready:
	case <-ctx.Done():
		t.Fatal("watcher producer did not start")
	}
	if _, _, err := s.dispatch(ctx, nil, requestFor(t, "identity.self", api.Empty{})); err != nil {
		t.Fatal("stalled watcher blocked control read", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("watcher exceeded its bounded write deadline")
	}
	select {
	case <-flood.closed:
	default:
		t.Fatal("watcher producer was not collected")
	}
	flood.mu.Lock()
	count := flood.count
	flood.mu.Unlock()
	if count < 257 {
		t.Fatalf("test did not exercise queue bound: %d", count)
	}
}
