package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dashboard"
)

type dashboardNativeFrame struct {
	raw  []byte
	conn *connectionContext
}

func (f dashboardNativeFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }
func (f dashboardNativeFrame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	if f.conn == nil || connection == nil || f.conn.ID() != connection.ID() || connection.Peer() == nil {
		return serviceError(api.CodeUnauthenticated, "dashboard native fixture frame is not bound")
	}
	return connection.Peer().Alive(ctx)
}

type dashboardProofStore struct {
	*unusedStore
	target api.HumanChallengeRequest
}

func (s *dashboardProofStore) AuthorizationTarget(context.Context, api.Scope, api.Request) (api.HumanChallengeRequest, error) {
	return s.target, nil
}

type dashboardProofAuth struct {
	*authFixture
	proof api.VerifiedHumanProof
}

func (a *dashboardProofAuth) Challenge(context.Context, api.Scope, api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return api.HumanChallenge{}, api.NotImplemented("lb-v2-identity", "dashboard test challenge")
}
func (a *dashboardProofAuth) Confirm(context.Context, api.Scope, api.HumanConfirmRequest) (api.ProofRef, error) {
	return api.ProofRef{}, api.NotImplemented("lb-v2-identity", "dashboard test confirmation")
}
func (a *dashboardProofAuth) CheckProof(ctx context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	if proof != a.proof.Ref || target != a.proof.Target || scope.Config != a.proof.Config ||
		scope.Actor.ID != a.proof.PrincipalID || scope.EndpointGeneration != a.proof.EndpointGeneration || scope.Frame == nil {
		return api.VerifiedHumanProof{}, serviceError(api.CodeUnauthenticated, "dashboard test proof binding differs")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return api.VerifiedHumanProof{}, err
	}
	return a.proof, nil
}

func dashboardTransportFixture(t *testing.T) (*Server, *connectionContext, api.Actor) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	binding := api.InstalledBinding{Config: "service-fixture", Class: api.EndpointHuman,
		EndpointGeneration: 1, ServiceVersion: "fixture"}
	connection, err := newConnection(left, binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.BindPeer(&peerFixture{facts: api.PeerFacts{HostUID: 1000, HostGID: 1000,
		HostPID: 100, ProcessGeneration: "dashboard-fixture"}}); err != nil {
		t.Fatal(err)
	}
	actor := api.Actor{Kind: "human", ID: "human-dashboard"}
	auth := &authFixture{scope: api.Scope{Config: binding.Config, Actor: actor,
		EndpointGeneration: binding.EndpointGeneration, PolicyGeneration: 1}}
	server := &Server{options: Options{Config: binding.Config}, deps: Dependencies{
		Binding: binding, Authenticator: auth, Store: &unusedStore{}, Clock: fixtureClock{}},
		handlers: make(map[api.Method]api.Handler), streams: make(map[api.Method]api.StreamHandler),
		connections: map[api.ID]*connectionContext{connection.ID(): connection}}
	return server, connection, actor
}

func dashboardFreshConnection(t *testing.T, server *Server) *connectionContext {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	connection, err := newConnection(left, server.deps.Binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.BindPeer(&peerFixture{facts: api.PeerFacts{HostUID: 1001, HostGID: 1001,
		HostPID: 101, ProcessGeneration: "dashboard-fresh"}}); err != nil {
		t.Fatal(err)
	}
	server.connections[connection.ID()] = connection
	return connection
}

func issueDashboardBootstrap(t *testing.T, server *Server, issuer, redemption *connectionContext, actor api.Actor) (dashboard.BootstrapBinding, api.Request, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	nonce := []byte("dashboard-browser-nonce-1234")
	if err := issuer.BindReadAuthority(api.ReadAuthority{SessionID: "session-issuer", PrincipalID: actor.ID,
		CredentialID: "credential-issuer", ConnectionID: issuer.ID(), Config: "service-fixture", EndpointGeneration: 1,
		Generation: 1, IdleExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano)),
		ExpiresAt: api.Timestamp(now.Add(2 * time.Minute).Format(time.RFC3339Nano))}); err != nil {
		t.Fatal(err)
	}
	target := api.HumanChallengeRequest{Method: "human.session"}
	request := requestFor(t, "human.session", api.Empty{})
	target.RequestSHA256 = request.RequestSHA256
	proof := api.VerifiedHumanProof{Ref: api.ProofRef{ID: "dashboard-proof", RequestSHA256: request.RequestSHA256,
		ExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))}, Config: "service-fixture",
		PrincipalID: actor.ID, ConnectionID: redemption.ID(), EndpointClass: api.EndpointHuman,
		EndpointGeneration: 1, Target: target}
	request.Proof = &proof.Ref
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	server.deps.Authenticator = &dashboardProofAuth{authFixture: server.deps.Authenticator.(*authFixture), proof: proof}
	server.deps.Store = &dashboardProofStore{unusedStore: &unusedStore{}, target: target}
	owner := api.Scope{Config: "service-fixture", Actor: actor, Source: "cli", Request: request,
		Connection: issuer, EndpointGeneration: 1, Frame: dashboardNativeFrame{raw: raw, conn: issuer}}
	binding, err := server.IssueDashboardBootstrap(context.Background(), owner, redemption.ID(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	return binding, request, raw, nonce
}

func TestDashboardBootstrapRefusesImpl6f85(t *testing.T) {
	server, connection, actor := dashboardTransportFixture(t)
	request := requestFor(t, "human.session", api.Empty{})
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.Scope(context.Background(), httptest.NewRequest("POST", "https://dashboard.example/rpc", nil), request, raw, nil)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
		t.Fatalf("implicit dashboard connection selection was not refused: %v", err)
	}
	_ = connection
	_ = actor
}

func TestDashboardBootstrapRedeemsOnce3a68(t *testing.T) {
	server, connection, actor := dashboardTransportFixture(t)
	redemption := dashboardFreshConnection(t, server)
	binding, sessionRequest, sessionRaw, nonce := issueDashboardBootstrap(t, server, connection, redemption, actor)
	claim := &dashboard.SessionClaim{BootstrapToken: binding.Token, BootstrapNonce: nonce}
	scope, err := server.Scope(context.Background(), httptest.NewRequest("POST", "https://dashboard.example/rpc", nil), sessionRequest, sessionRaw, claim)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Connection != redemption || scope.Actor != actor || scope.Source != "dashboard" {
		t.Fatalf("bootstrap redeemed to the wrong native principal: %+v", scope)
	}
	_, err = server.Scope(context.Background(), httptest.NewRequest("POST", "https://dashboard.example/rpc", nil), sessionRequest, sessionRaw, claim)
	var replayErr *api.Error
	if !errors.As(err, &replayErr) || replayErr.Code != api.CodeUnauthenticated {
		t.Fatalf("bootstrap redemption was reusable: %v", err)
	}
}

func TestDashNonceRefuse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nonce []byte
	}{
		{name: "missing"},
		{name: "wrong", nonce: []byte("another-browser-nonce")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, issuer, actor := dashboardTransportFixture(t)
			redemption := dashboardFreshConnection(t, server)
			binding, request, raw, expected := issueDashboardBootstrap(t, server, issuer, redemption, actor)
			nonce := tc.nonce
			_, err := server.Scope(context.Background(), httptest.NewRequest("POST", "https://dashboard.example/rpc", nil), request, raw,
				&dashboard.SessionClaim{BootstrapToken: binding.Token, BootstrapNonce: nonce})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
				t.Fatalf("%s browser nonce was accepted: %v", tc.name, err)
			}
			if tc.name == "wrong" && string(expected) == string(nonce) {
				t.Fatal("wrong nonce fixture unexpectedly matched the issued nonce")
			}
		})
	}
}

func TestDashBootSameConn(t *testing.T) {
	server, issuer, actor := dashboardTransportFixture(t)
	redemption := dashboardFreshConnection(t, server)
	binding, request, raw, _ := issueDashboardBootstrap(t, server, issuer, redemption, actor)
	request.Proof = &binding.Proof
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	owner := api.Scope{Config: "service-fixture", Actor: actor, Source: "cli", Request: request,
		Connection: issuer, EndpointGeneration: 1, Frame: dashboardNativeFrame{raw: raw, conn: issuer}}
	_, err = server.IssueDashboardBootstrap(context.Background(), owner, issuer.ID(), []byte("dashboard-browser-nonce-1234"))
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeConflict {
		t.Fatalf("same-connection bootstrap was not refused: %v", err)
	}
}

func TestDashBootRace(t *testing.T) {
	server, issuer, actor := dashboardTransportFixture(t)
	redemption := dashboardFreshConnection(t, server)
	binding, _, _, nonce := issueDashboardBootstrap(t, server, issuer, redemption, actor)
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, err := server.redeemDashboardBootstrap(context.Background(), binding.Token, nonce)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent bootstrap redemption successes=%d", successes)
	}
}

func TestDashboardBootstrapRefusesExpi8c30(t *testing.T) {
	issue := func(t *testing.T) (*Server, *connectionContext, api.Actor, dashboard.BootstrapBinding, api.Request, []byte, []byte) {
		t.Helper()
		server, issuer, actor := dashboardTransportFixture(t)
		redemption := dashboardFreshConnection(t, server)
		binding, request, raw, nonce := issueDashboardBootstrap(t, server, issuer, redemption, actor)
		request.Proof = &binding.Proof
		return server, redemption, actor, binding, request, raw, nonce
	}

	t.Run("expired", func(t *testing.T) {
		server, _, _, binding, request, raw, nonce := issue(t)
		server.mu.Lock()
		entry := server.dashboardBootstraps[binding.Token]
		entry.binding.ExpiresAt = api.Timestamp(time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano))
		server.dashboardBootstraps[binding.Token] = entry
		server.mu.Unlock()
		_, err := server.Scope(context.Background(), httptest.NewRequest("POST", "https://dashboard.example/rpc", nil), request, raw, &dashboard.SessionClaim{BootstrapToken: binding.Token, BootstrapNonce: nonce})
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
			t.Fatalf("expired bootstrap was accepted: %v", err)
		}
	})

	t.Run("foreign-or-missing-native", func(t *testing.T) {
		server, connection, actor, binding, request, raw, nonce := issue(t)
		delete(server.connections, connection.ID())
		_ = actor
		_, err := server.Scope(context.Background(), httptest.NewRequest("POST", "https://dashboard.example/rpc", nil), request, raw, &dashboard.SessionClaim{BootstrapToken: binding.Token, BootstrapNonce: nonce})
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
			t.Fatalf("bootstrap survived removal of its issuing native connection: %v", err)
		}
	})
}

func TestDashboardDispatchFrameSource(t *testing.T) {
	server, connection, actor := dashboardTransportFixture(t)
	now := time.Now().UTC()
	authority := api.ReadAuthority{SessionID: "session-dashboard", PrincipalID: actor.ID,
		CredentialID: "credential-dashboard", ConnectionID: connection.ID(), Config: "service-fixture",
		EndpointGeneration: 1, Generation: 1,
		IdleExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano)),
		ExpiresAt:     api.Timestamp(now.Add(2 * time.Minute).Format(time.RFC3339Nano))}
	if err := connection.BindReadAuthority(authority); err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, "identity.self", api.Empty{})
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	claim := &dashboard.SessionClaim{SessionID: authority.SessionID, Actor: actor,
		ConnectionID: connection.ID(), EndpointGeneration: authority.EndpointGeneration}
	scope, err := server.Scope(context.Background(), httptest.NewRequest("POST", "https://dashboard.example/rpc", nil), request, raw, claim)
	if err != nil {
		t.Fatal(err)
	}
	var seenSource string
	var frameBytes []byte
	if err := server.Register("identity.self", func(_ context.Context, seen api.Scope, _ json.RawMessage) (json.RawMessage, error) {
		seenSource, frameBytes = seen.Source, seen.Frame.Bytes()
		return json.Marshal(seen)
	}); err != nil {
		t.Fatal(err)
	}
	response, err := server.Dispatch(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != nil || len(response.Result) == 0 || seenSource != "dashboard" || string(frameBytes) != string(raw) {
		t.Fatalf("dashboard dispatch lost source/frame: response=%+v source=%q frame=%q", response, seenSource, frameBytes)
	}
}
