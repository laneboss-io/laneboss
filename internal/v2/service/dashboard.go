package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/dashboard"
)

// dashboardFrame binds an HTTP request to an already authenticated native
// human connection. It deliberately verifies the live peer lifetime rather
// than pretending that HTTP bytes carried Unix credential ancillary data.
type dashboardFrame struct {
	raw  []byte
	conn api.ConnectionContext
}

func (f *dashboardFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }

func (f *dashboardFrame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	if f == nil || connection == nil || f.conn == nil || connection.ID() != f.conn.ID() {
		return serviceError(api.CodeUnauthenticated, "dashboard frame lacks its claimed native connection")
	}
	peer := connection.Peer()
	if peer == nil {
		return serviceError(api.CodeUnauthenticated, "dashboard frame requires the pinned native peer")
	}
	return peer.Alive(ctx)
}

type dashboardSourceKey struct{}

const dashboardBootstrapTTL = time.Minute

type dashboardBootstrap struct {
	binding     dashboard.BootstrapBinding
	nonceDigest api.Digest
}

func withDashboardSource(ctx context.Context) context.Context {
	return context.WithValue(ctx, dashboardSourceKey{}, "dashboard")
}

func dispatchSource(ctx context.Context) string {
	if source, ok := ctx.Value(dashboardSourceKey{}).(string); ok && source != "" {
		return source
	}
	return "cli"
}

// IssueDashboardBootstrap creates the only HTTPS bootstrap selector. The
// issuer is a current human session on one native connection; redemption is
// explicitly pinned to a second fresh human connection so finalization can
// bind its first read authority without rebinding an existing session.
func dashboardNonceDigest(nonce []byte) api.Digest {
	sum := sha256.Sum256(nonce)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func (s *Server) IssueDashboardBootstrap(ctx context.Context, scope api.Scope, redeemID api.ID, browserNonce []byte) (dashboard.BootstrapBinding, error) {
	var empty dashboard.BootstrapBinding
	if scope.Source != "cli" || scope.Connection == nil || scope.Actor.Kind != "human" ||
		scope.Connection.Binding().Class != api.EndpointHuman {
		return empty, serviceError(api.CodeForbidden, "dashboard bootstrap requires the owner human endpoint")
	}
	if scope.Frame == nil {
		return empty, serviceError(api.CodeUnauthenticated, "dashboard bootstrap requires the native verified request frame")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return empty, err
	}
	source, ok := s.deps.Authenticator.(api.ConnectionScopeSource)
	if !ok {
		return empty, api.NotImplemented("lb-v2-identity", "current human connection scope")
	}
	current, err := source.CurrentConnectionScope(ctx, scope.Connection)
	if err != nil {
		return empty, err
	}
	if current.Config != scope.Config || current.Actor != scope.Actor || current.EndpointGeneration != scope.EndpointGeneration {
		return empty, serviceError(api.CodeUnauthenticated, "dashboard bootstrap issuer scope changed")
	}
	if _, err := api.WithReadAuthority(ctx, current); err != nil {
		return empty, err
	}
	if scope.Request.Method != "human.session" || scope.Request.Proof == nil {
		return empty, serviceError(api.CodeUnauthenticated, "dashboard bootstrap requires a human.session proof")
	}
	if len(browserNonce) < 16 {
		return empty, serviceError(api.CodeInvalid, "dashboard bootstrap browser nonce is too short")
	}
	if redeemID == "" || redeemID == scope.Connection.ID() {
		return empty, serviceError(api.CodeConflict, "dashboard bootstrap requires a fresh native redemption connection")
	}
	s.mu.RLock()
	redemption := s.connections[redeemID]
	now := s.deps.Clock.Now().UTC()
	open := 0
	for _, retained := range s.dashboardBootstraps {
		if retained.binding.ConnectionID != redeemID {
			continue
		}
		expires, parseErr := time.Parse(time.RFC3339Nano, string(retained.binding.ExpiresAt))
		if parseErr == nil && now.Before(expires) {
			open++
		}
	}
	s.mu.RUnlock()
	if open >= 8 {
		return empty, serviceError(api.CodeUnavailable, "dashboard bootstrap binding limit reached for native connection")
	}
	if redemption == nil || redemption.Binding().Class != api.EndpointHuman || redemption.Peer() == nil {
		return empty, serviceError(api.CodeUnauthenticated, "dashboard redemption connection is not a live native human endpoint")
	}
	if _, err := redemption.ReadAuthority(ctx); err == nil {
		return empty, serviceError(api.CodeConflict, "dashboard redemption connection already has read authority")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
			return empty, err
		}
	}
	redemptionScope, err := source.CurrentConnectionScope(ctx, redemption)
	if err != nil {
		return empty, err
	}
	if redemptionScope.Config != current.Config || redemptionScope.Actor != current.Actor ||
		redemptionScope.EndpointGeneration != current.EndpointGeneration {
		return empty, serviceError(api.CodeForbidden, "dashboard redemption connection has another human principal")
	}
	identityStore, ok := s.deps.Store.(api.IdentityStore)
	if !ok {
		return empty, api.NotImplemented("lb-v2-service", "dashboard human proof target")
	}
	verifier, ok := s.deps.Authenticator.(api.HumanVerifier)
	if !ok {
		return empty, api.NotImplemented("lb-v2-identity", "dashboard human proof verifier")
	}
	// These lookups originate in the issuer's verified native frame. Preserve
	// its exact frame/connection pair; the returned proof is separately bound
	// to the fresh redemption connection below.
	target, err := identityStore.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return empty, err
	}
	verified, err := verifier.CheckProof(ctx, scope, *scope.Request.Proof, target)
	if err != nil {
		return empty, err
	}
	if verified.ConnectionID != redemption.ID() || verified.PrincipalID != redemptionScope.Actor.ID ||
		verified.EndpointClass != api.EndpointHuman || verified.EndpointGeneration != redemptionScope.EndpointGeneration ||
		verified.Target != target || verified.Ref != *scope.Request.Proof {
		return empty, serviceError(api.CodeUnauthenticated, "dashboard proof was not issued for the fresh redemption connection")
	}
	token, err := wire.NewID()
	if err != nil {
		return empty, err
	}
	now = s.deps.Clock.Now().UTC()
	binding := dashboard.BootstrapBinding{Token: token, Config: current.Config,
		ConnectionID: redeemID, Actor: redemptionScope.Actor,
		EndpointGeneration: redemptionScope.EndpointGeneration,
		ExpiresAt:          api.Timestamp(now.Add(dashboardBootstrapTTL).Format(time.RFC3339Nano)),
		Proof:              *scope.Request.Proof}
	s.mu.Lock()
	if s.dashboardBootstraps == nil {
		s.dashboardBootstraps = make(map[api.ID]dashboardBootstrap)
	}
	for id, retained := range s.dashboardBootstraps {
		expires, parseErr := time.Parse(time.RFC3339Nano, string(retained.binding.ExpiresAt))
		if parseErr != nil || !now.Before(expires) {
			delete(s.dashboardBootstraps, id)
		}
	}
	s.dashboardBootstraps[token] = dashboardBootstrap{binding: binding, nonceDigest: dashboardNonceDigest(browserNonce)}
	s.mu.Unlock()
	return binding, nil
}

func (s *Server) loadDashboardBootstrap(ctx context.Context, token api.ID, nonce []byte, consume bool) (*connectionContext, dashboard.BootstrapBinding, error) {
	var empty dashboard.BootstrapBinding
	if !wire.ValidID(string(token)) {
		return nil, empty, serviceError(api.CodeUnauthenticated, "dashboard bootstrap binding is invalid or expired")
	}
	now := s.deps.Clock.Now().UTC()
	s.mu.Lock()
	entry, ok := s.dashboardBootstraps[token]
	if ok && consume {
		delete(s.dashboardBootstraps, token) // single-use, including failed redemption
	}
	var connection *connectionContext
	if ok {
		if expires, err := time.Parse(time.RFC3339Nano, string(entry.binding.ExpiresAt)); err != nil || !now.Before(expires) {
			ok = false
		} else {
			connection = s.connections[entry.binding.ConnectionID]
		}
	}
	s.mu.Unlock()
	digest := dashboardNonceDigest(nonce)
	if !ok || subtle.ConstantTimeCompare([]byte(entry.nonceDigest), []byte(digest)) != 1 || connection == nil || connection.Binding().Class != api.EndpointHuman || connection.ID() != entry.binding.ConnectionID {
		return nil, empty, serviceError(api.CodeUnauthenticated, "dashboard bootstrap binding is invalid, expired or no longer native")
	}
	if connection.Peer() == nil {
		return nil, empty, serviceError(api.CodeUnauthenticated, "dashboard bootstrap binding has no native peer")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return nil, empty, err
	}
	return connection, entry.binding, nil
}

func (s *Server) redeemDashboardBootstrap(ctx context.Context, token api.ID, nonce []byte) (api.ConnectionContext, dashboard.BootstrapBinding, error) {
	return s.loadDashboardBootstrap(ctx, token, nonce, true)
}

func (s *Server) BootstrapInfo(ctx context.Context, token api.ID, nonce []byte) (dashboard.BootstrapDetails, error) {
	_, binding, err := s.loadDashboardBootstrap(ctx, token, nonce, false)
	if err != nil {
		return dashboard.BootstrapDetails{}, err
	}
	return dashboard.BootstrapDetails{Config: binding.Config, Actor: binding.Actor,
		EndpointGeneration: binding.EndpointGeneration, ExpiresAt: binding.ExpiresAt, Proof: binding.Proof}, nil
}

func (s *Server) dashboardConnection(ctx context.Context, claim *dashboard.SessionClaim) (api.ConnectionContext, *dashboard.BootstrapBinding, error) {
	if claim == nil {
		return nil, nil, serviceError(api.CodeUnauthenticated, "dashboard bootstrap binding is required for human.session")
	}
	if claim.BootstrapToken != "" {
		connection, binding, err := s.redeemDashboardBootstrap(ctx, claim.BootstrapToken, claim.BootstrapNonce)
		if err != nil {
			return nil, nil, err
		}
		return connection, &binding, nil
	}
	if claim.ConnectionID == "" || claim.SessionID == "" {
		return nil, nil, serviceError(api.CodeUnauthenticated, "dashboard session claim is incomplete")
	}
	s.mu.RLock()
	connection := s.connections[claim.ConnectionID]
	s.mu.RUnlock()
	if connection == nil {
		return nil, nil, serviceError(api.CodeUnauthenticated, "dashboard session connection is no longer live")
	}
	authority, err := connection.ReadAuthority(ctx)
	if err != nil {
		return nil, nil, err
	}
	if authority.SessionID != claim.SessionID || authority.ConnectionID != claim.ConnectionID ||
		authority.PrincipalID != claim.Actor.ID || authority.EndpointGeneration != claim.EndpointGeneration {
		return nil, nil, serviceError(api.CodeForbidden, "dashboard cookie claim differs from its committed session")
	}
	return connection, nil, nil
}

func (s *Server) Scope(ctx context.Context, r *http.Request, request api.Request, raw []byte, claim *dashboard.SessionClaim) (api.Scope, error) {
	if r == nil {
		return api.Scope{}, serviceError(api.CodeInvalid, "dashboard transport request is required")
	}
	if request.Config != s.options.Config {
		return api.Scope{}, serviceError(api.CodeForbidden, "dashboard request conflicts with installed configuration")
	}
	framed, err := wire.DecodeRequest(raw)
	if err != nil || !reflect.DeepEqual(framed, request) {
		return api.Scope{}, serviceError(api.CodeIntegrity, "dashboard transport lost the exact request frame")
	}
	if claim != nil && claim.BootstrapToken != "" && request.Method != "human.session" {
		return api.Scope{}, serviceError(api.CodeForbidden, "dashboard bootstrap binding is only valid for human.session")
	}
	if claim == nil && request.Method != "human.session" {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "dashboard staging requires a native session claim")
	}
	connection, bootstrap, err := s.dashboardConnection(ctx, claim)
	if err != nil {
		return api.Scope{}, err
	}
	source, ok := s.deps.Authenticator.(api.ConnectionScopeSource)
	if !ok {
		return api.Scope{}, api.NotImplemented("lb-v2-identity", "current human connection scope")
	}
	scope, err := source.CurrentConnectionScope(ctx, connection)
	if err != nil {
		return api.Scope{}, err
	}
	if scope.Config != request.Config || scope.Actor.Kind != "human" || scope.Connection == nil ||
		scope.EndpointGeneration == 0 || scope.Connection.ID() != connection.ID() {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "dashboard transport returned a foreign human scope")
	}
	if bootstrap != nil && (bootstrap.Config != scope.Config || bootstrap.Actor != scope.Actor ||
		bootstrap.ConnectionID != connection.ID() || bootstrap.EndpointGeneration != scope.EndpointGeneration) {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "dashboard bootstrap binding differs from the current native principal")
	}
	scope.Request, scope.Source, scope.Connection = request, "dashboard", connection
	scope.Frame = &dashboardFrame{raw: append([]byte(nil), raw...), conn: connection}
	if request.Method == "human.session" {
		if request.Proof == nil {
			return api.Scope{}, serviceError(api.CodeUnauthenticated, "human.session requires its issuing operation proof")
		}
		identityStore, ok := s.deps.Store.(api.IdentityStore)
		if !ok {
			return api.Scope{}, api.NotImplemented("lb-v2-service", "dashboard human proof target")
		}
		verifier, ok := s.deps.Authenticator.(api.HumanVerifier)
		if !ok {
			return api.Scope{}, api.NotImplemented("lb-v2-identity", "dashboard human proof verifier")
		}
		target, err := identityStore.AuthorizationTarget(ctx, scope, request)
		if err != nil {
			return api.Scope{}, err
		}
		verified, err := verifier.CheckProof(ctx, scope, *request.Proof, target)
		if err != nil {
			return api.Scope{}, err
		}
		if verified.ConnectionID != connection.ID() || verified.PrincipalID != scope.Actor.ID ||
			verified.EndpointClass != api.EndpointHuman || verified.EndpointGeneration != scope.EndpointGeneration ||
			verified.Target != target || verified.Ref != *request.Proof {
			return api.Scope{}, serviceError(api.CodeUnauthenticated, "human.session proof was issued for another connection or principal")
		}
	}
	return scope, nil
}

func validateDashboardFrame(ctx context.Context, scope api.Scope, request api.Request) error {
	if scope.Source != "dashboard" || scope.Connection == nil || scope.Frame == nil || !reflect.DeepEqual(scope.Request, request) {
		return serviceError(api.CodeIntegrity, "dashboard dispatch scope is not bound to its request")
	}
	framed, err := wire.DecodeRequest(scope.Frame.Bytes())
	if err != nil || !reflect.DeepEqual(framed, request) {
		return serviceError(api.CodeIntegrity, "dashboard dispatch frame differs from its request")
	}
	return scope.Frame.Verify(ctx, scope.Connection)
}

func (s *Server) Dispatch(ctx context.Context, scope api.Scope, request api.Request) (api.Response, error) {
	if err := validateDashboardFrame(ctx, scope, request); err != nil {
		return api.Response{}, err
	}
	dispatchCtx := context.WithValue(withDashboardSource(ctx), requestFrameKey{}, scope.Frame)
	result, current, err := s.dispatch(dispatchCtx, scope.Connection, request)
	if err != nil {
		return api.Response{}, err
	}
	response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID, Result: result}
	if current.ReadView != nil {
		response.LastSeq = current.ReadView.Snapshot().LastSeq
	}
	if len(response.Result) == 0 {
		return api.Response{}, serviceError(api.CodeIntegrity, "dashboard dispatcher returned an empty success")
	}
	return response, nil
}

func (s *Server) dashboardReadScope(ctx context.Context, scope api.Scope, request api.Request) (api.Scope, error) {
	if err := validateDashboardFrame(ctx, scope, request); err != nil {
		return api.Scope{}, err
	}
	source, ok := s.deps.Authenticator.(api.ConnectionScopeSource)
	if !ok {
		return api.Scope{}, api.NotImplemented("lb-v2-identity", "current human connection scope")
	}
	current, err := source.CurrentConnectionScope(ctx, scope.Connection)
	if err != nil {
		return api.Scope{}, err
	}
	if current.Config != scope.Config || current.Actor != scope.Actor || current.EndpointGeneration != scope.EndpointGeneration || current.Actor.Kind != "human" {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "dashboard human connection authority changed")
	}
	current.Request, current.Source, current.Connection, current.Frame = request, "dashboard", scope.Connection, scope.Frame
	current, err = api.WithReadAuthority(ctx, current)
	if err != nil {
		return api.Scope{}, err
	}
	identity, ok := s.deps.Authenticator.(api.IdentityAPI)
	if !ok {
		return api.Scope{}, api.NotImplemented("lb-v2-identity", "dashboard human session read-back")
	}
	verified, err := identity.IdentitySelf(ctx, current, api.Empty{})
	if err != nil {
		return api.Scope{}, err
	}
	if verified.Config != current.Config || verified.Actor != current.Actor || verified.EndpointGeneration != current.EndpointGeneration || verified.PolicyGeneration == 0 {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "identity did not confirm the dashboard session")
	}
	current.PolicyGeneration = verified.PolicyGeneration
	return current, nil
}

func (s *Server) PollEvents(ctx context.Context, scope api.Scope, tail api.EventTailRequest) (api.EventPage, error) {
	if tail.Follow {
		return api.EventPage{}, serviceError(api.CodeInvalid, "dashboard liveness accepts bounded event batches only")
	}
	current, err := s.dashboardReadScope(ctx, scope, scope.Request)
	if err != nil {
		return api.EventPage{}, err
	}
	return s.deps.Store.Events(ctx, current, tail)
}

func (s *Server) ReplayCompleted(ctx context.Context, scope api.Scope, request api.Request) (api.Response, error) {
	if request.Proof == nil {
		return api.Response{}, serviceError(api.CodeForbidden, "completed replay requires the original proof selector")
	}
	current, err := s.dashboardReadScope(ctx, scope, request)
	if err != nil {
		return api.Response{}, err
	}
	receipts, ok := s.deps.Store.(api.ReceiptStore)
	if !ok {
		return api.Response{}, api.NotImplemented("lb-v2-service", "completed mutation receipt lookup")
	}
	key := api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
	receipt, err := receipts.LookupReceipt(ctx, current, key)
	if err != nil {
		return api.Response{}, err
	}
	if receipt.Config != current.Config || receipt.Actor != current.Actor || receipt.Key != key || receipt.Reply == nil ||
		!wire.SameJSON(receipt.RawRequest, scope.Frame.Bytes()) || receipt.Operation.Status == "pending" || receipt.Operation.Status == "running" {
		return api.Response{}, serviceError(api.CodeConflict, "completed receipt does not match the original dashboard request")
	}
	response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID, LastSeq: receipt.LastSeq}
	if receipt.Reply.Error != nil {
		response.Error = receipt.Reply.Error
		return response, nil
	}
	if len(receipt.Reply.Result) == 0 {
		return api.Response{}, serviceError(api.CodeIntegrity, "completed receipt has no retained result")
	}
	response.Result = append(json.RawMessage(nil), receipt.Reply.Result...)
	return response, nil
}

// AuthorizeEnrollment is intentionally an owner-operated wait. The protected
// helper must open the browser ceremony before the HTTP adapter can forward
// any challenge or attestation bytes; no request header or cookie can mint it.
func (s *Server) AuthorizeEnrollment(context.Context, *http.Request) (api.EnrollmentCeremonyRequest, error) {
	if s.options.AdminEnrollment == nil {
		return api.EnrollmentCeremonyRequest{}, api.NotImplemented("lb-v2-admin", "protected browser enrollment ceremony")
	}
	return api.EnrollmentCeremonyRequest{}, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-admin",
		Message: "owner-confirmed browser enrollment ceremony is not open", Instead: "The owner must open the protected administrator ceremony before enrolling a browser key."}
}

var _ dashboard.HumanTransport = (*Server)(nil)
var _ dashboard.HumanLivenessTransport = (*Server)(nil)
var _ dashboard.HumanReceiptTransport = (*Server)(nil)
var _ dashboard.BrowserEnrollmentTransport = (*Server)(nil)
