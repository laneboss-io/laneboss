package dashboard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// SessionClaim identifies an already tracked cookie without exposing its token.
// It is a selector, never authority. Resolve it against the service's live
// protected native connection registry, including the committed session.
// Browser TCP connections may differ; the original native connection may not.
type SessionClaim struct {
	SessionID          api.ID
	BootstrapToken     api.ID
	BootstrapNonce     []byte
	Actor              api.Actor
	ConnectionID       api.ID
	EndpointGeneration api.Generation
}

// BootstrapHeader carries a server-minted, short-lived binding from an
// owner-authenticated native human connection to the first HTTPS session.
// It is a selector for one redemption, never a general bearer authority.
const BootstrapHeader = "X-Laneboss-Dashboard-Bootstrap"

const BootstrapNonceHeader = "X-Laneboss-Dashboard-Nonce"

// BootstrapBinding is returned only to the owner over the authenticated
// native connection that created it. The browser sends Token and its bound
// nonce back over the pinned HTTPS origin; the service rechecks every other
// field from its protected in-memory binding before consuming it.
type BootstrapBinding struct {
	Token              api.ID         `json:"token"`
	Config             string         `json:"config"`
	ConnectionID       api.ID         `json:"connection_id"`
	Actor              api.Actor      `json:"actor"`
	EndpointGeneration api.Generation `json:"endpoint_generation"`
	ExpiresAt          api.Timestamp  `json:"expires_at"`
	Proof              api.ProofRef   `json:"proof"`
}

type BootstrapDetails struct {
	Config             string         `json:"config"`
	Actor              api.Actor      `json:"actor"`
	EndpointGeneration api.Generation `json:"endpoint_generation"`
	ExpiresAt          api.Timestamp  `json:"expires_at"`
	Proof              api.ProofRef   `json:"proof"`
}

type BootstrapInfoTransport interface {
	BootstrapInfo(context.Context, api.ID, []byte) (BootstrapDetails, error)
}

// HumanTransport is an installed service dependency, never browser input.
// Scope resolves a server-owned human connection/cookie context and its exact
// frame without refreshing read-session activity. Dispatch runs the normal
// foreground service dispatcher: current authorization,
// pinned reads, receipt reservation/replay and atomic proof/ticket use. Calling
// a module directly is not an implementation of this port.
// An HTTP frame must not be relabelled as native kernel-verified socket bytes.
type HumanTransport interface {
	Scope(context.Context, *http.Request, api.Request, []byte, *SessionClaim) (api.Scope, error)
	Dispatch(context.Context, api.Scope, api.Request) (api.Response, error)
}

// HumanReceiptTransport can only return an already completed exact receipt,
// after current frame, session, revocation and visibility checks. It must never
// reserve/await/execute a mutation or consume a proof. Missing receipts refuse.
type HumanReceiptTransport interface {
	ReplayCompleted(context.Context, api.Scope, api.Request) (api.Response, error)
}

// HumanLivenessTransport is a separate service-owned capability for passive
// event polling. It verifies the exact current frame, native identity,
// credential/session revocation, deadlines and object ACLs under a serialized
// pinned read. It must not call refreshing Authorize/RefreshReadSession, change
// read-authority generation/deadlines, or consume a proof. No public request
// field selects this path. Missing capability is an owning failure.
type HumanLivenessTransport interface {
	PollEvents(context.Context, api.Scope, api.EventTailRequest) (api.EventPage, error)
}

func (s *Service) httpScope(ctx context.Context, r *http.Request, req api.Request, raw []byte, session *browserSession) (api.Scope, error) {
	if s.deps.Transport == nil {
		return api.Scope{}, api.NotImplemented("lb-v2-service", "dashboard installed human transport")
	}
	bootstrapToken := r.Header.Get(BootstrapHeader)
	if bootstrapToken != "" && req.Method != "human.session" {
		return api.Scope{}, forbiddenErr("dashboard bootstrap binding is only valid for human.session", "Redeem the binding with human.session.")
	}
	if bootstrapToken != "" && session != nil {
		return api.Scope{}, forbiddenErr("dashboard bootstrap binding conflicts with a session cookie", "Use one explicit bootstrap binding.")
	}
	var claim *SessionClaim
	if session != nil {
		claim = &SessionClaim{SessionID: session.ID, Actor: session.Scope.Actor,
			ConnectionID: session.Scope.Connection.ID(), EndpointGeneration: session.Scope.EndpointGeneration}
	} else if bootstrapToken != "" {
		nonce, err := base64.RawURLEncoding.DecodeString(r.Header.Get(BootstrapNonceHeader))
		if err != nil || len(nonce) < 16 {
			return api.Scope{}, unauthErr("dashboard bootstrap nonce is missing or invalid", "Use the browser-bound sign-in handoff.")
		}
		claim = &SessionClaim{BootstrapToken: api.ID(bootstrapToken), BootstrapNonce: nonce}
	}
	scope, err := s.deps.Transport.Scope(ctx, r, req, raw, claim)
	if err != nil {
		return api.Scope{}, err
	}
	if scope.Config != req.Config || scope.Source != "dashboard" || scope.Actor.Kind != "human" ||
		scope.Connection == nil || scope.Frame == nil || !reflect.DeepEqual(scope.Request, req) ||
		!bytes.Equal(scope.Frame.Bytes(), raw) {
		return api.Scope{}, unauthErr("HTTP transport did not bind the exact human request", "Use the installed human transport.")
	}
	if session != nil && (scope.Actor != session.Scope.Actor || scope.Connection.ID() != session.Scope.Connection.ID() ||
		scope.EndpointGeneration != session.Scope.EndpointGeneration) {
		return api.Scope{}, forbiddenErr("cookie belongs to another human connection", "Reauthenticate on this connection.")
	}
	return scope, nil
}

// trackHumanSession retains only an already committed identity session. It
// cannot mint authority, extend a deadline or substitute the session ID for
// the authenticated principal.
func (s *Service) trackHumanSession(ctx context.Context, scope api.Scope, hs api.HumanSession) (string, error) {
	scoped, err := s.currentHumanScope(ctx, scope)
	if err != nil {
		return "", err
	}
	authority := scoped.ReadAuthority
	replyIdle, replyErr := parseTimestamp(hs.IdleExpiresAt)
	currentIdle, currentErr := parseTimestamp(authority.IdleExpiresAt)
	if hs.ID != authority.SessionID || hs.Config != scoped.Config || hs.ExpiresAt != authority.ExpiresAt ||
		replyErr != nil || currentErr != nil || replyIdle.After(currentIdle) || hs.SimulatedPresence != authority.SimulatedPresence {
		return "", integrityErr("session reply differs from committed live authority", "Preserve the service receipt.")
	}
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	expiry, _ := parseTimestamp(hs.ExpiresAt)
	idle := currentIdle
	bs := &browserSession{ID: hs.ID, CookieToken: "tok-" + token, Config: hs.Config, Scope: scoped,
		expiresAt: expiry, idleExpiresAt: idle}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepSessionsLocked(s.now())
	if s.config != "" && s.config != hs.Config {
		return "", forbiddenErr("session configuration mismatch", "Use the bound configuration.")
	}
	if current := s.sessionsByID[hs.ID]; current != nil && current.Scope.Actor == scoped.Actor &&
		current.Scope.Connection.ID() == scoped.Connection.ID() && current.Scope.EndpointGeneration == scoped.EndpointGeneration {
		current.Scope, current.expiresAt, current.idleExpiresAt = scoped, expiry, idle
		return current.CookieToken, nil
	}
	if current := s.sessionsByID[hs.ID]; current != nil {
		delete(s.sessionsByToken, current.CookieToken)
	}
	s.sessionsByToken[bs.CookieToken], s.sessionsByID[bs.ID] = bs, bs
	return bs.CookieToken, nil
}

func newReadRequest(config string, method api.Method, params any) (api.Request, []byte, error) {
	rawParams, err := json.Marshal(params)
	if err != nil {
		return api.Request{}, nil, err
	}
	id, err := randomHex(16)
	if err != nil {
		return api.Request{}, nil, err
	}
	req := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: config, Method: method,
		RequestID: api.ID("req-" + id), IdempotencyKey: api.ID("read-" + id), Params: rawParams}
	req.RequestSHA256, err = api.RequestDigest(req)
	if err != nil {
		return api.Request{}, nil, err
	}
	raw, err := json.Marshal(req)
	return req, raw, err
}

func (s *Service) forwardHTTPRPC(w http.ResponseWriter, r *http.Request, req api.Request, raw []byte) {
	for _, header := range []string{"X-Laneboss-Actor", "X-Actor", "X-Laneboss-Role", "Authorization"} {
		if r.Header.Get(header) != "" {
			writeErrorResponse(w, req.RequestID, forbiddenErr("header-supplied identity labels are forbidden", "Use the protected human endpoint."))
			return
		}
	}
	staging := req.Method == "human.challenge" || req.Method == "human.confirm" || req.Method == "human.session"
	bootstrapToken := r.Header.Get(BootstrapHeader)
	if bootstrapToken != "" && req.Method != "human.session" {
		writeErrorResponse(w, req.RequestID, forbiddenErr("dashboard bootstrap binding is only valid for human.session", "Redeem the binding with human.session."))
		return
	}
	if bootstrapToken != "" {
		if _, err := r.Cookie(sessionCookieName); err == nil {
			writeErrorResponse(w, req.RequestID, forbiddenErr("dashboard bootstrap binding conflicts with a session cookie", "Use one explicit bootstrap binding."))
			return
		}
	}
	if !staging && !isAllowedDashboardMutation(req.Method) && !isAllowedDashboardRead(req.Method) {
		writeErrorResponse(w, req.RequestID, forbiddenErr("method is not exposed on the dashboard", "Use a documented human method."))
		return
	}
	var session *browserSession
	var err error
	needsSession := !staging
	if _, cookieErr := r.Cookie(sessionCookieName); cookieErr == nil {
		needsSession = true
	}
	if needsSession {
		session, err = s.authenticateCookie(r.Context(), r, false)
		if err != nil {
			clearSessionCookie(w, err)
			if !staging || asAPIError(err).Code != api.CodeUnauthenticated {
				writeErrorResponse(w, req.RequestID, err)
				return
			}
			// The deleted cookie must not reach the bootstrap transport either.
			r = r.Clone(r.Context())
			cookies := r.Cookies()
			r.Header.Del("Cookie")
			for _, cookie := range cookies {
				if cookie.Name != sessionCookieName {
					r.AddCookie(cookie)
				}
			}
			session = nil
		}
		if session != nil && req.Config != session.Config {
			writeErrorResponse(w, req.RequestID, forbiddenErr("envelope configuration differs from cookie", "Use the bound configuration."))
			return
		}
	}
	if req.Method != "human.session" && (staging || !api.Methods[req.Method].Mutation) && req.Proof != nil {
		writeErrorResponse(w, req.RequestID, invalidErr("method does not accept an envelope proof", "Omit proof."))
		return
	}
	var expiredProof bool
	if req.Method == "human.session" || isAllowedDashboardMutation(req.Method) {
		// Root start uses the separately issued ticket, never envelope proof.
		if req.Method != "lane.start" {
			if err := validateProofShape(req); err != nil {
				writeErrorResponse(w, req.RequestID, err)
				return
			}
			expires, _ := parseTimestamp(req.Proof.ExpiresAt)
			expiredProof = !s.now().Before(expires)
		} else if req.Proof != nil {
			writeErrorResponse(w, req.RequestID, invalidErr("root start does not accept an envelope proof", "Use a human-issued root ticket."))
			return
		}
	}
	scope, err := s.httpScope(r.Context(), r, req, raw, session)
	if err != nil {
		writeErrorResponse(w, req.RequestID, err)
		return
	}
	// No local receipt cache, proof consumption or successful module fallback.
	dispatchCtx, provenance := captureHTTPPresence(r.Context())
	var response api.Response
	if expiredProof {
		replayer, ok := s.deps.Transport.(HumanReceiptTransport)
		if !ok {
			writeErrorResponse(w, req.RequestID, forbiddenErr("human proof expired", "Confirm the operation again."))
			return
		}
		response, err = replayer.ReplayCompleted(r.Context(), scope, req)
	} else {
		response, err = s.deps.Transport.Dispatch(dispatchCtx, scope, req)
	}
	if err != nil {
		writeErrorResponse(w, req.RequestID, err)
		return
	}
	if response.Protocol != api.Protocol || response.Schema != api.SchemaVersion || response.RequestID != req.RequestID ||
		(response.Error == nil) == (len(response.Result) == 0) {
		writeErrorResponse(w, req.RequestID, integrityErr("invalid service RPC response", "Inspect the retained service receipt."))
		return
	}
	if response.Error != nil {
		writeRPCResponse(w, statusForError(response.Error), response)
		return
	}
	if req.Method == "human.session" {
		var hs api.HumanSession
		if err := api.DecodeObject(response.Result, &hs); err != nil {
			writeErrorResponse(w, req.RequestID, err)
			return
		}
		token, err := s.trackHumanSession(r.Context(), scope, hs)
		if err != nil {
			writeErrorResponse(w, req.RequestID, err)
			return
		}
		expiry, _ := parseTimestamp(hs.ExpiresAt)
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", HttpOnly: true,
			Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(expiry.Sub(s.now()) / time.Second)})
	}
	if session != nil {
		presenceHeaders(w, map[string]any{"simulated_presence": sessionPresence(session)})
	}
	if err := applyHTTPPresence(w, req.Method, provenance); err != nil {
		writeErrorResponse(w, req.RequestID, err)
		return
	}
	writeRPCResponse(w, http.StatusOK, response)
}

func sessionPresence(session *browserSession) bool {
	return session != nil && session.Scope.ReadAuthority != nil && session.Scope.ReadAuthority.SimulatedPresence
}

func isAllowedDashboardRead(method api.Method) bool {
	switch method {
	case "dashboard.tree", "dashboard.raw", "dashboard.decisions", "dashboard.refusals",
		"dashboard.plugins", "dashboard.resources", "dashboard.lifecycle", "dashboard.approvals",
		"lane.status", "lane.list", "mail.list", "org.change.get", "operation.get", "store.verify":
		return true
	}
	return false
}

// Each bounded SSE batch uses the explicitly non-refreshing service read.
// Ordinary Dispatch is never a fallback for passive background traffic.
func (s *Service) sseBatch(ctx context.Context, r *http.Request, scope api.Scope, cookie string, tail api.EventTailRequest, since api.Sequence) ([]api.Event, error) {
	if cookie == "" {
		return nil, unauthErr("SSE requires a session cookie", "Establish human.session.")
	}
	tail.Follow, tail.Cursor, tail.Since = false, "", since
	poller, ok := s.deps.Transport.(HumanLivenessTransport)
	if !ok {
		return nil, api.NotImplemented("lb-v2-service", "dashboard non-refreshing event liveness")
	}
	session, err := s.authenticateCookie(ctx, r, false)
	if err != nil {
		return nil, err
	}
	req, raw, err := newReadRequest(scope.Config, "event.tail", tail)
	if err != nil {
		return nil, err
	}
	bound, err := s.httpScope(ctx, r, req, raw, session)
	if err != nil {
		return nil, err
	}
	if bound.Request.Method != "event.tail" || bound.Request.Proof != nil {
		return nil, forbiddenErr("event liveness requires its exact read frame", "Use the installed human event endpoint.")
	}
	var claimed api.EventTailRequest
	if err := api.DecodeObject(bound.Request.Params, &claimed); err != nil {
		return nil, err
	}
	if claimed != tail {
		return nil, invalidErr("event liveness filters differ from the bound frame", "Use the exact event request.")
	}
	page, err := poller.PollEvents(ctx, bound, tail)
	if err != nil {
		return nil, err
	}
	return page.Events, nil
}
