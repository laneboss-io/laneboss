package dashboard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	webv2 "laneboss.io/laneboss/web/v2"
)

const (
	sessionCookieName = "laneboss_session"
	maxSSEFrames      = 256
	maxSSEBytes       = 4 * 1024 * 1024
	ssePollInterval   = time.Second
)

type browserSession struct {
	ID            api.ID
	CookieToken   string
	Config        string
	expiresAt     time.Time
	idleExpiresAt time.Time
	Scope         api.Scope
}

// ConfigureHTTP pins the configuration, origin, and RP ID for the human HTTPS UI.
func (s *Service) ConfigureHTTP(config, origin, rpID string) error {
	if !configPattern.MatchString(config) {
		return invalidErr("invalid dashboard configuration name", "Provide a valid configuration name.")
	}
	if origin == "" {
		return invalidErr("dashboard origin is required", "Provide a fixed origin URL.")
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return invalidErr("invalid dashboard origin URL", "Use a fixed origin such as https://127.0.0.1:8443.")
	}
	if strings.Contains(origin, "*") {
		return invalidErr("wildcard origin is forbidden", "Pin an exact origin URL.")
	}
	if rpID != "" && rpID != parsed.Hostname() {
		return invalidErr("dashboard RP ID differs from origin", "Use the installed RP ID.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config != "" && (s.config != config || s.origin != strings.TrimRight(origin, "/") || s.rpID != parsed.Hostname()) {
		return conflictErr("dashboard HTTP pins are already installed", "Create a new handler for another installation.")
	}
	s.config = config
	s.origin = strings.TrimRight(origin, "/")
	s.host = parsed.Host
	if rpID != "" {
		s.rpID = rpID
	} else {
		s.rpID = parsed.Hostname()
	}
	return nil
}

// RevokeSession immediately revokes a human session by its record ID.
func (s *Service) RevokeSession(sessionID api.ID) {
	s.evictSession(sessionID, true)
}

func clearSessionCookie(w http.ResponseWriter, err error) {
	if asAPIError(err) != nil && asAPIError(err).Code == api.CodeUnauthenticated {
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
}

func (s *Service) authenticateCookie(ctx context.Context, r *http.Request, _ bool) (*browserSession, error) {
	// Reject any attempt to supply actor/session authority via headers.
	for _, forbiddenHdr := range []string{"X-Laneboss-Actor", "X-Actor", "X-Laneboss-Role", "Authorization"} {
		if r.Header.Get(forbiddenHdr) != "" {
			return nil, forbiddenErr("header-supplied identity labels are forbidden", "Use the verified session cookie.")
		}
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil, unauthErr("missing human session cookie", "Authenticate via human.challenge, human.confirm and human.session.")
	}
	s.mu.Lock()
	if _, isRecordID := s.sessionsByID[api.ID(c.Value)]; isRecordID {
		s.mu.Unlock()
		return nil, unauthErr("session record ID is not a valid cookie token", "Use the HttpOnly cookie issued by human.session.")
	}
	bs, ok := s.sessionsByToken[c.Value]
	var revoked bool
	if ok {
		_, revoked = s.revokedSessions[bs.ID]
	}
	if !ok || revoked {
		s.mu.Unlock()
		return nil, unauthErr("unknown or revoked human session", "Establish a new human.session.")
	}
	if s.config != "" && bs.Config != s.config {
		s.mu.Unlock()
		return nil, forbiddenErr("session configuration mismatch", "Use a session bound to this configuration.")
	}
	now := s.now().UTC()
	// Idle activity is committed/refreshed by identity on the same connection.
	// The cached idle deadline can be older than a successful service read.
	if !now.Before(bs.expiresAt) {
		delete(s.sessionsByToken, c.Value)
		delete(s.sessionsByID, bs.ID)
		s.mu.Unlock()
		return nil, unauthErr("human session expired", "Reauthenticate to start a new human.session.")
	}
	clone := *bs
	s.mu.Unlock()
	// Reload the last identity-committed deadlines. Cookie checks never
	// refresh them, and a stale local idle snapshot cannot reject active work.
	scoped, err := s.snapshotHumanScope(ctx, clone.Scope)
	if err != nil {
		return nil, err
	}
	if scoped.ReadAuthority.SessionID != clone.ID {
		return nil, unauthErr("cookie session differs from live authority", "Reauthenticate.")
	}
	idle, idleErr := parseTimestamp(scoped.ReadAuthority.IdleExpiresAt)
	expiry, expErr := parseTimestamp(scoped.ReadAuthority.ExpiresAt)
	if idleErr != nil || expErr != nil || !s.now().Before(idle) || !s.now().Before(expiry) {
		return nil, unauthErr("human session expired", "Reauthenticate.")
	}
	clone.Scope, clone.idleExpiresAt, clone.expiresAt = scoped, idle, expiry
	return &clone, nil
}

func statusForError(err *api.Error) int {
	if err == nil {
		return http.StatusOK
	}
	switch err.Code {
	case api.CodeInvalid, api.CodeCursorExpired:
		return http.StatusBadRequest
	case api.CodeUnauthenticated:
		return http.StatusUnauthorized
	case api.CodeForbidden:
		return http.StatusForbidden
	case api.CodeNotFound:
		return http.StatusNotFound
	case api.CodeConflict, api.CodeIdempotencyConflict, api.CodeBudget, api.CodeCancelled:
		return http.StatusConflict
	case api.CodeIntegrity:
		return http.StatusInternalServerError
	default:
		return http.StatusServiceUnavailable
	}
}

func asAPIError(err error) *api.Error {
	if err == nil {
		return nil
	}
	var typed *api.Error
	if errors.As(err, &typed) {
		return typed
	}
	return unavailableErr("dashboard operation failed", "Inspect the service status and retry.")
}

func writeRPCResponse(w http.ResponseWriter, status int, resp api.Response) {
	presenceHeaders(w, resp)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeErrorResponse(w http.ResponseWriter, reqID api.ID, err error) {
	typed := asAPIError(err)
	if reqID == "" {
		reqID = "req-http-error"
	}
	resp := api.Response{
		Protocol:  api.Protocol,
		Schema:    api.SchemaVersion,
		RequestID: reqID,
		LastSeq:   0,
		Error:     typed,
	}
	writeRPCResponse(w, statusForError(typed), resp)
}

func writeJSONResult(w http.ResponseWriter, value any) {
	presenceHeaders(w, value)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(value)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src "+webv2.ScriptSources()+"; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}

func (s *Service) checkHostAndOrigin(r *http.Request, requireOrigin bool) error {
	s.mu.Lock()
	pinnedHost := s.host
	pinnedOrigin := s.origin
	configured := s.config != "" && pinnedOrigin != "" && pinnedHost != "" && s.rpID != ""
	s.mu.Unlock()

	if !configured {
		return &api.Error{Code: api.CodePrerequisite, Owner: ownerName, Message: "dashboard HTTP pins are not installed", Instead: "Configure the protected HTTPS origin, RP ID and configuration before serving."}
	}
	if r.Host != pinnedHost {
		return forbiddenErr("request Host header does not match pinned dashboard host", "Connect through the pinned dashboard origin.")
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return forbiddenErr("cross-site request rejected", "Issue requests only from the pinned dashboard origin.")
	}
	originHdr := r.Header.Get("Origin")
	if requireOrigin {
		if originHdr == "" {
			return forbiddenErr("Origin header is required for POST requests", "Send the pinned Origin header.")
		}
		if originHdr != pinnedOrigin {
			return forbiddenErr("Origin header does not match pinned dashboard origin", "Use the exact pinned dashboard origin.")
		}
	} else if originHdr != "" {
		if originHdr != pinnedOrigin {
			return forbiddenErr("Origin header mismatch", "Use the exact pinned dashboard origin.")
		}
	}
	return nil
}

// ServeHTTP implements the human-only dashboard HTTP/SSE routes and POST /api/v2/rpc.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	requireOrigin := r.Method == http.MethodPost
	if err := s.checkHostAndOrigin(r, requireOrigin); err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	if r.URL.Path == "/api/v2/bootstrap" {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			w.Header().Set("Allow", http.MethodGet)
			writeErrorResponse(w, "", invalidErr("bootstrap preview requires GET without a query", "Use GET /api/v2/bootstrap."))
			return
		}
		infoTransport, ok := s.deps.Transport.(BootstrapInfoTransport)
		if !ok {
			writeErrorResponse(w, "", api.NotImplemented("lb-v2-service", "dashboard bootstrap preview"))
			return
		}
		nonce, err := base64.RawURLEncoding.DecodeString(r.Header.Get(BootstrapNonceHeader))
		if err != nil || len(nonce) < 16 {
			writeErrorResponse(w, "", unauthErr("dashboard bootstrap nonce is missing or invalid", "Use the browser-bound sign-in handoff."))
			return
		}
		info, err := infoTransport.BootstrapInfo(r.Context(), api.ID(r.Header.Get(BootstrapHeader)), nonce)
		if err != nil {
			writeErrorResponse(w, "", err)
			return
		}
		writeJSONResult(w, info)
		return
	}
	if r.URL.Path == "/enroll" || strings.HasPrefix(r.URL.Path, "/api/v2/enrollment/") {
		s.handleEnrollment(w, r)
		return
	}

	if r.URL.Path == "/" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeErrorResponse(w, "", invalidErr("only GET is permitted on /", "Use GET /."))
			return
		}
		if r.URL.RawQuery != "" {
			writeErrorResponse(w, "", invalidErr("query parameters are not accepted on /", "Open / without query parameters."))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(webv2.Page())
		return
	}

	if r.URL.Path == "/api/v2/rpc" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeErrorResponse(w, "", invalidErr("only POST is permitted on /api/v2/rpc", "Use POST /api/v2/rpc."))
			return
		}
		s.handleHTTPRPC(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeErrorResponse(w, "", invalidErr("only GET is permitted on read-only routes", "Use GET for read views or POST /api/v2/rpc."))
		return
	}

	method := api.Method("dashboard." + strings.TrimPrefix(r.URL.Path, "/api/v2/"))
	if r.URL.Path == "/api/v2/events" {
		method = "event.tail"
	}
	if r.URL.Path == "/api/v2/humans" {
		method = "human.pending"
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v2/") || method != "event.tail" && !isAllowedDashboardRead(method) {
		writeErrorResponse(w, "", &api.Error{Code: api.CodeNotFound, Message: "dashboard route not found", Owner: ownerName})
		return
	}
	sess, err := s.authenticateCookie(r.Context(), r, true)
	if err != nil {
		clearSessionCookie(w, err)
		writeErrorResponse(w, "", err)
		return
	}

	if method == "event.tail" {
		s.handleSSEEvents(w, r, sess.Scope, sess.CookieToken)
		return
	}
	query, err := parseHTTPDashboardQuery(r.URL.RawQuery)
	if err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	var params any = query
	if method == "human.pending" {
		if r.URL.RawQuery != "" {
			writeErrorResponse(w, "", invalidErr("human registrations accept no query", "Use the exact registrations route."))
			return
		}
		params = api.Empty{}
	}
	readReq, raw, err := newReadRequest(sess.Config, method, params)
	if err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	scope, err := s.httpScope(r.Context(), r, readReq, raw, sess)
	if err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	dispatchCtx, provenance := captureHTTPPresence(r.Context())
	response, err := s.deps.Transport.Dispatch(dispatchCtx, scope, readReq)
	if err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	if response.Error != nil {
		writeErrorResponse(w, readReq.RequestID, response.Error)
		return
	}
	if len(response.Result) == 0 || response.Protocol != api.Protocol || response.Schema != api.SchemaVersion || response.RequestID != readReq.RequestID {
		writeErrorResponse(w, "", integrityErr("invalid service read response", "Inspect the service."))
		return
	}
	presenceHeaders(w, map[string]any{"simulated_presence": sessionPresence(sess)})
	if err := applyHTTPPresence(w, method, provenance); err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	writeJSONResult(w, response.Result)
}

func parseHTTPDashboardQuery(rawQuery string) (api.DashboardQuery, error) {
	q := api.DashboardQuery{Limit: defaultPageLimit}
	if rawQuery == "" {
		return q, nil
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return q, invalidErr("malformed query string", "Provide valid URL query parameters.")
	}
	for k, list := range vals {
		if len(list) != 1 {
			return q, invalidErr("duplicate or empty query parameter", "Provide each query parameter at most once.")
		}
		v := list[0]
		switch k {
		case "life_id":
			q.LifeID = api.ID(v)
		case "run":
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil || u == 0 || u > maxSafeInt {
				return q, invalidErr("invalid run query parameter", "Provide a positive integer run.")
			}
			q.Run = api.RunNumber(u)
		case "level":
			lvl, err := strconv.Atoi(v)
			if err != nil || lvl < 3 || lvl > 6 {
				return q, invalidErr("invalid level query parameter", "Specify level 3, 4, 5 or 6.")
			}
			q.Level = lvl
		case "driver":
			q.Driver = api.Driver(v)
		case "since":
			q.Since = api.Timestamp(v)
		case "until":
			q.Until = api.Timestamp(v)
		case "cursor":
			q.Cursor = v
		case "limit":
			lim, err := strconv.Atoi(v)
			if err != nil || lim < 1 || lim > maxPageLimit {
				return q, invalidErr("limit must be between 1 and 200", "Specify limit in 1..200.")
			}
			q.Limit = lim
		default:
			return q, invalidErr("unknown query parameter", "Use only documented DashboardQuery parameters.")
		}
	}
	if err := validateQuery(q); err != nil {
		return q, err
	}
	return q, nil
}

type sseCursorPayload struct {
	Config  string        `json:"c"`
	ActorID string        `json:"a"`
	LifeID  api.ID        `json:"l"`
	Run     api.RunNumber `json:"r"`
	Until   api.EventKind `json:"u"`
	LastSeq api.Sequence  `json:"s"`
}

func (h *Service) hmacSign(raw []byte) string {
	mac := hmac.New(sha256.New, h.cursorKey[:])
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) buildSSECursor(scope api.Scope, req api.EventTailRequest, seq api.Sequence) string {
	p := sseCursorPayload{
		Config:  scope.Config,
		ActorID: string(scope.Actor.ID),
		LifeID:  req.LifeID,
		Run:     req.Run,
		Until:   req.Until,
		LastSeq: seq,
	}
	raw, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + s.hmacSign(raw)
}

func (s *Service) parseSSECursor(scope api.Scope, req api.EventTailRequest, cursor string) (api.Sequence, error) {
	if cursor == "" {
		return req.Since, nil
	}
	if req.Since != 0 {
		return 0, invalidErr("cursor cannot be combined with since", "Pass either cursor or since, not both.")
	}
	parts := strings.Split(cursor, ".")
	if len(parts) != 2 {
		return 0, invalidErr("malformed event stream cursor", "Reopen the event stream without a cursor.")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !hmac.Equal([]byte(parts[1]), []byte(s.hmacSign(raw))) {
		return 0, invalidErr("invalid event stream cursor signature", "Reopen the event stream without a cursor.")
	}
	var p sseCursorPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, invalidErr("corrupt event stream cursor", "Reopen the event stream without a cursor.")
	}
	if p.Config != scope.Config || p.ActorID != string(scope.Actor.ID) {
		return 0, invalidErr("event cursor principal or configuration mismatch", "Use a cursor from the same human session.")
	}
	if p.LifeID != req.LifeID || p.Run != req.Run || p.Until != req.Until {
		return 0, invalidErr("event cursor filter mismatch", "Keep the same life_id, run and until filters when resuming from a cursor.")
	}
	return p.LastSeq, nil
}

func (s *Service) handleSSEEvents(w http.ResponseWriter, r *http.Request, scope api.Scope, cookieToken string) {
	if cookieToken == "" {
		writeErrorResponse(w, "", unauthErr("SSE requires a session cookie", "Establish human.session."))
		return
	}
	if r.URL.RawQuery != "" {
		vals, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			writeErrorResponse(w, "", invalidErr("malformed event query parameters", "Use valid URL query parameters."))
			return
		}
		var tailReq api.EventTailRequest
		for k, list := range vals {
			if len(list) != 1 {
				writeErrorResponse(w, "", invalidErr("duplicate query parameter", "Provide each parameter once."))
				return
			}
			v := list[0]
			switch k {
			case "life_id":
				if !validID(api.ID(v)) {
					writeErrorResponse(w, "", invalidErr("invalid life_id", "Provide a valid life_id."))
					return
				}
				tailReq.LifeID = api.ID(v)
			case "run":
				u, err := strconv.ParseUint(v, 10, 64)
				if err != nil || u == 0 || u > maxSafeInt {
					writeErrorResponse(w, "", invalidErr("invalid run number", "Provide a positive integer run."))
					return
				}
				tailReq.Run = api.RunNumber(u)
			case "since":
				u, err := strconv.ParseUint(v, 10, 64)
				if err != nil || u > maxSafeInt {
					writeErrorResponse(w, "", invalidErr("invalid since sequence", "Provide a valid sequence integer."))
					return
				}
				tailReq.Since = api.Sequence(u)
			case "cursor":
				tailReq.Cursor = v
			case "follow":
				b, err := strconv.ParseBool(v)
				if err != nil {
					writeErrorResponse(w, "", invalidErr("invalid follow boolean", "Use true or false."))
					return
				}
				tailReq.Follow = b
			case "until":
				ek := api.EventKind(v)
				if _, ok := api.EventSchemas[ek]; !ok {
					writeErrorResponse(w, "", invalidErr("unknown until event kind", "Use a registered v2 EventKind."))
					return
				}
				tailReq.Until = ek
			case "deadline_ms":
				d, err := strconv.ParseInt(v, 10, 64)
				if err != nil || d < 0 || d > maxSafeInt {
					writeErrorResponse(w, "", invalidErr("invalid deadline_ms", "Provide a nonnegative integer deadline_ms."))
					return
				}
				tailReq.DeadlineMS = d
			default:
				writeErrorResponse(w, "", invalidErr("unknown event query parameter", "Use EventTailRequest parameters only."))
				return
			}
		}
		s.streamSSE(w, r, scope, cookieToken, tailReq)
		return
	}
	s.streamSSE(w, r, scope, cookieToken, api.EventTailRequest{})
}

func (s *Service) streamSSE(w http.ResponseWriter, r *http.Request, scope api.Scope, cookieToken string, tailReq api.EventTailRequest) {
	if cookieToken == "" {
		writeErrorResponse(w, "", unauthErr("SSE requires a session cookie", "Establish human.session."))
		return
	}
	if lastID := strings.TrimSpace(r.Header.Get("Last-Event-ID")); lastID != "" {
		if tailReq.Cursor != "" && tailReq.Cursor != lastID {
			writeErrorResponse(w, "", invalidErr("Last-Event-ID conflicts with cursor query parameter", "Supply a single consistent cursor."))
			return
		}
		tailReq.Cursor = lastID
		tailReq.Since = 0 // EventSource reconnect supersedes its original URL offset.
	}
	sinceSeq, err := s.parseSSECursor(scope, tailReq, tailReq.Cursor)
	if err != nil {
		writeErrorResponse(w, "", err)
		return
	}

	// The event.tail dispatcher authorizes the selected life/run and pins
	// its read snapshot before any stream headers are written.
	// Probe initial events before writing 200 text/event-stream headers so store failures return proper HTTP status.
	initialEvents, err := s.sseBatch(r.Context(), r, scope, cookieToken, tailReq, sinceSeq)
	if err != nil {
		clearSessionCookie(w, err)
		writeErrorResponse(w, "", err)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErrorResponse(w, "", unavailableErr("streaming unsupported by response writer", "Use an HTTP/1.1 or HTTP/2 streaming connection."))
		return
	}

	reqHex, _ := randomHex(16)
	reqID := api.ID("req-sse-" + reqHex)

	simulated := scope.ReadAuthority != nil && scope.ReadAuthority.SimulatedPresence
	if cookieToken != "" {
		s.mu.Lock()
		simulated = sessionPresence(s.sessionsByToken[cookieToken])
		s.mu.Unlock()
	}
	presenceHeaders(w, map[string]any{"simulated_presence": simulated, "events": initialEvents})
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var frameIndex uint64
	var sentBytes int
	lastCursor := tailReq.Cursor
	if lastCursor == "" {
		lastCursor = s.buildSSECursor(scope, tailReq, sinceSeq)
	}

	writeFrame := func(frame api.StreamFrame) error {
		raw, err := json.Marshal(frame)
		if err != nil {
			return err
		}
		if frameIndex > maxSSEFrames || sentBytes+len(raw) > maxSSEBytes {
			overflowFrame := api.StreamFrame{
				RequestID: reqID,
				Index:     frameIndex + 1,
				Cursor:    lastCursor,
				End:       true,
				Error:     unavailableErr("SSE stream queue limit exceeded", "Reconnect using Last-Event-ID cursor."),
			}
			ob, _ := json.Marshal(overflowFrame)
			_, _ = fmt.Fprintf(w, "id: %s\ndata: %s\n\n", lastCursor, ob)
			flusher.Flush()
			return errors.New("stream overflow")
		}
		sentBytes += len(raw)
		_, werr := fmt.Fprintf(w, "id: %s\ndata: %s\n\n", frame.Cursor, raw)
		if werr != nil {
			return werr
		}
		flusher.Flush()
		return nil
	}

	emitBatch := func(events []api.Event) (bool, error) {
		for _, ev := range events {
			if ev.Seq <= sinceSeq {
				continue
			}
			sinceSeq = ev.Seq
			if tailReq.LifeID != "" && ev.LifeID != tailReq.LifeID {
				continue
			}
			if tailReq.Run != 0 && ev.Run != tailReq.Run {
				continue
			}
			lastCursor = s.buildSSECursor(scope, tailReq, sinceSeq)
			frameIndex++
			evCopy := ev
			frame := api.StreamFrame{
				RequestID: reqID,
				Index:     frameIndex,
				Cursor:    lastCursor,
				Event:     &evCopy,
				End:       false,
			}
			if err := writeFrame(frame); err != nil {
				return false, err
			}
			// Only an authentic service-origin event for the selected life and run satisfies until.
			if tailReq.Until != "" && ev.Origin == "service" && ev.Kind == tailReq.Until {
				if (tailReq.LifeID == "" || ev.LifeID == tailReq.LifeID) && (tailReq.Run == 0 || ev.Run == tailReq.Run) {
					frameIndex++
					endFrame := api.StreamFrame{
						RequestID: reqID,
						Index:     frameIndex,
						Cursor:    lastCursor,
						End:       true,
					}
					_ = writeFrame(endFrame)
					return true, nil
				}
			}
		}
		return false, nil
	}

	done, err := emitBatch(initialEvents)
	if err != nil || done {
		return
	}

	if !tailReq.Follow {
		frameIndex++
		_ = writeFrame(api.StreamFrame{
			RequestID: reqID,
			Index:     frameIndex,
			Cursor:    lastCursor,
			End:       true,
		})
		return
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	if tailReq.DeadlineMS > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(tailReq.DeadlineMS)*time.Millisecond)
		defer cancel()
	}

	ticker := time.NewTicker(ssePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			frameIndex++
			code := api.CodeCancelled
			msg := "event stream cancelled"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				code = api.CodeDeadline
				msg = "event stream deadline exceeded"
			}
			_ = writeFrame(api.StreamFrame{
				RequestID: reqID,
				Index:     frameIndex,
				Cursor:    lastCursor,
				End:       true,
				Error: &api.Error{
					Code:    code,
					Message: msg,
					Instead: "Reconnect with the saved cursor if further events are needed.",
					Owner:   ownerName,
				},
			})
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				continue
			}
			// Each batch rechecks the cookie and live identity without refresh.
			moreEvents, readErr := s.sseBatch(ctx, r, scope, cookieToken, tailReq, sinceSeq)
			if readErr != nil {
				frameIndex++
				_ = writeFrame(api.StreamFrame{
					RequestID: reqID,
					Index:     frameIndex,
					Cursor:    lastCursor,
					End:       true,
					Error:     asAPIError(readErr),
				})
				return
			}
			finished, emitErr := emitBatch(moreEvents)
			if emitErr != nil || finished {
				return
			}
		}
	}
}

func (s *Service) handleHTTPRPC(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeErrorResponse(w, "", invalidErr("Content-Type must be application/json", "Send application/json."))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, api.MaxFrameBytes+1))
	if err != nil {
		writeErrorResponse(w, "", invalidErr("failed to read request body", "Send a valid JSON request."))
		return
	}
	if len(body) == 0 || len(body) > api.MaxFrameBytes {
		writeErrorResponse(w, "", invalidErr("request frame size out of bounds", "Keep request payload within 1..1048576 bytes."))
		return
	}

	var req api.Request
	if err := decodeStrictJSON(body, &req); err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	if !validRequestID(req.RequestID) {
		writeErrorResponse(w, "", invalidErr("invalid request_id", "Provide a valid opaque request_id."))
		return
	}
	if !validRequestID(req.IdempotencyKey) {
		writeErrorResponse(w, req.RequestID, invalidErr("invalid idempotency_key", "Provide a valid opaque idempotency_key."))
		return
	}
	if req.Protocol != api.Protocol || req.Schema != api.SchemaVersion {
		writeErrorResponse(w, req.RequestID, &api.Error{
			Code:    api.CodeVersion,
			Message: "unsupported protocol or schema version",
			Instead: "Use laneboss.rpc.v2 with schema 2.",
			Owner:   ownerName,
		})
		return
	}
	if !configPattern.MatchString(req.Config) {
		writeErrorResponse(w, req.RequestID, invalidErr("invalid config in request envelope", "Specify the bound configuration name."))
		return
	}
	s.mu.Lock()
	boundCfg := s.config
	s.mu.Unlock()
	if boundCfg != "" && req.Config != boundCfg {
		writeErrorResponse(w, req.RequestID, forbiddenErr("request config conflicts with dashboard session config", "Use the bound configuration."))
		return
	}

	spec, exists := api.Methods[req.Method]
	if !exists {
		writeErrorResponse(w, req.RequestID, invalidErr("unknown RPC method", "Use a documented method from the v2 RPC catalog."))
		return
	}

	if err := api.DecodeObject(req.Params, reflect.New(spec.Request).Interface()); err != nil {
		writeErrorResponse(w, req.RequestID, err)
		return
	}

	computedDigest, err := RequestDigest(req.Protocol, req.Schema, req.Config, req.Method, req.Params)
	if err != nil {
		writeErrorResponse(w, req.RequestID, err)
		return
	}
	if !validDigest(req.RequestSHA256) || req.RequestSHA256 != computedDigest {
		writeErrorResponse(w, req.RequestID, invalidErr("request_sha256 does not match canonical JCS request digest", "Compute SHA256(RFC8785-JCS({protocol,schema,config,method,params}))."))
		return
	}

	s.forwardHTTPRPC(w, r, req, body)
}

func isAllowedDashboardMutation(m api.Method) bool {
	switch m {
	case "grants.root", "ticket.issue", "lane.start", "lane.input", "lane.stop", "lane.resume", "lane.mark", "lane.review", "mail.send", "org.change.approve", "human.enroll":
		return true
	default:
		return false
	}
}

func validateProofShape(req api.Request) error {
	if req.Proof == nil {
		return forbiddenErr("operation-bound human proof is required for mutations", "Call human.challenge and human.confirm to obtain a proof.")
	}
	if req.Proof.ID == "" || !validID(req.Proof.ID) {
		return forbiddenErr("invalid proof identifier", "Obtain a valid ProofRef from human.confirm.")
	}
	if !validDigest(req.Proof.RequestSHA256) || req.Proof.RequestSHA256 != req.RequestSHA256 {
		return forbiddenErr("proof request_sha256 does not match request envelope digest", "Bind the challenge and proof to the exact request_sha256.")
	}
	if _, err := parseTimestamp(req.Proof.ExpiresAt); err != nil {
		return invalidErr("invalid proof expires_at timestamp", "Use RFC3339Nano UTC ending with Z.")
	}
	return nil
}
