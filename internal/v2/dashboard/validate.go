package dashboard

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/credentialtext"
	"laneboss.io/laneboss/internal/v2/api"
)

const (
	ownerName             = "lb-v2-dashboard"
	maxPageLimit          = 200
	defaultPageLimit      = 100
	maxSafeInt            = (1 << 53) - 1
	maxMailBytes          = 262144
	defaultIdleSessionTTL = 5 * time.Minute
	defaultMaxSessionTTL  = 30 * time.Minute
)

var (
	configPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	secretPattern = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9._~+/=-]{16,}|sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,})`)
)

func invalidErr(msg, instead string) *api.Error {
	return &api.Error{
		Code:    api.CodeInvalid,
		Message: msg,
		Instead: instead,
		Owner:   ownerName,
	}
}

func unauthErr(msg, instead string) *api.Error {
	return &api.Error{
		Code:    api.CodeUnauthenticated,
		Message: msg,
		Instead: instead,
		Owner:   ownerName,
	}
}

func forbiddenErr(msg, instead string) *api.Error {
	return &api.Error{
		Code:    api.CodeForbidden,
		Message: msg,
		Instead: instead,
		Owner:   ownerName,
	}
}

func conflictErr(msg, instead string) *api.Error {
	return &api.Error{
		Code:    api.CodeConflict,
		Message: msg,
		Instead: instead,
		Owner:   ownerName,
	}
}

func unavailableErr(msg, instead string) *api.Error {
	return &api.Error{
		Code:    api.CodeUnavailable,
		Message: msg,
		Instead: instead,
		Owner:   ownerName,
	}
}

func integrityErr(msg, instead string) *api.Error {
	return &api.Error{
		Code:    api.CodeIntegrity,
		Message: msg,
		Instead: instead,
		Owner:   ownerName,
	}
}

func validID(id api.ID) bool {
	return idPattern.MatchString(string(id))
}

func validRequestID(id api.ID) bool {
	return len(id) >= 22 && validID(id)
}

func validDigest(d api.Digest) bool {
	return digestPattern.MatchString(string(d))
}

func parseTimestamp(ts api.Timestamp) (time.Time, error) {
	raw := string(ts)
	if raw == "" || !strings.HasSuffix(raw, "Z") {
		return time.Time{}, fmt.Errorf("timestamp must be UTC RFC3339Nano ending with Z")
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func screenString(s string) string {
	if secretPattern.MatchString(s) || credentialtext.HasCredential(s) {
		return "[withheld]"
	}
	return s
}

func randomHex(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// decodeStrictJSON delegates to api.DecodeObject, enforcing exact field maps,
// UTF-8/surrogate checks, no duplicate keys, no explicit nulls, and no unknown fields.
func decodeStrictJSON(raw []byte, target any) error {
	return api.DecodeObject(raw, target)
}

// CanonicalJCS formats a JSON payload according to RFC 8785 (JCS).
func CanonicalJCS(raw []byte) ([]byte, error) {
	return api.CanonicalJSON(raw)
}

// RequestDigest computes SHA256(RFC8785-JCS({protocol,schema,config,method,params})).
func RequestDigest(protocol string, schema uint32, config string, method api.Method, params json.RawMessage) (api.Digest, error) {
	if len(params) == 0 {
		return "", invalidErr("request params are required", "Provide a JSON params object.")
	}
	return api.RequestDigest(api.Request{
		Protocol: protocol,
		Schema:   schema,
		Config:   config,
		Method:   method,
		Params:   params,
	})
}

// currentHumanScope obtains a new snapshot after identity has refreshed the same
// connection. A session ID, local timer or a copied Scope is never authority.
func (s *Service) currentHumanScope(ctx context.Context, scope api.Scope) (api.Scope, error) {
	return s.humanScope(ctx, scope, true)
}

// snapshotHumanScope checks the current durable connection/session without
// treating background liveness or cookie validation as foreground activity.
// It grants no method access: PollEvents/Dispatch still validate the exact
// current frame and object visibility under their serialized service read.
func (s *Service) snapshotHumanScope(ctx context.Context, scope api.Scope) (api.Scope, error) {
	return s.humanScope(ctx, scope, false)
}

func (s *Service) humanScope(ctx context.Context, scope api.Scope, refresh bool) (api.Scope, error) {
	if scope.Config == "" || !validID(api.ID(scope.Config)) {
		return api.Scope{}, invalidErr("scope config is missing or invalid", "Bind one configuration.")
	}
	s.mu.Lock()
	config := s.config
	s.mu.Unlock()
	if config != "" && config != scope.Config || scope.Request.Config != "" && scope.Request.Config != scope.Config {
		return api.Scope{}, forbiddenErr("scope configuration conflicts with dashboard", "Use the bound configuration.")
	}
	if scope.Actor.Kind != "human" || scope.LaunchID != "" || scope.Actor.LifeID != "" || scope.Actor.Level != 0 || scope.Actor.Role != "" {
		if scope.Actor.Kind == "" {
			return api.Scope{}, unauthErr("human authentication is required", "Establish human.session.")
		}
		return api.Scope{}, forbiddenErr("dashboard requires a verified human", "Use the human endpoint.")
	}
	if s.auth == nil || s.identity == nil {
		return api.Scope{}, api.NotImplemented("lb-v2-identity", "dashboard human authorization")
	}
	if !refresh && scope.Connection == nil {
		return api.Scope{}, unauthErr("live human connection is required", "Establish human.session.")
	}
	policyReloaded := false
	reloadPolicy := func(cause error, target *api.Scope) error {
		if asAPIError(cause).Code != api.CodeConflict || policyReloaded {
			return cause
		}
		policyReloaded = true
		policyScope := *target
		policyScope.PolicyGeneration, policyScope.ReadView = 0, nil
		policy, err := s.deps.Store.Policy(ctx, policyScope)
		if err != nil {
			return wrapStoreErr(err, "current human policy is unavailable")
		}
		if policy.Generation == 0 {
			return integrityErr("current human policy has no generation", "Reload protected policy authority.")
		}
		target.PolicyGeneration = policy.Generation
		return nil
	}
	// A cached caller snapshot may predate an identity refresh on this same
	// connection. Load it before authorization and again after its CAS update.
	if scope.Connection != nil {
		var err error
		scope, err = api.WithReadAuthority(ctx, scope)
		if err != nil {
			return api.Scope{}, err
		}
	}
	// Foreground Authorize validates the current frame and durably refreshes
	// idle activity. Cookie/SSE liveness instead uses the non-refreshing
	// identity and stored-session checks below; its service read checks access.
	if refresh {
		if err := s.auth.Authorize(ctx, scope, scope.Request); err != nil {
			if retryErr := reloadPolicy(err, &scope); retryErr != nil {
				return api.Scope{}, retryErr
			}
			if err := s.auth.Authorize(ctx, scope, scope.Request); err != nil {
				return api.Scope{}, err
			}
		}
	}
	scoped, err := api.WithReadAuthority(ctx, scope)
	if err != nil {
		return api.Scope{}, err
	}
	verified, err := s.identity.IdentitySelf(ctx, scoped, api.Empty{})
	if err != nil {
		if retryErr := reloadPolicy(err, &scoped); retryErr != nil {
			return api.Scope{}, retryErr
		}
		verified, err = s.identity.IdentitySelf(ctx, scoped, api.Empty{})
		if err != nil {
			return api.Scope{}, err
		}
	}
	if verified.Config != scoped.Config || verified.Actor != scoped.Actor || verified.LaunchID != "" ||
		verified.EndpointGeneration != scoped.EndpointGeneration || verified.PolicyGeneration == 0 {
		return api.Scope{}, unauthErr("identity did not confirm the current human scope", "Reauthenticate.")
	}
	// PolicyGeneration is current authorization, not a selected lane's old
	// launch label. Keep all historical launch/grant bytes unchanged.
	scoped.PolicyGeneration = verified.PolicyGeneration
	authority := *scoped.ReadAuthority
	stored, err := s.deps.Store.ReadSession(ctx, scoped, authority.SessionID)
	if err != nil {
		return api.Scope{}, wrapStoreErr(err, "read session is unavailable")
	}
	if stored.Revoked || api.ReadAuthorityFromSession(stored) != authority || authority.Generation == 0 {
		return api.Scope{}, unauthErr("live read session revision differs from the store", "Reauthenticate.")
	}
	expiry, expErr := parseTimestamp(authority.ExpiresAt)
	idle, idleErr := parseTimestamp(authority.IdleExpiresAt)
	now := s.now()
	if expErr != nil || idleErr != nil || idle.After(expiry) || !now.Before(expiry) || !now.Before(idle) {
		return api.Scope{}, unauthErr("human read session expired", "Reauthenticate.")
	}
	s.mu.Lock()
	_, revoked := s.revokedSessions[authority.SessionID]
	if cached := s.sessionsByID[authority.SessionID]; cached != nil && !revoked {
		cached.expiresAt, cached.idleExpiresAt = expiry, idle
		cached.Scope.PolicyGeneration = scoped.PolicyGeneration
	}
	s.mu.Unlock()
	if revoked {
		return api.Scope{}, unauthErr("human session has been revoked", "Reauthenticate.")
	}
	return scoped, nil
}

func (s *Service) authorizeHumanRead(ctx context.Context, scope api.Scope) error {
	_, err := s.currentHumanScope(ctx, scope)
	return err
}

func (s *Service) authorizeHumanSession(ctx context.Context, scope api.Scope, refresh bool) error {
	_, err := s.humanScope(ctx, scope, refresh)
	return err
}

func (s *Service) evictSession(sessionID api.ID, markRevoked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if markRevoked {
		expires := s.now().Add(defaultMaxSessionTTL)
		if bs := s.sessionsByID[sessionID]; bs != nil {
			expires = bs.expiresAt
		}
		s.revokedSessions[sessionID] = expires
	}
	if bs := s.sessionsByID[sessionID]; bs != nil {
		delete(s.sessionsByToken, bs.CookieToken)
		delete(s.sessionsByID, sessionID)
	}
}

// Called with mu held. Idle expiry is verified against live identity rather
// than a stale cached deadline. Absolute expiry cannot be extended.
func (s *Service) sweepSessionsLocked(now time.Time) {
	for token, bs := range s.sessionsByToken {
		if !now.Before(bs.expiresAt) {
			delete(s.sessionsByToken, token)
			if s.sessionsByID[bs.ID] == bs {
				delete(s.sessionsByID, bs.ID)
			}
		}
	}
	for id, expires := range s.revokedSessions {
		if !now.Before(expires) {
			delete(s.revokedSessions, id)
		}
	}
}

// ValidateQueryInput performs the shared semantic validation for DashboardQuery
// across service handlers, HTTP routes, ergonomic CLI commands, and --request FILE inputs.
func ValidateQueryInput(q api.DashboardQuery) error {
	if q.Limit < 1 || q.Limit > maxPageLimit {
		return invalidErr("limit must be between 1 and 200", "Pass a limit in 1..200.")
	}
	if len(q.Cursor) > 8192 || strings.ContainsAny(q.Cursor, "\r\n\x00") {
		return invalidErr("invalid pagination cursor", "Reopen the view without a cursor.")
	}
	if q.LifeID != "" && !validID(q.LifeID) {
		return invalidErr("invalid life_id", "Provide a valid opaque life_id.")
	}
	if q.Run > maxSafeInt {
		return invalidErr("run exceeds maximum integer range", "Provide a valid run number.")
	}
	if q.Level != 0 && (q.Level < 3 || q.Level > 6) {
		return invalidErr("level must be between 3 and 6", "Specify level 3, 4, 5 or 6.")
	}
	if q.Driver != "" && q.Driver != api.DriverClaudock && q.Driver != api.DriverCodex {
		return invalidErr("unsupported driver", "Use claudock-cli or codex.")
	}
	var sinceTime, untilTime time.Time
	var err error
	if q.Since != "" {
		sinceTime, err = parseTimestamp(q.Since)
		if err != nil {
			return invalidErr("invalid since timestamp", "Use RFC3339Nano UTC ending with Z.")
		}
	}
	if q.Until != "" {
		untilTime, err = parseTimestamp(q.Until)
		if err != nil {
			return invalidErr("invalid until timestamp", "Use RFC3339Nano UTC ending with Z.")
		}
	}
	if q.Since != "" && q.Until != "" && untilTime.Before(sinceTime) {
		return invalidErr("until timestamp precedes since timestamp", "Ensure until >= since.")
	}
	return nil
}

// ValidateQueryJSON decodes and validates a raw DashboardQuery JSON object for cli.RegisterInputValidator.
func ValidateQueryJSON(raw json.RawMessage) error {
	var q api.DashboardQuery
	if err := api.DecodeObject(raw, &q); err != nil {
		return invalidErr("invalid DashboardQuery JSON shape", "Match the exact DashboardQuery fields in v2-contracts.md.")
	}
	return ValidateQueryInput(q)
}

func validateQuery(q api.DashboardQuery) error {
	return ValidateQueryInput(q)
}

type cursorPayload struct {
	Config     string `json:"c"`
	ActorID    string `json:"a"`
	View       string `json:"v"`
	FilterHash string `json:"f"`
	Offset     int    `json:"o"`
	Generation uint64 `json:"g"`
}

func queryFilterHash(q api.DashboardQuery) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%d|%s|%s|%s", q.LifeID, q.Run, q.Level, q.Driver, q.Since, q.Until)
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func (s *Service) encodeCursor(scope api.Scope, view string, q api.DashboardQuery, offset int, gen api.Generation) string {
	p := cursorPayload{
		Config:     scope.Config,
		ActorID:    string(scope.Actor.ID),
		View:       view,
		FilterHash: queryFilterHash(q),
		Offset:     offset,
		Generation: uint64(gen),
	}
	raw, _ := json.Marshal(p)
	mac := hmac.New(sha256.New, s.cursorKey[:])
	mac.Write(raw)
	sig := mac.Sum(nil)[:16]
	return base64.RawURLEncoding.EncodeToString(raw) + "." + hex.EncodeToString(sig)
}

func (s *Service) decodeCursor(scope api.Scope, view string, q api.DashboardQuery, gen api.Generation) (int, error) {
	if q.Cursor == "" {
		return 0, nil
	}
	parts := strings.Split(q.Cursor, ".")
	if len(parts) != 2 {
		return 0, invalidErr("malformed pagination cursor", "Reopen the view without a cursor.")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, invalidErr("invalid cursor encoding", "Reopen the view without a cursor.")
	}
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return 0, invalidErr("invalid cursor signature", "Reopen the view without a cursor.")
	}
	mac := hmac.New(sha256.New, s.cursorKey[:])
	mac.Write(raw)
	expectedSig := mac.Sum(nil)[:16]
	if !hmac.Equal(sig, expectedSig) {
		return 0, invalidErr("cursor authentication failed", "Reopen the view without a cursor.")
	}
	var p cursorPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, invalidErr("corrupt cursor payload", "Reopen the view without a cursor.")
	}
	if p.Config != scope.Config || p.ActorID != string(scope.Actor.ID) || p.View != view {
		return 0, invalidErr("cursor scope mismatch", "Use a cursor from the same configuration, principal and view.")
	}
	if p.FilterHash != queryFilterHash(q) {
		return 0, invalidErr("cursor filter mismatch", "Do not change query filters when continuing with a cursor.")
	}
	if gen != 0 && p.Generation != 0 && p.Generation != uint64(gen) {
		return 0, &api.Error{
			Code:    api.CodeCursorExpired,
			Message: "cursor generation expired",
			Instead: "Reopen an authorized snapshot and resume from its cursor.",
			Owner:   ownerName,
		}
	}
	if p.Offset < 0 {
		return 0, invalidErr("negative cursor offset", "Reopen the view without a cursor.")
	}
	return p.Offset, nil
}
