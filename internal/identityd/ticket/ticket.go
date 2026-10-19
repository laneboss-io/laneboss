// Package ticket supplies the identity service's human-issued registration
// tickets. The service owns the database under its separate OS account; clients
// must never open a ticket store or supply their own human authorization.
package ticket

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/instancename"
)

const DefaultTTL = 10 * time.Minute
const MaxTTL = 10 * time.Minute

const prefix = "lbt2."
const randomBytes = 32

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Scope is fixed at issue. The persisted scope, never the redemption request,
// supplies the granted level and role.
type Scope struct {
	Config string `json:"config"`
	Level  int    `json:"level"`
	Role   string `json:"role"`
}

func (s Scope) Valid() bool {
	return namePattern.MatchString(s.Config) && s.Level >= 3 && s.Level <= 6 && instancename.Valid(s.Role)
}

// Verifier is the part-1 registration boundary: verify and consume in one
// operation before recording a session. There is deliberately no read-only
// Verify method which could be raced against a later consume.
type Verifier interface {
	Redeem(context.Context, Scope, string, func(Scope) error) error
}

type Issuer interface {
	Issue(context.Context, Scope, time.Duration) (string, error)
}

// HumanAuthorizer must authenticate the service's OS peer and apply the existing
// human-principal rule (including a real controlling terminal). A client-supplied
// principal, PID, boolean, or terminal label is not an authorization source.
type HumanAuthorizer interface {
	RequireHuman(context.Context) error
}

// Registrar consumes the presented ticket and records the authenticated peer's
// persistent parent atomically with respect to that peer's registration. An
// empty ticket cannot authorize a new registration.
type Registrar interface {
	Register(context.Context, Scope, string) error
}

type ConfigurationProbe interface {
	Configured(string) bool
}

// Service is the narrow client interface shared by ticket issue and start.
type Service interface {
	Issuer
	Registrar
}

type Reason string

const (
	HumanRequired  Reason = "human-required"
	Required       Reason = "required"
	Unknown        Reason = "unknown"
	Expired        Reason = "expired"
	WrongLevel     Reason = "wrong-level"
	WrongRole      Reason = "wrong-role"
	WrongConfig    Reason = "wrong-config"
	Used           Reason = "used"
	InvalidTTL     Reason = "invalid-ttl"
	InvalidScope   Reason = "invalid-scope"
	Unavailable    Reason = "unavailable"
	InvalidFile    Reason = "invalid-file"
	InvalidSession Reason = "invalid-session"
	PolicyChanged  Reason = "policy-changed"
	Unsupported    Reason = "unsupported"
)

// Refusal contains a fixed reason and, for revocation, validated policy scope.
// A raw ticket or storage error can never become part of its diagnostic text.
type Refusal struct {
	Reason Reason
	Policy *PolicyChange
}

func (e *Refusal) Error() string {
	if e.Reason == PolicyChanged {
		return e.Policy.message()
	}
	first, instead := "the identity ticket service is unavailable", "have the human restore the identity service; do not register through local files."
	switch e.Reason {
	case HumanRequired:
		first, instead = "only the human at a real terminal may issue a registration ticket", "have the human run laneboss ticket issue --config NAME --level LEVEL --role ROLE from a real terminal."
	case Required:
		first = "supervisor registration requires a human-issued ticket"
	case Unknown:
		first = "the registration ticket is unknown"
	case Expired:
		first = "the registration ticket has expired"
	case WrongLevel:
		first = "the registration ticket is for another level"
	case WrongRole:
		first = "the registration ticket is for another role"
	case WrongConfig:
		first = "the registration ticket is for another configuration"
	case Used:
		first = "the registration ticket has already been used"
	case InvalidTTL:
		first, instead = "the ticket lifetime must be positive and at most 10m", "have the human issue a ticket with --ttl 10m or a shorter positive duration."
	case InvalidScope:
		first, instead = "the registration ticket scope is invalid", "have the human issue a ticket with --config NAME --level LEVEL --role ROLE matching the configured role; supply that exact level and role to start."
	case InvalidSession:
		first, instead = "the supervisor needs a dedicated parent session", "have the human issue a ticket from the owner's attested terminal with laneboss ticket issue --config NAME --level LEVEL --role ROLE; the dedicated persistent agent session must invoke laneboss start --config NAME --level LEVEL --role ROLE --ticket-file PATH directly. Plugin wrappers and shell-tool parents cannot register in service mode."
	case Unsupported:
		first, instead = "identity service registration is unsupported on macOS", "use a supported Linux identity service deployment; without a service, macOS retains legacy open registration with its notice."
	case InvalidFile:
		first, instead = "the registration ticket file is not a private bounded regular file containing one ticket", "have the human supply a mode-0600 ticket file owned by this account; pass its path with --ticket-file."
	}
	switch e.Reason {
	case Required, Unknown, Expired, WrongLevel, WrongRole, WrongConfig, Used:
		instead = "have the human issue a fresh ticket for the configuration, level and role they want with laneboss ticket issue --config NAME --level LEVEL --role ROLE, then run laneboss start --config NAME --level LEVEL --role ROLE --ticket-file PATH from the persistent session."
	}
	if e.Reason == Used {
		instead = "the ticket may have been taken by another process; have the human inspect laneboss service status --config NAME and its consuming peer before issuing a fresh ticket for the level and role they want with --level LEVEL --role ROLE, then register with --level LEVEL --role ROLE --ticket-file PATH."
	}
	return first + "\nInstead: " + instead
}

func refusal(reason Reason) error { return &Refusal{Reason: reason} }

func ValidTTL(ttl time.Duration) bool { return ttl > 0 && ttl <= MaxTTL }

// Valid accepts exactly one canonical ticket, without whitespace or alternate
// base64 encodings. Malformed and unknown tickets share the same refusal.
func Valid(raw string) bool {
	_, ok := scopeOf(raw)
	return ok
}

// The public scope is diagnostic data. Only a matching persisted digest can
// authorize use. Embedding it permits a different configuration's isolated
// service to distinguish wrong scope without reading another store.
func scopeOf(raw string) (Scope, bool) {
	if !strings.HasPrefix(raw, prefix) || len(raw) > 180 {
		return Scope{}, false
	}
	parts := strings.Split(strings.TrimPrefix(raw, prefix), ".")
	if len(parts) < 4 {
		return Scope{}, false
	}
	level, err := strconv.Atoi(parts[1])
	if err != nil || strconv.Itoa(level) != parts[1] {
		return Scope{}, false
	}
	scope := Scope{Config: parts[0], Level: level, Role: strings.Join(parts[2:len(parts)-1], ".")}
	if !scope.Valid() {
		return Scope{}, false
	}
	encoded := parts[len(parts)-1]
	if len(encoded) != base64.RawURLEncoding.EncodedLen(randomBytes) {
		return Scope{}, false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return scope, err == nil && len(data) == randomBytes && base64.RawURLEncoding.EncodeToString(data) == encoded
}

func digest(raw string) [sha256.Size]byte { return sha256.Sum256([]byte(raw)) }
