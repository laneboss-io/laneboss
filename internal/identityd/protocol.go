// Package identityd owns service identities independently of caller-owned CLI
// state. Only kernel peer credentials and service-owned records select an actor.
package identityd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/identityd/ticket"
	"laneboss.io/laneboss/internal/lane"
	"laneboss.io/laneboss/internal/protocol"
)

const (
	Version            = 1
	MaxRequestBytes    = 64 * 1024
	MaxResponseBytes   = 128 * 1024
	MaxPayloadBytes    = 48 * 1024
	MaxConnections     = 32
	MaxUIDConnections  = 8
	MaxPeerConnections = 2
	MaxRequests        = 64
	StateRoot          = "/var/lib/laneboss"
	RuntimeRoot        = "/var/run/laneboss"
)

var laneName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type ProcessRef struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
}

type Peer struct {
	PID   int    `json:"pid"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Start string `json:"start"`
}

type Principal struct {
	ID      string `json:"id"`
	Level   int    `json:"level"`
	Starter string `json:"starter,omitempty"`
}

// Claim is uninterpreted caller data. It never selects a process or actor in a
// release build. Keeping it separate makes provenance explicit on the wire.
type Request struct {
	Version int             `json:"laneboss_service"`
	Config  string          `json:"config"`
	Op      string          `json:"op"`
	Ticket  json.RawMessage `json:"ticket,omitempty"`
	Lane    string          `json:"lane,omitempty"`
	Run     int             `json:"run,omitempty"`
	Level   int             `json:"level,omitempty"`
	Process *ProcessRef     `json:"process,omitempty"`
	Type    string          `json:"type,omitempty"`
	Kind    string          `json:"kind,omitempty"`
	To      string          `json:"to,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Claim   json.RawMessage `json:"claim,omitempty"`
}

type ServiceInfo struct {
	Config string `json:"config"`
	Peer   Peer   `json:"process"`
	Seq    int64  `json:"last_seq"`
}

type Response struct {
	Version        int                  `json:"laneboss_service"`
	OK             bool                 `json:"ok"`
	Code           int                  `json:"code"`
	Error          string               `json:"error,omitempty"`
	Identified     bool                 `json:"identified"`
	Lifetime       string               `json:"peer_lifetime,omitempty"`
	Peer           *Peer                `json:"peer,omitempty"`
	Principal      *Principal           `json:"principal,omitempty"`
	Root           *ProcessRef          `json:"identity_root,omitempty"`
	DetachmentRoot *ProcessRef          `json:"detachment_root,omitempty"`
	Service        ServiceInfo          `json:"service"`
	Record         *Record              `json:"record,omitempty"`
	Ticket         string               `json:"ticket,omitempty"`
	Human          bool                 `json:"human,omitempty"`
	LastConsumer   *ticket.Consumer     `json:"last_ticket_consumer,omitempty"`
	PolicyChange   *ticket.PolicyChange `json:"policy_change,omitempty"`
}

// Grant is the result of cryptographic/bootstrap authorization, not request
// labels. The service independently checks Session against the peer's kernel
// ancestry, including UID and start time, before retaining it.
type Grant struct {
	Principal Principal
	Session   ProcessRef

	// The trusted issuer must attest that Session is dedicated to this
	// supervisor, not a login shell, multiplexer or shared user service.
	DedicatedSession bool
}

// TicketVerifier is the integration boundary for part 2. Implementations must
// bind tickets to this configuration and connected peer, enforce freshness and
// replay protection, and honor ctx. No verifier is selected through client data.
type TicketVerifier interface {
	Verify(ctx context.Context, config string, peer Peer, ticket json.RawMessage) (Grant, error)
}

// RejectTickets keeps production registration closed until part 2 is installed.
type RejectTickets struct{}

func (RejectTickets) Verify(context.Context, string, Peer, json.RawMessage) (Grant, error) {
	return Grant{}, refuse("the bootstrap ticket verifier is not installed\nInstead: keep using the existing CLI until the service bootstrap ticket verifier is installed.")
}

type failure struct {
	code int
	text string
}

func (e *failure) Error() string { return e.text }

func refuse(text string) error { return &failure{2, "refused: " + text} }

func corrupt(text string) error { return &failure{3, "integrity problem: " + text} }

func unidentified(start bool) error {
	if start {
		return refuse("the caller has no recorded identity\nInstead: register with laneboss start --role ROLE from the persistent session that will issue these commands, or run this command from a terminal as the human.")
	}
	err := caller.RequireIdentity(caller.Principal{})
	return refuse(err.Error())
}

func validPrincipal(p Principal) bool {
	return records.ValidID(p.ID) && p.ID != "human" && p.Level >= 3 && p.Level <= 6 && (p.Starter == "" || records.ValidID(p.Starter))
}

func validSupervisor(p Principal) bool {
	return validPrincipal(p) && (strings.HasPrefix(p.ID, "supervisor:") && p.Level >= 4 || strings.HasPrefix(p.ID, "instance:"))
}

func parseRequest(data []byte) (Request, error) {
	var request Request
	// The shared parser rejects duplicate keys, invalid Unicode and trailing JSON.
	if _, err := eventstore.Parse(data, "the service request"); err != nil {
		return request, refuse("the service request must be one valid JSON object\nInstead: send one bounded JSON object per line without duplicate fields.")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return request, refuse("the service request has invalid fields\nInstead: use the versioned service request schema in docs/service.md.")
	}
	allowed := map[string]bool{"laneboss_service": true, "config": true, "op": true, "ticket": true, "lane": true, "run": true, "level": true, "process": true, "type": true, "kind": true, "to": true, "payload": true, "claim": true}
	for name := range fields {
		if !allowed[name] && !looseFieldCase() {
			return request, refuse("the service request has invalid fields\nInstead: use exact lower-case field names from docs/service.md.")
		}
	}
	if raw := fields["process"]; len(raw) > 0 && string(raw) != "null" {
		var processFields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &processFields); err != nil || processFields == nil {
			return request, refuse("the service process reference has invalid fields")
		}
		for name := range processFields {
			if name != "pid" && name != "start" && !looseFieldCase() {
				return request, refuse("the service process reference needs exact pid and start field names")
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, refuse("the service request has invalid fields\nInstead: use the versioned service request schema in docs/service.md.")
	}
	return request, nil
}

func validateAppend(request Request, principal Principal) error {
	if request.Type != "event" && request.Type != "report" && request.Type != "send" {
		return refuse("append needs an event, report or send type\nInstead: use the service append schema in docs/service.md.")
	}
	if len(request.Payload) == 0 {
		return refuse("append needs a JSON payload\nInstead: supply the event or message as payload.")
	}
	encoded, err := json.Marshal(request.Payload)
	if err != nil || len(encoded) > MaxPayloadBytes && !oversizedPayload() {
		return refuse("the append payload exceeds 49152 bytes after JSON encoding\nInstead: send a smaller observation or message.")
	}
	if request.Type == "event" {
		if !allowedEvent(request.Kind, principal) && !unknownEvent() {
			return refuse("the event kind is not allowed for the caller's role\nInstead: append an allowed observation, or report up with laneboss report.")
		}
		payload, err := eventstore.Parse(request.Payload, "the event payload")
		if err != nil {
			return refuse("the event payload is not valid JSON")
		}
		var target any
		if request.Lane != "" {
			target = request.Lane
		}
		value, err := eventstore.ValidateCLI(eventstore.Object{"kind": request.Kind, "lane": target, "actor": principal.ID, "protocol_version": protocol.Version, "payload": payload})
		if err != nil {
			return refuse(err.Error())
		}
		if err := lane.ValidateEventPayload(request.Kind, value["payload"].(map[string]any)); err != nil {
			return refuse("the event payload does not satisfy the CLI schema\nInstead: supply the documented payload for this observation kind.")
		}
	} else if request.Kind != "" {
		return refuse("message append may not supply an event kind\nInstead: use type report or send without kind.")
	}
	if request.Lane != "" && !laneName.MatchString(request.Lane) || request.To != "" && !records.ValidID(request.To) {
		return refuse("the record target is invalid\nInstead: use a recorded principal or lane name.")
	}
	if request.Type == "send" && request.To == "" {
		return refuse("send needs a recipient\nInstead: supply the recorded recipient as to.")
	}
	return nil
}

// Identity/lifecycle decisions are not observations. New kinds need an explicit
// role entry here as well as the CLI's existing payload checks.
func allowedEvent(kind string, principal Principal) bool {
	if kind == "agent.observed" || kind == "lane.refusal" || kind == "lane.workaround_suspected" {
		return strings.HasPrefix(principal.ID, "lane:") || validSupervisor(principal)
	}
	return kind == "lane.refusal_reviewed" && validSupervisor(principal) && principal.Level >= 4
}

func safeError(err error) (int, string) {
	var scoped *ticket.Refusal
	if errors.As(err, &scoped) {
		return 2, "refused: " + scoped.Error()
	}
	if problem, ok := err.(*failure); ok {
		return problem.code, problem.text
	}
	return 3, "integrity problem: service operation failed"
}
