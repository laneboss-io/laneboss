package ticket

import (
	"context"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/eventstore"
)

// Registration carries the requested level and role for comparison only.
// Neither field supplies the granted identity.
type Registration struct {
	Level int    `json:"level"`
	Role  string `json:"role"`
	Value string `json:"value"`
}

// RegistrationVerifier's method matches part 1's TicketVerifier when P and G
// are identityd.Peer and identityd.Grant. Keeping the types generic lets this
// additive package compile independently of the parallel service branch.
type RegistrationVerifier[P, G any] struct {
	Tickets Verifier
	// ResolveGrant receives the persisted issued scope inside atomic redemption,
	// after used/scope checks. It resolves the peer's persistent live parent
	// from kernel state. Current policy may refuse, never replace that scope.
	ResolveGrant func(context.Context, Scope, P) (G, error)
}

func (v *RegistrationVerifier[P, G]) Verify(ctx context.Context, config string, peer P, presented json.RawMessage) (G, error) {
	var zero G
	if v == nil || v.Tickets == nil || v.ResolveGrant == nil {
		return zero, refusal(Unavailable)
	}
	if len(presented) == 0 {
		return zero, refusal(Required)
	}
	if len(presented) > 2048 {
		return zero, refusal(Unknown)
	}
	// Reuse the launcher's real JSON parser for duplicate fields, invalid
	// Unicode, non-finite values and trailing input before typed decoding.
	parsed, err := eventstore.Parse(presented, "the registration ticket")
	if err != nil {
		return zero, refusal(Unknown)
	}
	object, ok := parsed.(map[string]any)
	if !ok || len(object) != 3 {
		return zero, refusal(Unknown)
	}
	role, roleOK := object["role"].(string)
	levelValue, levelOK := object["level"].(json.Number)
	level, levelErr := levelValue.Int64()
	raw, rawOK := object["value"].(string)
	if !roleOK || !levelOK || levelErr != nil || !rawOK || level < 3 || level > 6 {
		return zero, refusal(Unknown)
	}
	scope := Scope{Config: config, Level: int(level), Role: role}
	if !scope.Valid() {
		return zero, refusal(InvalidScope)
	}
	if raw == "" {
		return zero, refusal(Required)
	}
	var grant G
	err = v.Tickets.Redeem(ctx, scope, raw, func(issued Scope) error {
		var err error
		grant, err = v.ResolveGrant(ctx, issued, peer)
		if err != nil {
			var r *Refusal
			if errors.As(err, &r) {
				return r
			}
			return refusal(Unavailable)
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	return grant, nil
}
