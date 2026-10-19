package ticket

import (
	"context"
	"encoding/json"
	"testing"
)

type fixturePeer struct{ pid int }
type fixtureGrant struct {
	config string
	role   string
	level  int
	pid    int
}

func TestRegistrationVerifier(t *testing.T) {
	s, _ := newTestStore(t)
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	resolved := 0
	verifier := &RegistrationVerifier[fixturePeer, fixtureGrant]{
		Tickets: s,
		ResolveGrant: func(ctx context.Context, issued Scope, peer fixturePeer) (fixtureGrant, error) {
			resolved++
			if ctx.Err() != nil || peer.pid <= 1 {
				return fixtureGrant{}, refusal(InvalidScope)
			}
			return fixtureGrant{issued.Config, issued.Role, issued.Level, peer.pid}, nil
		},
	}
	presented, err := json.Marshal(Registration{Level: scope.Level, Role: scope.Role, Value: raw})
	if err != nil {
		t.Fatal("cannot encode the registration fixture")
	}
	_, err = verifier.Verify(context.Background(), scope.Config, fixturePeer{1}, presented)
	requireReason(t, err, InvalidScope)
	grant, err := verifier.Verify(context.Background(), scope.Config, fixturePeer{42}, presented)
	if err != nil || grant != (fixtureGrant{scope.Config, scope.Role, scope.Level, 42}) || resolved != 2 {
		t.Fatal("the verifier did not bind a consumed ticket to the resolver's actual peer and role")
	}
	_, err = verifier.Verify(context.Background(), scope.Config, fixturePeer{42}, presented)
	requireReason(t, err, Used)
	if resolved != 2 {
		t.Fatal("a used ticket reached grant construction")
	}
	for _, malformed := range []json.RawMessage{
		json.RawMessage(`{"level":5,"role":"top","role":"mini","value":"input"}`),
		json.RawMessage(`{"level":5,"role":"top","value":"input","principal":"human"}`),
		json.RawMessage(`{"level":5,"role":"top","value":"input"} {}`),
		json.RawMessage(`{"level":5,"role":"top","value":1}`),
		json.RawMessage(`{"level":5.0,"role":"top","value":"input"}`),
		json.RawMessage(`{"level":true,"role":"top","value":"input"}`),
		json.RawMessage(`{"level":5,"level":4,"role":"top","value":"input"}`),
		json.RawMessage(`{"role":"top","value":"input"}`),
	} {
		before := resolved
		_, err := verifier.Verify(context.Background(), scope.Config, fixturePeer{42}, malformed)
		requireReason(t, err, Unknown)
		if resolved != before {
			t.Fatal("malformed client data reached the trusted grant resolver")
		}
	}
	_, err = verifier.Verify(context.Background(), scope.Config, fixturePeer{42}, nil)
	requireReason(t, err, Required)
}
