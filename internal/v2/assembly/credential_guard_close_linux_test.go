//go:build linux

package assembly

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type closeGateFixture struct {
	calls int
	err   error
}

func (*closeGateFixture) Projection() api.CredentialProjectionRecord {
	return api.CredentialProjectionRecord{}
}
func (*closeGateFixture) Check(context.Context) error {
	return errors.New("guard check is outside the close fixture")
}
func (g *closeGateFixture) Close() error {
	g.calls++
	return g.err
}

func TestCredentialBrokerGuardClose(t *testing.T) {
	for _, mode := range []string{"closed", "failure", "unknown_input", "absent"} {
		t.Run(mode, func(t *testing.T) {
			guard := &closeGateFixture{}
			if mode == "failure" {
				guard.err = errors.New("component guard retained a failure")
			}
			cancelled := false
			session := &credentialBrokerSession{host: &credentialBrokerHost{attempted: true}, guard: guard,
				cancelGuard: func() { cancelled = true }}
			raw := json.RawMessage(`{}`)
			if mode == "unknown_input" {
				raw = json.RawMessage(`{"untrusted":true}`)
			}
			if mode == "absent" {
				session.guard = nil
			}
			value, files, err := session.Call(context.Background(), nil, "guard_close", raw, nil)
			if mode == "unknown_input" || mode == "absent" {
				if err == nil || value != nil || len(files) != 0 || guard.calls != 0 || cancelled {
					t.Fatal("broker acknowledged a close without its exact owned guard")
				}
				return
			}
			if guard.calls != 1 || !cancelled || session.guard != nil || session.cancelGuard != nil {
				t.Fatal("broker acknowledged before finishing its actual guard close")
			}
			if mode == "failure" {
				if !errors.Is(err, guard.err) || value != nil {
					t.Fatal("broker discarded the actual guard close failure")
				}
			} else if err != nil || value != (api.Empty{}) || len(files) != 0 {
				t.Fatal("broker failed to acknowledge its completed guard close", err)
			}
			if err := session.Close(); err != nil || guard.calls != 1 {
				t.Fatal("broker session cleanup repeated an already completed guard close", err)
			}
		})
	}
}
