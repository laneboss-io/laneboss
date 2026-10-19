//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCurrentApprovedHead(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, PolicyGeneration: 1}
	first := api.EffectivePolicy{Generation: 1, SHA256: testDigest([]byte("first approved policy"))}
	fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 1, first)
	view, err := s.BeginRead(ctx, scope)
	if err != nil {
		t.Fatal("policy read snapshot setup failed", err)
	}
	t.Cleanup(func() {
		if err := view.Close(); err != nil {
			t.Error(err)
		}
	})
	second := api.EffectivePolicy{Generation: 2, SHA256: testDigest([]byte("second approved policy"))}
	fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 2, second)
	scope.ReadView = view
	old, err := s.Policy(ctx, scope)
	if err != nil || !sameValue(old, first) {
		t.Fatal("historical policy snapshot control failed", err)
	}
	current, err := s.CurrentApprovedPolicy(ctx, scope)
	if err != nil || !sameValue(current, second) {
		t.Fatal("current policy used the historical snapshot", err)
	}
	scope.Config = "other-fixture"
	if _, err := s.CurrentApprovedPolicy(ctx, scope); err == nil {
		t.Fatal("current policy accepted a foreign configuration")
	}
}

func TestPolicyHeadRefusal(t *testing.T) {
	for _, mode := range []string{"absent", "malformed", "closed"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := testStore(t)
			scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}}
			if mode == "malformed" {
				fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 1, api.EffectivePolicy{Generation: 1})
			}
			if mode == "closed" {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.CurrentApprovedPolicy(context.Background(), scope); err == nil {
				t.Fatal("policy source invented an approved head")
			}
		})
	}
}
