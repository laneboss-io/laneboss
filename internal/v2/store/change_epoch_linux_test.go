//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestChangeApplyEpochFence(t *testing.T) {
	for _, current := range []bool{true, false} {
		t.Run(map[bool]string{true: "current", false: "stale"}[current], func(t *testing.T) {
			s, _, tx := deferredChangeFixture(t)
			// Component life facts isolate the publication epoch join. This
			// fixture is not a complete native launched-lane acceptance tree.
			fixtureProjection(t, s, "lane", tx.Scope.Actor.LifeID, 1, api.Lane{LifeID: tx.Scope.Actor.LifeID, Run: 1, LaunchID: tx.Scope.LaunchID, Generation: 1, CancellationEpoch: 7})
			if current {
				tx.Effects[0].Context.CancellationEpoch = 7
			}
			commit, err := s.Transact(context.Background(), tx)
			if current {
				if err != nil || commit.Deferred == nil || commit.Reply != nil {
					t.Fatal("current life epoch publication control refused", err)
				}
			} else if err == nil {
				t.Fatal("publication reserved a stale L6 cancellation epoch")
			}
		})
	}
}

func TestChangeAuthorizedPublicationSu6744(t *testing.T) {
	s, _, tx := deferredChangeFixture(t)
	ctx := context.Background()
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal(err)
	}
	fixtureProjection(t, s, "lane", tx.Scope.Actor.LifeID, 1, api.Lane{LifeID: tx.Scope.Actor.LifeID, Run: 1, LaunchID: tx.Scope.LaunchID, Generation: 1, CancellationEpoch: 7})
	scope, lease, request := publicationClaim(t, s, tx)
	actual, err := s.PublishChange(ctx, scope, request)
	if err != nil {
		t.Fatal("authorized durable org publication borrowed its caller's later life epoch", err)
	}
	if commit, err := s.CompleteEffect(ctx, scope, publicationOutcome(t, tx, lease, actual)); err != nil || commit.Operation.Status != "succeeded" {
		t.Fatal("original consumed D6 approval could not reconcile its measured publication", err)
	}
}
