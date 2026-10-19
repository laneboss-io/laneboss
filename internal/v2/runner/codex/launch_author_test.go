package codex

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaunchAuthorDiffersFromClaimant(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	lease := f.service.deps.Planning.Lease
	current := fixtureCopy(f.store.effects[lease.Record.Effect.ID])
	cause := *current.Effect.Context
	cause.Actor = api.Actor{Kind: "service", ID: "original-plan-author"}
	current.Effect.Context = &cause
	f.store.effects[current.Effect.ID] = current
	lease.Record = current
	f.service.deps.Planning.Lease = lease
	if _, err := f.service.launchInput(ctx, f.request, "start"); err != nil {
		t.Fatal("immutable author was mistaken for current planning ownership", err)
	}
	current.ClaimID = "stale-plan-claim"
	f.store.effects[current.Effect.ID] = current
	if _, err := f.service.launchInput(ctx, f.request, "start"); err == nil {
		t.Fatal("independent author handling removed the live runner claim check")
	}
}
