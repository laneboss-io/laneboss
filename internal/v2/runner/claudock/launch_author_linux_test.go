//go:build linux

package claudock

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaunchAuthorDiffersFromClaimant(t *testing.T) {
	f := runnerSetup(t)
	ctx := context.Background()
	selector, _, err := f.service.retainedLaunch(ctx, f.request.Target)
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.launch.Effect(ctx, selector.Scope, selector.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	cause := *current.Effect.Context
	cause.Actor = api.Actor{Kind: "service", ID: "original-plan-author"}
	current.Effect.Context = &cause
	f.launch.write("effect-"+string(selector.EffectID), current)
	if _, err := f.service.planning(ctx, f.request, "start"); err != nil {
		t.Fatal("immutable author was mistaken for current planning ownership", err)
	}
	current.ClaimID = "stale-plan-claim"
	f.launch.write("effect-"+string(selector.EffectID), current)
	if _, err := f.service.planning(ctx, f.request, "start"); err == nil {
		t.Fatal("independent author handling removed the live runner claim check")
	}
}
