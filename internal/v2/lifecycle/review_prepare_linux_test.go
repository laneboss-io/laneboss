//go:build linux

package lifecycle

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type prepareReviewClock struct{ now time.Time }

func (c prepareReviewClock) Now() time.Time { return c.now }

func TestRevPrepareAfterReclaim(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t, api.Timestamp(time.Now().Add(30*time.Second).UTC().Format(time.RFC3339Nano)))
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.Clock = prepareReviewClock{now: time.Now().Add(31 * time.Second)}
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.Execution
	scope.Actor.ID = fx.ID(t)
	fresh, err := f.State.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: f.Claim.Record.Effect.ID,
		ExpectedGeneration: f.Claim.Record.Generation, ClaimantID: scope.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("could not reclaim the real original planning effect", err)
	}
	s := &Service{deps: Dependencies{Store: f.State, Clock: f.Deps.Clock}}
	execution := &planExecution{service: s, scope: scope, lease: fresh, record: f.Record}
	if err := execution.checkClaim(context.Background()); err != nil {
		t.Fatal("replacement planning claim is not authentic", err)
	}
	request := api.CredentialProjectionRequest{Cause: *f.PreparedClaim.Record.Effect.Context, Claim: f.PreparedClaim,
		Handoff: *f.Record.Handoff, Prepared: f.Prepared, Lease: f.Plan.Lease, Home: f.Plan.Data.Home}
	if err := execution.prepareEffect(context.Background(), request); err != nil {
		t.Fatal("fresh planner rejected the original completed prepare authority", err)
	}
	request.Claim.ClaimID = fx.ID(t)
	if err := execution.prepareEffect(context.Background(), request); err == nil {
		t.Fatal("historical prepare accepted a foreign claim")
	}
}
