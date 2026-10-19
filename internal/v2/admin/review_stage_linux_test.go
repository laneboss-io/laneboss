//go:build linux

package admin_test

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestReviewCurrentStageFreshClaimant(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	for _, kind := range []api.InternalKind{api.InternalHelperOpen, api.InternalHelperStop} {
		t.Run(string(kind), func(t *testing.T) {
			f := fx.Ready(t, true)
			cause := f.Intent(t, api.InternalLifecycleEffect)
			cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
			effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause}
			if kind == api.InternalHelperOpen {
				spec := f.Record.Handoff.Spec
				effect.Launch = &spec
			} else {
				handle := api.ProcessHandle{ID: f.Reservation.LaunchID, Target: f.Reservation.Target,
					ContainmentID: f.Prepared.ContainmentID, Generation: f.Prepared.ProcessGeneration}
				effect.Stop = &handle
			}
			if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
				t.Fatal("could not retain actual lifecycle stage", err)
			}
			scope := f.Execution
			scope.Actor.ID = fx.ID(t)
			lease, err := f.State.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID,
				ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: fx.Expiry()})
			if err != nil {
				t.Fatal(err)
			}
			cause.Actor, cause.Kind, cause.ID = scope.Actor, kind, fx.ID(t)
			ctx := api.WithEffectLease(context.Background(), lease)
			if _, err := admin.ReviewCurrentStage(ctx, f.State, f.Deps.Config, cause, kind); err != nil {
				t.Fatal("fresh claimant could not authorize its retained lifecycle stage", err)
			}
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause,
				Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: f.Reservation.ID, Generation: f.Record.Generation}},
				Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: cause.Target.LifeID, Epoch: cause.CancellationEpoch}}}}); err != nil {
				t.Fatal("stage preflight consumed the actual release intent identity", err)
			}
		})
	}
}

type stageReviewClock struct{ now time.Time }

func (c stageReviewClock) Now() time.Time { return c.now }

func reclaimReviewStage(t *testing.T, f *fx.Fixture, old api.EffectLease, actor api.Actor) api.EffectLease {
	t.Helper()
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.Clock = stageReviewClock{now: time.Now().Add(31 * time.Second)}
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.Execution
	scope.Actor = actor
	fresh, err := f.State.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: old.Record.Effect.ID,
		ExpectedGeneration: old.Record.Generation, ClaimantID: actor.ID, Deadline: fx.Expiry()})
	if err != nil || fresh.ClaimID == old.ClaimID {
		t.Fatal("real stage claim was not reclaimed", err)
	}
	return fresh
}

func TestRevAuthorityNeedsAttempt(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	f := fx.New(t)
	f.Reserve(t, api.Timestamp(time.Now().Add(30*time.Second).UTC().Format(time.RFC3339Nano)))
	f.Source(t)
	ownership := f.Retain(t, "manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}), f.Execution.Actor, "")
	inventory := f.Retain(t, "manifest", fx.JSON(t, []api.ResourceFile{}), f.Execution.Actor, "")
	snapshot := api.OrgSnapshot{Config: f.Deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: inventory.SHA256},
		Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, OwnershipManifest: ownership,
		Renderer: api.Executable{ID: fx.ID(t), SHA256: inventory.SHA256, Version: "review-component"}, PublishedBy: fx.ID(t), PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	orgCause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &orgCause, Writes: api.StateWrites{OrgSnapshots: []api.OrgSnapshot{snapshot}}}); err != nil {
		t.Fatal(err)
	}
	fresh := reclaimReviewStage(t, f, f.Claim, api.Actor{Kind: "service", ID: fx.ID(t)})
	ctx := context.Background()
	cause := *f.Claim.Record.Effect.Context
	valid := api.PlanningClaim(f.Reservation.ID, fresh)
	if _, err := admin.ReviewLaunchAuthority(ctx, f.State, f.Deps.Config, f.Reservation.ID, &cause, valid); err != nil {
		t.Fatal("authentic explicit planning selector failed", err)
	}
	for _, claims := range [][]api.LaunchClaim{nil, {{}}} {
		if _, err := admin.ReviewLaunchAuthority(ctx, f.State, f.Deps.Config, f.Reservation.ID, &cause, claims...); err == nil {
			t.Error("immutable cause adopted a replacement claimant without an attempt selector")
		}
	}
}

func TestReviewStageStaleAttempt(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	for _, sameActor := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh_actor", true: "same_actor"}[sameActor], func(t *testing.T) {
			f := fx.New(t)
			f.Reserve(t)
			f.Source(t)
			f.BuildPlan(t, true)
			f.Spec(t)
			cause := f.Intent(t, api.InternalHelperPrepare)
			cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
			request := api.HelperLaunchRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, PreparedSpecID: f.Reservation.SpecID, SpecSHA256: f.Record.Handoff.SpecSHA256}
			effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperPrepare: &request}
			parent := cause
			parent.ID = fx.ID(t)
			if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{effect}}); err != nil {
				t.Fatal(err)
			}
			old, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
				ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
			if err != nil {
				t.Fatal(err)
			}
			actor := f.Execution.Actor
			if !sameActor {
				actor.ID = fx.ID(t)
			}
			fresh := reclaimReviewStage(t, f, old, actor)
			if _, err := admin.ReviewCurrentStage(api.WithEffectLease(context.Background(), old), f.State, f.Deps.Config, cause, cause.Kind); err == nil {
				t.Fatal("stale helper attempt borrowed the replacement durable claim")
			}
			if _, err := admin.ReviewCurrentStage(api.WithEffectLease(context.Background(), fresh), f.State, f.Deps.Config, cause, cause.Kind); err != nil {
				t.Fatal("actual fresh helper claimant lost its immutable input", err)
			}
		})
	}
}

func TestReviewStageFenceIntentDistinct(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	f := fx.Ready(t, true)
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	spec := f.Record.Handoff.Spec
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Launch: &spec}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal(err)
	}
	lease, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	cause.Kind, cause.ID = api.InternalHelperOpen, fx.ID(t)
	ctx := api.WithEffectLease(context.Background(), lease)
	if _, err := admin.ReviewCurrentStage(ctx, f.State, f.Deps.Config, cause, cause.Kind); err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: f.Reservation.ID, Generation: f.Record.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: cause.Target.LifeID, Epoch: cause.CancellationEpoch}}}}); err != nil {
		t.Fatal("stage read fence collided with actual open transaction", err)
	}
}

func TestReviewControlIntentKeepsAttempt(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	for _, kind := range []api.InternalKind{api.InternalHelperOpen, api.InternalHelperStop} {
		t.Run(string(kind), func(t *testing.T) {
			f := fx.Ready(t, true)
			cause := f.Intent(t, api.InternalLifecycleEffect)
			cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
			effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause}
			if kind == api.InternalHelperOpen {
				spec := f.Record.Handoff.Spec
				effect.Launch = &spec
			} else {
				handle := api.ProcessHandle{ID: f.Reservation.LaunchID, Target: f.Reservation.Target,
					ContainmentID: f.Prepared.ContainmentID, Generation: f.Prepared.ProcessGeneration}
				effect.Stop = &handle
			}
			if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
				t.Fatal(err)
			}
			scope := f.Execution
			scope.Actor.ID = fx.ID(t)
			lease, err := f.State.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: fx.Expiry()})
			if err != nil {
				t.Fatal(err)
			}
			selected, claim, err := f.State.LaunchControlIntent(api.WithEffectLease(context.Background(), lease), kind, f.Reservation.LaunchID)
			if err != nil || claim.ClaimID != lease.ClaimID || selected.Actor != scope.Actor || selected.EffectID != effect.ID {
				t.Fatal("control source substituted the live planner for the caller's actual stage", err)
			}
			foreign := lease
			foreign.ClaimID = fx.ID(t)
			if _, _, err := f.State.LaunchControlIntent(api.WithEffectLease(context.Background(), foreign), kind, f.Reservation.LaunchID); err == nil {
				t.Fatal("control source adopted a live claim for a foreign attempt selector")
			}
		})
	}
}
