//go:build linux

package admin_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The credential transfer resolves a registered handoff's runtime during the later helper_prepare stage: the explicit
// attempt is that stage's claim while the handoff keeps the helper_register cause of its planning effect (box 61).
// Every lease here comes from the real store's ClaimEffect; launchAuthority is driven through ReviewLaunchAuthority.

// stageLaunch is a real spec_retained launch with the org snapshot its launch fence compares.
func stageLaunch(t *testing.T) *fx.Fixture {
	t.Helper()
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	ownership := f.Retain(t, "manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}), f.Execution.Actor, "")
	inventory := f.Retain(t, "manifest", fx.JSON(t, []api.ResourceFile{}), f.Execution.Actor, "")
	snapshot := api.OrgSnapshot{Config: f.Deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: inventory.SHA256},
		Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, OwnershipManifest: ownership,
		Renderer: api.Executable{ID: fx.ID(t), SHA256: inventory.SHA256, Version: "stage-component"}, PublishedBy: fx.ID(t), PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	orgCause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &orgCause, Writes: api.StateWrites{OrgSnapshots: []api.OrgSnapshot{snapshot}}}); err != nil {
		t.Fatal(err)
	}
	return f
}

// stagePrepare retains a helper_prepare child of f's launch, as the service's prepareAgent does, and claims it until
// deadline. change edits the retained request before it is committed.
func stagePrepare(t *testing.T, f *fx.Fixture, deadline time.Duration, change func(*api.HelperLaunchRequest)) api.EffectLease {
	t.Helper()
	cause := f.Intent(t, api.InternalHelperPrepare)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	request := api.HelperLaunchRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, PreparedSpecID: f.Reservation.SpecID, SpecSHA256: f.Record.Handoff.SpecSHA256}
	if change != nil {
		change(&request)
	}
	effect := api.Effect{ID: request.Cause.EffectID, OperationID: request.Cause.CauseOperationID, Context: &request.Cause, HelperPrepare: &request}
	parent := request.Cause
	parent.ID = fx.ID(t)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("could not retain the prepare stage", err)
	}
	lease, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(time.Now().Add(deadline).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal("could not claim the prepare stage", err)
	}
	return lease
}

func stageRefused(t *testing.T, name string, err error, code api.ErrorCode, message string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.Message != message {
		t.Errorf("%s: want %s %q, got %v", name, code, message, err)
	}
}

func TestStageCausePrepareClaim(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	f := stageLaunch(t)
	f.PrepareJob(t)
	cause := f.Record.Handoff.Cause
	if cause.Kind != api.InternalHelperRegister || cause.EffectID != f.Claim.Record.Effect.ID || f.PreparedClaim.Record.Effect.ID == cause.EffectID {
		t.Fatal("the fixture lost the box shape: a register-stage cause and a separate prepare-stage claim")
	}
	ctx := context.Background()
	record, err := admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, f.PreparedClaim), f.State, f.Deps.Config, f.Reservation.ID, &cause)
	if err != nil || record.Reservation.ID != f.Reservation.ID || record.Handoff == nil || !reflect.DeepEqual(*record.Handoff, *f.Record.Handoff) {
		t.Fatal("the prepare stage claim could not resolve its registered handoff", err)
	}
	// An unrelated effect: a claimed prepare stage of the same operation that names another spec digest.
	other := stagePrepare(t, f, time.Hour, func(r *api.HelperLaunchRequest) { r.SpecSHA256 = fx.Digest([]byte("another launch spec")) })
	_, err = admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, other), f.State, f.Deps.Config, f.Reservation.ID, &cause)
	stageRefused(t, "foreign_spec", err, api.CodeForbidden, "prepare stage claim does not name this registered launch spec")
	// A cause that is not the retained handoff's own, differing only in its ID.
	changed := cause
	changed.ID = fx.ID(t)
	_, err = admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, f.PreparedClaim), f.State, f.Deps.Config, f.Reservation.ID, &changed)
	stageRefused(t, "changed_cause", err, api.CodeForbidden, "prepare stage claim does not name this registered launch spec")
	// A claimed effect that is not a prepare stage keeps the original refusal.
	allocation := f.Intent(t, api.InternalHelperAllocate)
	allocation.ID, allocation.EffectID = fx.ID(t), fx.ID(t)
	allocate := f.Allocation
	allocate.Cause = allocation
	effect := api.Effect{ID: allocation.EffectID, OperationID: allocation.CauseOperationID, Context: &allocation, HelperAllocate: &allocate}
	planning := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &planning, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal(err)
	}
	unrelated, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, unrelated), f.State, f.Deps.Config, f.Reservation.ID, &cause)
	stageRefused(t, "unrelated_effect", err, api.CodeConflict, "launch cause differs from its explicit execution claim")
}

// The box's retry: a new claimant holds the prepare stage while the handoff's cause keeps its original author.
func TestStageCauseNewClaimant(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	f := stageLaunch(t)
	old := stagePrepare(t, f, 30*time.Second, nil)
	claimant := api.Actor{Kind: "service", ID: fx.ID(t)}
	fresh := reclaimReviewStage(t, f, old, claimant)
	cause := f.Record.Handoff.Cause
	if cause.Actor == claimant || fresh.Record.ClaimantID != claimant.ID {
		t.Fatal("the reclaimed stage must have a claimant other than the cause's author")
	}
	ctx := context.Background()
	record, err := admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, fresh), f.State, f.Deps.Config, f.Reservation.ID, &cause)
	if err != nil || record.Reservation.ID != f.Reservation.ID {
		t.Fatal("the new claimant of the prepare stage could not resolve its registered handoff", err)
	}
	live := cause
	live.Actor = claimant
	if _, err := admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, fresh), f.State, f.Deps.Config, f.Reservation.ID, &live); err != nil {
		t.Fatal("the registered cause carrying the live claimant was refused", err)
	}
	_, err = admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, old), f.State, f.Deps.Config, f.Reservation.ID, &cause)
	stageRefused(t, "stale_attempt", err, api.CodeConflict, "launch effect attempt is stale or foreign")
	foreign := cause
	foreign.Actor = api.Actor{Kind: "service", ID: fx.ID(t)}
	_, err = admin.ReviewLaunchAuthority(api.WithEffectLease(ctx, fresh), f.State, f.Deps.Config, f.Reservation.ID, &foreign)
	stageRefused(t, "foreign_actor", err, api.CodeForbidden, "launch cause differs from the durable service claim")
}
