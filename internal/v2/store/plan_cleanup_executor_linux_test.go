//go:build linux

package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestFailedPlanCleanupExecutorAvailable(t *testing.T) {
	for _, mode := range []string{"complete", "reclaim", "refusal", "foreign", "stale", "overlap", "missing", "readback", "survivor", "broker", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			f, tx, jobs := failedPlanFixtureAt(t, "prepared", true)
			if _, ok := any(f.State).(api.PlanCleanupStore); !ok {
				t.Fatal("retained failed-plan cleanup has no durable claim/completion owner")
			}
			ctx := context.Background()
			if _, err := f.State.FailPlan(ctx, tx, jobs); err != nil {
				t.Fatal(err)
			}
			clock := &cleanupAttemptClock{}
			if err := f.State.Close(); err != nil {
				t.Fatal(err)
			}
			f.Deps.Clock = clock
			var err error
			f.State, err = store.New(f.Deps)
			if err != nil {
				t.Fatal(err)
			}
			port := any(f.State).(api.PlanCleanupStore)
			scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: fx.ID(t)}}
			claimRequest := func(job api.PlanCleanup, generation api.Generation) api.EffectClaimRequest {
				return api.EffectClaimRequest{EffectID: job.ID, ExpectedGeneration: generation, ClaimantID: scope.Actor.ID,
					Deadline: api.Timestamp(clock.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano))}
			}
			// The companion request is blocked by a real prerequisite, rather
			// than depending on enumeration order in either consumer.
			if _, err := port.ClaimPlanCleanup(ctx, scope, jobs[1], claimRequest(jobs[1], 1)); err == nil {
				t.Fatal("injection was revoked before its measured release")
			} else {
				launchCode(t, err, api.CodeContainmentUnknown)
			}
			job := jobs[0]
			if mode == "foreign" {
				changed := job
				changed.Slot.ID = fx.ID(t)
				_, err := port.ClaimPlanCleanup(ctx, scope, changed, claimRequest(job, 1))
				launchCode(t, err, api.CodeForbidden)
			}
			if mode == "stale" {
				_, err := port.ClaimPlanCleanup(ctx, scope, job, claimRequest(job, 2))
				launchCode(t, err, api.CodeConflict)
			}
			claim, err := port.ClaimPlanCleanup(ctx, scope, job, claimRequest(job, 1))
			if err != nil || claim.Generation != 2 || claim.ClaimantID != scope.Actor.ID || !reflect.DeepEqual(claim.Request, job) {
				t.Fatal("cleanup did not retain its original request under a fresh claim", err)
			}
			if mode == "overlap" {
				_, err := port.ClaimPlanCleanup(ctx, scope, job, claimRequest(job, claim.Generation))
				launchCode(t, err, api.CodeConflict)
			}
			if mode == "foreign" {
				borrowed := scope
				borrowed.Actor.ID = fx.ID(t)
				launchCode(t, port.CheckPlanCleanupClaim(ctx, borrowed, claim), api.CodeConflict)
			}
			if mode == "reclaim" {
				old, oldScope := claim, scope
				clock.offset += time.Minute
				launchCode(t, port.CheckPlanCleanupClaim(ctx, scope, old), api.CodeConflict)
				scope.Actor.ID = fx.ID(t)
				claim, err = port.ClaimPlanCleanup(ctx, scope, job, claimRequest(job, old.Generation))
				if err != nil || claim.ClaimID == old.ClaimID || claim.ClaimantID == old.ClaimantID || claim.Generation != old.Generation+1 {
					t.Fatal("expired cleanup attempt did not yield to a fresh claimant", err)
				}
				launchCode(t, port.CheckPlanCleanupClaim(ctx, oldScope, old), api.CodeConflict)
			}
			if mode == "refusal" {
				refusal := &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-secrets", Message: "component broker journal unavailable", Instead: "Reconcile the original journal.", Retryable: true}
				if err := port.RecordPlanCleanupRefusal(ctx, scope, claim, refusal); err != nil {
					t.Fatal(err)
				}
				status, err := port.PlanCleanupStatus(ctx, scope, job.ID)
				if err != nil || status.State != "pending" || status.Receipt != nil || !reflect.DeepEqual(status.Refusal, refusal) || status.Generation != claim.Generation+1 {
					t.Fatal("cleanup refusal was discarded or falsely completed", err)
				}
				claim, err = port.ClaimPlanCleanup(ctx, scope, job, claimRequest(job, status.Generation))
				if err != nil {
					t.Fatal(err)
				}
			}
			owner := &cleanupComponentOwner{t: t, f: f, store: port, clock: clock, receipts: map[api.ID]api.PlanCleanupReceipt{}}
			receipt, err := owner.ExecutePlanCleanup(ctx, scope, claim)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing" {
				_, err := port.CompletePlanCleanup(ctx, scope, claim, receipt, nil)
				launchCode(t, err, api.CodeNotImplemented)
			}
			if mode == "readback" {
				changed := receipt
				changed.ID = fx.ID(t)
				_, err := port.CompletePlanCleanup(ctx, scope, claim, changed, owner)
				launchCode(t, err, api.CodeIntegrity)
			}
			if mode == "survivor" || mode == "broker" {
				changed := receipt
				if mode == "survivor" {
					bad := *receipt.Abort
					bad.Quiescence.Survivors = nil
					changed.Abort = &bad
				} else {
					changed.Broker = job.SlotResult
				}
				owner.receipts[job.ID] = changed
				_, err := port.CompletePlanCleanup(ctx, scope, claim, changed, owner)
				if err == nil {
					t.Fatal("unmeasured cleanup completed", mode)
				}
				owner.receipts[job.ID] = receipt
			}
			if mode == "rollback" {
				cleanupDDL(t, f, "CREATE TRIGGER cleanup_completion_failure BEFORE INSERT ON projection_history WHEN NEW.kind='plan_cleanup' AND json_extract(NEW.data,'$.State')='completed' BEGIN SELECT RAISE(ABORT, 'component cleanup completion denied'); END")
				_, refused := port.CompletePlanCleanup(ctx, scope, claim, receipt, owner)
				cleanupDDL(t, f, "DROP TRIGGER cleanup_completion_failure")
				status, err := port.PlanCleanupStatus(ctx, scope, job.ID)
				if refused == nil || err != nil || status.State != "claimed" || status.Receipt != nil {
					t.Fatal("failed completion left a partial acknowledgement", refused, err)
				}
			}
			actual, err := port.CompletePlanCleanup(ctx, scope, claim, receipt, owner)
			if err != nil || !reflect.DeepEqual(actual, receipt) {
				t.Fatal("cleanup did not commit its measured terminal acknowledgement", err)
			}
			if replay, err := port.CompletePlanCleanup(ctx, scope, claim, receipt, owner); err != nil || !reflect.DeepEqual(replay, receipt) {
				t.Fatal("exact completion replay replaced its original acknowledgement", err)
			}
			changed := receipt
			changed.ID = fx.ID(t)
			_, err = port.CompletePlanCleanup(ctx, scope, claim, changed, owner)
			launchCode(t, err, api.CodeConflict)
			second, err := port.ClaimPlanCleanup(ctx, scope, jobs[1], claimRequest(jobs[1], 1))
			if err != nil {
				t.Fatal("measured release did not unlock the original injection cleanup", err)
			}
			secondReceipt, err := owner.ExecutePlanCleanup(ctx, scope, second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := port.CompletePlanCleanup(ctx, scope, second, secondReceipt, owner); err != nil {
				t.Fatal(err)
			}
			if pending, err := port.PendingPlanCleanup(ctx, scope); err != nil || len(pending) != 0 {
				t.Fatal("completed cleanup remained dispatchable", err)
			}
			retained, err := f.State.LaunchPlan(ctx, scope, f.Reservation.ID)
			if err != nil || !reflect.DeepEqual(retained, tx.Writes.LaunchPlans[0]) {
				t.Fatal("cleanup rewrote the original failed launch", err)
			}
			if verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
				t.Fatal("completed cleanup failed full store verification", err)
			}
			if err := f.State.Close(); err != nil {
				t.Fatal(err)
			}
			f.State, err = store.New(f.Deps)
			if err != nil {
				t.Fatal("cleanup completion did not survive writer restart", err)
			}
			if status, err := f.State.PlanCleanupStatus(ctx, scope, job.ID); err != nil || status.State != "completed" || !reflect.DeepEqual(*status.Receipt, receipt) {
				t.Fatal("restart lost the exact cleanup acknowledgement", err)
			}
		})
	}
}

type cleanupAttemptClock struct{ offset time.Duration }

func (c *cleanupAttemptClock) Now() time.Time { return time.Now().Add(c.offset) }

// These are explicit resource-owner component fixtures, not native acceptance.
// The store, atomic failure writer, claims, immutable bytes, completion writer,
// rollback/reopen and verification are real. Native execution needs its own
// root canary and must never be credited from this boundary fixture.
type cleanupComponentOwner struct {
	t        *testing.T
	f        *fx.Fixture
	store    api.PlanCleanupStore
	clock    api.Clock
	receipts map[api.ID]api.PlanCleanupReceipt
}

func (o *cleanupComponentOwner) ExecutePlanCleanup(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) (api.PlanCleanupReceipt, error) {
	if err := o.store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	job := claim.Request
	allocation, err := o.store.PlanCleanupAllocation(ctx, scope, claim)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	zero := uint64(0)
	now := api.Timestamp(o.clock.Now().UTC().Format(time.RFC3339Nano))
	abort := &api.AbortReceipt{ID: fx.ID(o.t), LeaseID: allocation.ID, ObservedAt: now,
		Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{Target: job.Cause.Target, ContainmentID: allocation.ContainmentID},
			State: "not_started", Survivors: &zero, PromptStatus: "not_written", ObservedAt: now}}
	if job.Kind == "revoke_injection" {
		for _, prior := range o.receipts {
			if prior.ReservationID == job.ReservationID && prior.Kind == "release" {
				abort = prior.Abort
			}
		}
	}
	ack := api.PlanCleanupBrokerReceipt{CleanupID: job.ID, ReservationID: job.ReservationID, LaunchID: job.LaunchID,
		Kind: job.Kind, Slot: job.Slot, Injection: job.Injection, NativeReceiptID: abort.ID, CompletedAt: now}
	raw := fx.JSON(o.t, ack)
	cause := o.f.Intent(o.t, api.InternalOrgBootstrap)
	cause.Actor = scope.Actor
	ref, err := o.f.State.RetainObject(ctx, scope, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{
		ObjectKey: fx.ID(o.t), Class: "manifest", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: job.Cause.Target.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	receipt := api.PlanCleanupReceipt{ID: fx.ID(o.t), CleanupID: job.ID, ReservationID: job.ReservationID, LaunchID: job.LaunchID,
		Kind: job.Kind, SlotID: job.Slot.ID, Allocation: allocation, Broker: ref, Abort: abort, CompletedAt: now}
	o.receipts[job.ID] = receipt
	return receipt, nil
}

func (o *cleanupComponentOwner) ReadPlanCleanupReceipt(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) (api.PlanCleanupReceipt, error) {
	if err := o.store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	receipt, ok := o.receipts[claim.Request.ID]
	if !ok {
		return api.PlanCleanupReceipt{}, errors.New("component owner has no original cleanup journal")
	}
	return receipt, nil
}
