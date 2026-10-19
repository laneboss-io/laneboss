//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The SQLite writer, encrypted broker and service reconciler are real. This
// explicit native boundary validates the retained effect lease and persists a
// component receipt; native collection is tested separately by the root canary.
type cleanupCredentialHelper struct {
	api.HelperControl
	t         *testing.T
	f         *fx.Fixture
	directory string
	calls     int
}

func (h *cleanupCredentialHelper) AbortGate(ctx context.Context, request api.HelperAbortRequest) (api.AbortReceipt, error) {
	lease, ok := api.EffectLeaseFromContext(ctx)
	actual, err := h.f.State.Effect(ctx, h.f.Execution, request.EffectID)
	if err != nil || !ok || !api.EffectLeaseClaimed(lease) || !reflect.DeepEqual(actual, lease.Record) ||
		actual.Effect.HelperAbort == nil || *actual.Effect.HelperAbort != request {
		return api.AbortReceipt{}, serviceError(api.CodeForbidden, "component native cleanup lacks its actual retained effect attempt")
	}
	path := filepath.Join(h.directory, string(request.EffectID)+".json")
	if raw, err := os.ReadFile(path); err == nil {
		var outcome api.EffectOutcome
		if err := json.Unmarshal(raw, &outcome); err != nil || outcome.Abort == nil {
			return api.AbortReceipt{}, serviceError(api.CodeIntegrity, "component native journal changed")
		}
		return *outcome.Abort, nil
	} else if !os.IsNotExist(err) {
		return api.AbortReceipt{}, err
	}
	h.calls++
	zero := uint64(0)
	stamp := api.Timestamp(h.f.Deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	receipt := api.AbortReceipt{ID: fx.ID(h.t), LeaseID: request.LeaseID, PreparedID: request.PreparedID, ObservedAt: stamp,
		Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{Target: request.Cause.Target, ContainmentID: h.f.Plan.Lease.ContainmentID},
			State: "not_started", Survivors: &zero, PromptStatus: "not_written", ObservedAt: stamp}}
	raw, err := json.Marshal(api.EffectOutcome{EffectID: request.EffectID, Status: "succeeded", Abort: &receipt})
	if err == nil {
		err = os.WriteFile(path, raw, 0600)
	}
	return receipt, err
}

func (h *cleanupCredentialHelper) ReadPlanCleanupNative(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, effect api.Effect) (api.EffectOutcome, error) {
	if err := h.f.State.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.EffectOutcome{}, err
	}
	raw, err := os.ReadFile(filepath.Join(h.directory, string(effect.ID)+".json"))
	if err != nil {
		return api.EffectOutcome{}, err
	}
	var outcome api.EffectOutcome
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return outcome, err
	}
	if outcome.EffectID != effect.ID || effect.HelperAbort == nil || outcome.Abort == nil || outcome.Abort.LeaseID != effect.HelperAbort.LeaseID {
		return api.EffectOutcome{}, serviceError(api.CodeIntegrity, "component read selected another native cleanup")
	}
	return outcome, nil
}

func cleanupCredentialBroker(t *testing.T, f *fx.Fixture, jobs []api.PlanCleanup, helper *cleanupCredentialHelper) (*secrets.Service, *native.Service, string) {
	t.Helper()
	directory := filepath.Join(testdir.New(t), "broker")
	keyID := fx.ID(t)
	backend, err := native.New(native.Dependencies{Directory: directory, Config: f.Deps.Config, KeyHandle: keyID, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	key := []byte(fx.Digest([]byte(fx.ID(t))))[:32]
	if err := backend.Unlock(context.Background(), keyID, bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	clear(key)
	job, loginID := jobs[0], fx.ID(t)
	if err := backend.WithBroker(context.Background(), func(j bstate.Journal) error {
		for _, id := range job.Injection.SlotIDs {
			slot := bstate.Slot{Schema: "laneboss.credential-slot.v2", Config: f.Deps.Config, ID: id, Kind: "task", Target: job.Cause.Target,
				ReservationID: job.ReservationID, LaunchID: job.LaunchID, OperationID: job.Cause.CauseOperationID, RequestID: job.Cause.CauseRequestID,
				RequestedBy: job.Cause.RequestedBy, HelperLeaseID: f.Plan.Lease.ID, GrantSetID: f.Reservation.GrantSetID,
				GrantSHA256: f.Record.Inputs.Grants.SHA256, Fingerprint: fx.Digest([]byte(id)), Material: []byte(fx.ID(t)), Returned: []byte{}}
			if id == job.Slot.ID {
				slot.Kind, slot.Credential, slot.ProfileID, slot.LoginID = "profile", job.Slot, job.Slot.ProfileID, loginID
			}
			if err := j.Write("slot", id, slot); err != nil {
				return err
			}
		}
		return j.Write("login", loginID, bstate.Login{ID: loginID, SlotID: job.Slot.ID, Generation: 1})
	}); err != nil {
		t.Fatal(err)
	}
	broker, err := secrets.New(secrets.Dependencies{Backend: backend, Store: f.State, Human: planningCredentialBoundary{}, Clock: f.Deps.Clock,
		Config: f.Deps.Config, ServiceScope: f.Execution, Helper: helper, CleanupNative: helper, ProjectionIdentity: planningCredentialBoundary{}})
	if err != nil {
		t.Fatal(err)
	}
	return broker, backend, directory
}

func TestCredentialPlanCleanupOwner(t *testing.T) {
	for _, mode := range []string{"complete", "foreign", "stale", "receipt", "missing", "reconciler", "restart"} {
		t.Run(mode, func(t *testing.T) {
			f, jobs := cleanupReconcileFixture(t)
			clock := &planReconcileClock{}
			helper := &cleanupCredentialHelper{t: t, f: f, directory: testdir.New(t)}
			broker, backend, directory := cleanupCredentialBroker(t, f, jobs, helper)
			owner, ok := any(broker).(api.PlanCleanupExecutor)
			if !ok {
				t.Fatal("installed credential owner lacks failed-plan cleanup execution and independent read-back")
			}
			ctx := context.Background()
			scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: fx.ID(t)}}
			claim, err := f.State.ClaimPlanCleanup(ctx, scope, jobs[0], api.EffectClaimRequest{EffectID: jobs[0].ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano))})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "foreign" {
				foreign := claim
				foreign.Request.Slot.ID = fx.ID(t)
				if _, err := owner.ExecutePlanCleanup(ctx, scope, foreign); err == nil || helper.calls != 0 {
					t.Fatal("foreign cleanup borrowed the live claim", err)
				}
				if _, err := owner.ReadPlanCleanupReceipt(ctx, scope, foreign); err == nil {
					t.Fatal("foreign cleanup read a resource receipt")
				}
			}
			if mode == "missing" {
				missing, err := secrets.New(secrets.Dependencies{Backend: backend, Store: f.State, Human: planningCredentialBoundary{}, Clock: f.Deps.Clock, Config: f.Deps.Config, ServiceScope: f.Execution, ProjectionIdentity: planningCredentialBoundary{}})
				if err != nil {
					t.Fatal(err)
				}
				_, err = any(missing).(api.PlanCleanupExecutor).ExecutePlanCleanup(ctx, scope, claim)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" || typed.Message != "installed failed-plan cleanup helper and journal read-back is not implemented" {
					t.Fatal("missing helper lost its exact refusal", err)
				}
			}
			receipt, err := owner.ExecutePlanCleanup(ctx, scope, claim)
			if err != nil {
				t.Fatal("real credential owner did not execute pending cleanup", err)
			}
			path := filepath.Join(directory, ".broker-plan_cleanup-"+string(jobs[0].ID)+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if replay, err := owner.ExecutePlanCleanup(ctx, scope, claim); err != nil || !reflect.DeepEqual(replay, receipt) {
				t.Fatal("cleanup retry replaced its original receipt", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) || helper.calls != 1 {
				t.Fatal("cleanup retry repeated collection or rewrote the broker journal", err)
			}
			if read, err := owner.ReadPlanCleanupReceipt(ctx, scope, claim); err != nil || !reflect.DeepEqual(read, receipt) {
				t.Fatal("independent cleanup read differs", err)
			}
			if mode == "restart" {
				restarted, err := secrets.New(secrets.Dependencies{Backend: backend, Store: f.State, Human: planningCredentialBoundary{}, Clock: f.Deps.Clock, Config: f.Deps.Config, ServiceScope: f.Execution, Helper: helper, CleanupNative: helper, ProjectionIdentity: planningCredentialBoundary{}})
				if err != nil {
					t.Fatal(err)
				}
				owner = any(restarted).(api.PlanCleanupExecutor)
				if replay, err := owner.ExecutePlanCleanup(ctx, scope, claim); err != nil || !reflect.DeepEqual(replay, receipt) || helper.calls != 1 {
					t.Fatal("new credential owner lost the original cleanup journal", err)
				}
			}
			if mode == "receipt" {
				changed := receipt
				changed.Broker = jobs[0].SlotResult
				if _, err := f.State.CompletePlanCleanup(ctx, scope, claim, changed, owner); err == nil {
					t.Fatal("mismatched cleanup receipt was acknowledged")
				}
			}
			if mode == "stale" {
				// Refusal ends the old attempt without fabricating a new clock or
				// changing the immutable request; a successor recovers its journal.
				if err := f.State.RecordPlanCleanupRefusal(ctx, scope, claim, serviceError(api.CodeUnavailable, "component lost reply")); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.ExecutePlanCleanup(ctx, scope, claim); err == nil {
					t.Fatal("stale cleanup attempt executed")
				}
				if _, err := owner.ReadPlanCleanupReceipt(ctx, scope, claim); err == nil {
					t.Fatal("stale cleanup attempt read a receipt")
				}
				status, err := f.State.PlanCleanupStatus(ctx, scope, jobs[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				scope.Actor.ID = fx.ID(t)
				claim, err = f.State.ClaimPlanCleanup(ctx, scope, jobs[0], api.EffectClaimRequest{EffectID: jobs[0].ID, ExpectedGeneration: status.Generation, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano))})
				if err != nil {
					t.Fatal(err)
				}
				if replay, err := owner.ExecutePlanCleanup(ctx, scope, claim); err != nil || !reflect.DeepEqual(replay, receipt) || helper.calls != 1 {
					t.Fatal("successor cleanup lost the original journal", err)
				}
			}
			if _, err := f.State.CompletePlanCleanup(ctx, scope, claim, receipt, owner); err != nil {
				t.Fatal(err)
			}
			if mode == "reconciler" {
				host := fixtureServer(t)
				host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, f.State, clock
				host.runtime.Credentials = broker
				if err := host.reconcilePlanCleanup(ctx, effectRetries{}); err != nil {
					t.Fatal("real reconciler did not consume the remaining cleanup", err)
				}
			} else {
				second, err := f.State.ClaimPlanCleanup(ctx, scope, jobs[1], api.EffectClaimRequest{EffectID: jobs[1].ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano))})
				if err != nil {
					t.Fatal(err)
				}
				revoked, err := owner.ExecutePlanCleanup(ctx, scope, second)
				if err != nil || !reflect.DeepEqual(revoked.Abort, receipt.Abort) {
					t.Fatal("injection revocation replaced its release measurement", err)
				}
				if _, err := f.State.CompletePlanCleanup(ctx, scope, second, revoked, owner); err != nil {
					t.Fatal(err)
				}
			}
			if pending, err := f.State.PendingPlanCleanup(ctx, scope); err != nil || len(pending) != 0 {
				t.Fatal("acknowledged credential cleanup remained pending", err)
			}
			if err := backend.WithBroker(ctx, func(j bstate.Journal) error {
				for _, id := range jobs[0].Injection.SlotIDs {
					var slot bstate.Slot
					if err := j.Read("slot", id, &slot); err != nil {
						return err
					}
					defer clear(slot.Material)
					if !slot.Released || len(slot.Material)+len(slot.Returned) != 0 {
						return serviceError(api.CodeIntegrity, "broker cleanup retained material")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type cleanupProjectedHelper struct {
	*credentialPipeline
	native *cleanupCredentialHelper
}

func (h *cleanupProjectedHelper) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	if request.LeaseID != h.request.Lease.ID || request.PreparedID != h.request.Prepared.ID || request.LaunchID != h.request.Handoff.Spec.LaunchID {
		return api.LaunchReconciliation{}, serviceError(api.CodeForbidden, "component cleanup reconciliation changed the original gate")
	}
	prepared := h.request.Prepared
	return api.LaunchReconciliation{Prepared: &prepared, GateState: "prepared"}, ctx.Err()
}

func (h *cleanupProjectedHelper) ReadCredentialWithdrawal(ctx context.Context, record api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	return h.credentialPipeline.WithdrawCredentials(ctx, record)
}

func (h *cleanupProjectedHelper) AbortGate(ctx context.Context, request api.HelperAbortRequest) (api.AbortReceipt, error) {
	record, err := h.f.State.CredentialProjection(ctx, h.f.Deps.Config, h.request.Prepared.ID)
	if err != nil {
		return api.AbortReceipt{}, err
	}
	if record.State != "withdrawing" || record.Fence == nil || record.Fence.Cause != request.Cause {
		return api.AbortReceipt{}, serviceError(api.CodeForbidden, "component native abort did not receive the real broker fence")
	}
	zero, exit, executed := uint64(0), 0, false
	stamp := api.Timestamp(h.clock.Now().UTC().Format(time.RFC3339Nano))
	h.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: record.Authority.ID, Generation: record.Generation + 1, Cause: record.Fence.Cause,
		Prepared: h.request.Prepared, HelperLeaseID: h.request.Lease.ID, Home: h.request.Home, ObservedAt: stamp, AgentExecuted: &executed,
		Observation: api.ProcessObservation{Handle: api.ProcessHandle{ID: h.f.Reservation.LaunchID, Target: h.request.Prepared.Target, ContainmentID: h.request.Prepared.ContainmentID, Generation: h.request.Prepared.ProcessGeneration},
			State: "exited", ExitCode: &exit, Survivors: &zero, ObservedAt: stamp}, HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero}
	if _, err := h.p.broker.FinishCredentialWithdrawal(ctx, record, h.withdrawal); err != nil {
		return api.AbortReceipt{}, err
	}
	return h.native.AbortGate(ctx, request)
}

func (h *cleanupProjectedHelper) ReadPlanCleanupNative(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, effect api.Effect) (api.EffectOutcome, error) {
	return h.native.ReadPlanCleanupNative(ctx, scope, claim, effect)
}

func TestCredentialPlanCleanupWithdrawal(t *testing.T) {
	var helper *cleanupProjectedHelper
	f, n, _, held := credentialProjectionPipelineFixture(t, func(n *credentialPipeline, deps *secrets.Dependencies) {
		helper = &cleanupProjectedHelper{credentialPipeline: n, native: &cleanupCredentialHelper{t: t, f: n.f, directory: testdir.New(t)}}
		deps.Helper, deps.CleanupNative, deps.WithdrawalNative = helper, helper, helper
	})
	ctx := context.Background()
	plan, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := f.State.Effect(ctx, f.Execution, f.Claim.Record.Effect.ID)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.Execution
	scope.Actor = api.Actor{Kind: "service", ID: parent.ClaimantID}
	cause := *parent.Effect.Context
	cause.ID, cause.Actor = cleanupTestID(plan.Reservation.ID, "cause-write"), scope.Actor
	jobCause := cause
	jobCause.Kind, jobCause.ID, jobCause.EffectID = api.InternalHelperAbort, cleanupTestID(plan.Reservation.ID, "cause-cleanup-withdraw"), cleanupTestID(plan.Reservation.ID, "cleanup-withdraw")
	stage := func(name string) api.BlobRef {
		meta, err := f.State.ObjectMetadata(ctx, scope, cleanupTestID(plan.Reservation.ID, name))
		if err != nil {
			t.Fatal("actual planner did not retain the cleanup stage", name, err)
		}
		return meta.Ref
	}
	in, out := stage("input-injection"), stage("result-injection")
	injection := f.Plan.Injection
	job := api.PlanCleanup{ID: jobCause.EffectID, Kind: "withdraw", Cause: jobCause, ReservationID: plan.Reservation.ID, LaunchID: plan.Reservation.LaunchID,
		Slot: f.Plan.Runner.Slot, SlotKnown: true, SlotResult: stage("result-credential-slot"), Injection: &injection, InjectionIn: &in, InjectionOut: &out,
		Prepared: &n.request.Prepared, Withdrawal: &api.CredentialWithdrawalRequest{ProjectionID: held.Authority.ID, ExpectedGeneration: held.Generation, Cause: jobCause, Reason: "refused"}}
	next := plan
	next.Generation++
	next.Phase, next.Error = "failed", serviceError(api.CodePrerequisite, "component start failed before opening its retained gate")
	if _, err := f.State.FailPlan(ctx, api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: plan.Reservation.ID, Generation: plan.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: plan.Reservation.Target.LifeID, Epoch: plan.Reservation.CancellationEpoch}}}}, []api.PlanCleanup{job}); err != nil {
		t.Fatal("failed projected start did not retain its actual cleanup", err)
	}
	scope.Actor.ID = fx.ID(t)
	claim, err := f.State.ClaimPlanCleanup(ctx, scope, job, api.EffectClaimRequest{EffectID: job.ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(n.clock.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	owner := any(n.p.broker).(api.PlanCleanupExecutor)
	receipt, err := owner.ExecutePlanCleanup(ctx, scope, claim)
	if err != nil {
		t.Fatal("real broker did not withdraw the failed start before collection", err)
	}
	if receipt.Withdrawal == nil || receipt.Withdrawal.State != "withdrawn" || receipt.Withdrawal.Withdrawal == nil || receipt.Abort == nil || receipt.Abort.PreparedID != n.request.Prepared.ID {
		t.Fatal("projected cleanup lost its original withdrawal or nonexecuting native proof")
	}
	if read, err := owner.ReadPlanCleanupReceipt(ctx, scope, claim); err != nil || !reflect.DeepEqual(read, receipt) {
		t.Fatal("projected cleanup independent read differs", err)
	}
	if replay, err := owner.ExecutePlanCleanup(ctx, scope, claim); err != nil || !reflect.DeepEqual(replay, receipt) || helper.native.calls != 1 {
		t.Fatal("projected cleanup retry repeated collection or replaced a receipt", err)
	}
	if _, err := f.State.CompletePlanCleanup(ctx, scope, claim, receipt, owner); err != nil {
		t.Fatal(err)
	}
	if verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("projected failed-start cleanup did not verify", err)
	}
}
