//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func cleanupTestID(reservation api.ID, stage string) api.ID {
	return api.ID(fx.Digest([]byte("launch\x00" + string(reservation) + "\x00" + stage)))
}

// Preserve the real broker's projection methods while deliberately removing
// the private cleanup executor. An unconfigured concrete broker still has that
// executor once its implementation is linked and is not an absence control.
type cleanupProjectionOnly struct {
	api.CredentialProjectionBroker
}

func withoutCleanupExecutor(t *testing.T, broker api.CredentialProjectionBroker) api.CredentialProjectionBroker {
	t.Helper()
	if _, ok := broker.(api.PlanCleanupExecutor); !ok {
		t.Fatal("missing-executor control requires a real executor to remove")
	}
	missing := cleanupProjectionOnly{CredentialProjectionBroker: broker}
	if _, ok := any(missing).(api.PlanCleanupExecutor); ok {
		t.Fatal("missing-executor control retained the cleanup execution capability")
	}
	return missing
}

func cleanupReconcileFixture(t *testing.T) (*fx.Fixture, []api.PlanCleanup) {
	t.Helper()
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.PrepareJob(t)
	r := f.Reservation
	retain := func(stage string, value any) api.BlobRef {
		raw := fx.JSON(t, value)
		ref, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalLaunchPlan),
			Object: api.ObjectWrite{ObjectKey: cleanupTestID(r.ID, stage), Class: "manifest", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
				ACL: api.ObjectACL{Config: r.Config, Owner: f.Execution.Actor, LifeID: r.Target.LifeID, Audience: "service", Generation: r.Generation}}})
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	result := func(input api.BlobRef, value any) any {
		return struct {
			Schema string          `json:"schema"`
			Input  api.Digest      `json:"input"`
			Value  json.RawMessage `json:"value"`
		}{"laneboss.launch-stage.v2", input.SHA256, fx.JSON(t, value)}
	}
	slotInput := retain("input-credential-slot", struct{ Target api.LifeRef }{r.Target})
	slotResult := retain("result-credential-slot", result(slotInput, f.Plan.Runner.Slot))
	injectionInput := retain("input-injection", struct{ Target api.LifeRef }{r.Target})
	injectionResult := retain("result-injection", result(injectionInput, f.Plan.Injection))
	next := f.Record
	next.Generation++
	next.Phase, next.Error = "failed", &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-admin", Message: "component native prepare refused"}
	cause := f.Intent(t, api.InternalLaunchPlan)
	cause.ID, cause.LogicalTurnID = cleanupTestID(r.ID, "cause-write"), f.Claim.Record.Effect.Context.LogicalTurnID
	jobs := make([]api.PlanCleanup, 0, 2)
	for _, kind := range []string{"release", "revoke_injection"} {
		cleanupCause := cause
		cleanupCause.ID, cleanupCause.EffectID = cleanupTestID(r.ID, "cause-cleanup-"+kind), cleanupTestID(r.ID, "cleanup-"+kind)
		cleanupCause.Kind = api.InternalHelperRelease
		injection := f.Plan.Injection
		jobs = append(jobs, api.PlanCleanup{ID: cleanupCause.EffectID, Kind: kind, Cause: cleanupCause, ReservationID: r.ID, LaunchID: r.LaunchID,
			Slot: f.Plan.Runner.Slot, SlotKnown: true, SlotResult: slotResult, Injection: &injection, InjectionIn: &injectionInput, InjectionOut: &injectionResult})
	}
	tx := api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: f.Record.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
	if _, err := f.State.FailPlan(context.Background(), tx, jobs); err != nil {
		t.Fatal("real failure writer did not retain the cleanup batch", err)
	}
	return f, jobs
}

// This wrapper observes the real writer; it supplies no claim or completion.
type cleanupReconcileStore struct {
	*store.Service
	stop             context.CancelFunc
	clock            api.Clock
	mode             string
	claims           []api.PlanCleanupClaim
	completed        int
	refusals         int
	shortFirst       bool
	cancelAfterClaim bool
	releaseLast      bool
}

func (s *cleanupReconcileStore) PendingPlanCleanup(ctx context.Context, scope api.Scope) ([]api.PlanCleanup, error) {
	jobs, err := s.Service.PendingPlanCleanup(ctx, scope)
	if err != nil {
		return nil, err
	}
	if s.releaseLast && len(jobs) == 2 && jobs[0].Kind == "release" {
		jobs[0], jobs[1] = jobs[1], jobs[0]
	}
	return jobs, nil
}

func (s *cleanupReconcileStore) ClaimPlanCleanup(ctx context.Context, scope api.Scope, job api.PlanCleanup, request api.EffectClaimRequest) (api.PlanCleanupClaim, error) {
	if s.shortFirst && len(s.claims) == 0 {
		request.Deadline = api.Timestamp(s.clock.Now().Add(time.Second).UTC().Format(time.RFC3339Nano))
	}
	claim, err := s.Service.ClaimPlanCleanup(ctx, scope, job, request)
	if err == nil {
		s.claims = append(s.claims, claim)
		if s.cancelAfterClaim {
			s.stop()
		}
	}
	return claim, err
}

func TestFailedPlanCleanupCancellation(t *testing.T) {
	wantRefusal := api.NotImplemented("lb-v2-secrets", "protected failed-plan cleanup execution and journal read-back")
	for _, boundary := range []string{"after_claim", "after_refusal"} {
		t.Run(boundary, func(t *testing.T) {
			f, jobs := cleanupReconcileFixture(t)
			// Only the real claim/refusal callbacks cancel successfully. This
			// deadline is a hang guard; expiration cannot satisfy the test.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			state := &cleanupReconcileStore{Service: f.State, stop: cancel, clock: f.Deps.Clock, mode: "missing",
				cancelAfterClaim: boundary == "after_claim", releaseLast: true}
			host := fixtureServer(t)
			host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, f.Deps.Clock
			host.runtime = api.RuntimeServices{Store: state, Helper: &admin.Service{}, Credentials: withoutCleanupExecutor(t, &secrets.Service{})}
			host.reconcileLoop(ctx)
			if !errors.Is(ctx.Err(), context.Canceled) || len(state.claims) != 1 || state.completed != 0 {
				t.Fatal("cancellation control missed its real claimed cleanup boundary")
			}
			status, err := f.State.PlanCleanupStatus(context.Background(), f.Execution, jobs[0].ID)
			if err != nil || status.State != "pending" || status.Receipt != nil || !reflect.DeepEqual(status.Refusal, wantRefusal) || state.refusals != 1 {
				t.Fatal("shutdown discarded the actual missing-executor refusal", err)
			}
			if host.fault != nil {
				t.Fatal("ordinary shutdown became a reconciliation fault after durable refusal", host.fault)
			}
		})
	}
}

func (s *cleanupReconcileStore) CompletePlanCleanup(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, receipt api.PlanCleanupReceipt, reads api.PlanCleanupExecutor) (api.PlanCleanupReceipt, error) {
	actual, err := s.Service.CompletePlanCleanup(ctx, scope, claim, receipt, reads)
	if err == nil {
		s.completed++
		if s.completed == 2 {
			s.stop()
		}
	}
	return actual, err
}

func (s *cleanupReconcileStore) RecordPlanCleanupRefusal(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, cause *api.Error) error {
	err := s.Service.RecordPlanCleanupRefusal(ctx, scope, claim, cause)
	if err == nil {
		s.refusals++
		if s.mode == "missing" {
			s.stop()
		}
	}
	return err
}

// Native helper/broker results are explicit component inputs. This test proves
// the installed reconciliation loop and concrete writer, not native collection.
// A complete-looking enqueue is never a substitute for the independent read.
type cleanupReconcileOwner struct {
	api.CredentialProjectionBroker
	t        *testing.T
	f        *fx.Fixture
	store    *cleanupReconcileStore
	mode     string
	calls    int
	reads    int
	receipts map[api.ID]api.PlanCleanupReceipt
}

func (o *cleanupReconcileOwner) ExecutePlanCleanup(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) (api.PlanCleanupReceipt, error) {
	if err := o.store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	o.calls++
	if o.mode == "retry" && o.calls == 1 {
		return api.PlanCleanupReceipt{}, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-secrets", Message: "component broker temporarily unavailable", Retryable: true}
	}
	if o.mode == "deadline" && o.calls == 1 {
		<-ctx.Done()
		return api.PlanCleanupReceipt{}, ctx.Err()
	}
	if o.mode == "integrity" {
		return api.PlanCleanupReceipt{}, serviceError(api.CodeIntegrity, "component native journal differs from its original selector")
	}
	if receipt, found := o.receipts[claim.Request.ID]; found {
		return receipt, nil
	}
	allocation, err := o.store.PlanCleanupAllocation(ctx, scope, claim)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	job := claim.Request
	zero := uint64(0)
	now := api.Timestamp(o.store.clock.Now().UTC().Format(time.RFC3339Nano))
	abort := &api.AbortReceipt{ID: fx.ID(o.t), LeaseID: allocation.ID, ObservedAt: now,
		Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{Target: job.Cause.Target, ContainmentID: allocation.ContainmentID}, State: "not_started", Survivors: &zero, PromptStatus: "not_written", ObservedAt: now}}
	if job.Kind == "revoke_injection" {
		for _, prior := range o.receipts {
			if prior.ReservationID == job.ReservationID && prior.Kind == "release" {
				abort = prior.Abort
			}
		}
	}
	ack := api.PlanCleanupBrokerReceipt{CleanupID: job.ID, ReservationID: job.ReservationID, LaunchID: job.LaunchID, Kind: job.Kind,
		Slot: job.Slot, Injection: job.Injection, NativeReceiptID: abort.ID, CompletedAt: now}
	raw := fx.JSON(o.t, ack)
	cause := o.f.Intent(o.t, api.InternalOrgBootstrap)
	cause.Actor = scope.Actor
	ref, err := o.f.State.RetainObject(ctx, scope, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: fx.ID(o.t),
		Class: "manifest", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: job.Cause.Target.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	receipt := api.PlanCleanupReceipt{ID: fx.ID(o.t), CleanupID: job.ID, ReservationID: job.ReservationID, LaunchID: job.LaunchID,
		Kind: job.Kind, SlotID: job.Slot.ID, Allocation: allocation, Broker: ref, Abort: abort, CompletedAt: now}
	o.receipts[job.ID] = receipt
	return receipt, nil
}

func (o *cleanupReconcileOwner) ReadPlanCleanupReceipt(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) (api.PlanCleanupReceipt, error) {
	if err := o.store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	o.reads++
	receipt, found := o.receipts[claim.Request.ID]
	if !found {
		return api.PlanCleanupReceipt{}, serviceError(api.CodeNotFound, "component native journal has no original receipt")
	}
	if o.mode == "readback" {
		receipt.ID = fx.ID(o.t)
	}
	return receipt, nil
}

func TestFailedPlanCleanupRealReconciler(t *testing.T) {
	for _, mode := range []string{"complete", "retry", "deadline", "missing", "integrity", "readback"} {
		t.Run(mode, func(t *testing.T) {
			f, jobs := cleanupReconcileFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			state := &cleanupReconcileStore{Service: f.State, stop: cancel, clock: f.Deps.Clock, mode: mode, shortFirst: mode == "deadline"}
			owner := &cleanupReconcileOwner{t: t, f: f, store: state, mode: mode, receipts: map[api.ID]api.PlanCleanupReceipt{}}
			host := fixtureServer(t)
			host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, f.Deps.Clock
			host.runtime = api.RuntimeServices{Store: state, Helper: &admin.Service{}, Credentials: owner}
			if mode == "missing" {
				// Remove the actual executor instead of depending on which
				// prerequisite an unconfigured concrete broker refuses first.
				host.runtime.Credentials = withoutCleanupExecutor(t, &secrets.Service{})
			}
			host.reconcileLoop(ctx)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("real reconciler did not consume the retained cleanup request")
			}
			scope := f.Execution
			if mode == "missing" {
				wantRefusal := api.NotImplemented("lb-v2-secrets", "protected failed-plan cleanup execution and journal read-back")
				found := false
				for _, job := range jobs {
					status, err := state.PlanCleanupStatus(context.Background(), scope, job.ID)
					if err != nil || status.Receipt != nil {
						t.Fatal("missing executor fabricated cleanup completion", err)
					}
					if status.Refusal != nil {
						found = true
						if !reflect.DeepEqual(status.Refusal, wantRefusal) || status.State != "pending" {
							t.Fatal("missing executor lost its actual owning refusal")
						}
					}
				}
				if !found || host.fault != nil || state.completed != 0 || state.refusals != 1 {
					t.Fatal("missing executor was silently dropped", host.fault)
				}
				return
			}
			if mode == "integrity" || mode == "readback" {
				codeIs(t, host.fault, api.CodeIntegrity)
				if state.completed != 0 {
					t.Fatal("integrity failure manufactured a terminal acknowledgement")
				}
				return
			}
			if host.fault != nil || state.completed != 2 || owner.reads != 2 {
				t.Fatal("real reconciler lost measured cleanup or independent read-back", host.fault)
			}
			wantClaims := 2
			if mode == "retry" || mode == "deadline" {
				wantClaims++
			}
			if len(state.claims) != wantClaims || owner.calls != wantClaims {
				t.Fatal("retry did not continue the original retained cleanup")
			}
			for i, claim := range state.claims {
				if !reflect.DeepEqual(claim.Request, jobs[0]) && !reflect.DeepEqual(claim.Request, jobs[1]) || claim.ClaimantID == claim.Request.Cause.Actor.ID ||
					i > 0 && claim.ClaimantID == state.claims[i-1].ClaimantID {
					t.Fatal("cleanup retry rewrote its pin or reused the previous claimant")
				}
			}
			if pending, err := state.PendingPlanCleanup(context.Background(), scope); err != nil || len(pending) != 0 {
				t.Fatal("measured cleanup remained dispatchable", err)
			}
			if verified, err := state.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
				t.Fatal("real reconciler broke durable cleanup verification", err)
			}
		})
	}
}
