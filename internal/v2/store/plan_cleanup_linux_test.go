//go:build linux

package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func cleanupID(r api.ID, stage string) api.ID {
	return api.ID(fx.Digest([]byte("launch\x00" + string(r) + "\x00" + stage)))
}

func retainCleanupStage(t *testing.T, f *fx.Fixture, stage string, value any) api.BlobRef {
	t.Helper()
	raw, err := api.CanonicalJSON(fx.JSON(t, value))
	if err != nil {
		t.Fatal(err)
	}
	r := f.Reservation
	cause := f.Intent(t, api.InternalLaunchPlan)
	ref, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: cause,
		Object: api.ObjectWrite{ObjectKey: cleanupID(r.ID, stage), Class: "manifest", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
			ACL: api.ObjectACL{Config: r.Config, Owner: f.Execution.Actor, LifeID: r.Target.LifeID, Audience: "service", Generation: r.Generation}}})
	if err != nil {
		t.Fatal("cleanup stage retention setup failed", err)
	}
	return ref
}

func failedPlanFixture(t *testing.T, bound bool) (*fx.Fixture, api.Transaction, []api.PlanCleanup) {
	t.Helper()
	return failedPlanFixtureKnown(t, bound, true)
}

func failedPlanFixtureKnown(t *testing.T, bound, known bool) (*fx.Fixture, api.Transaction, []api.PlanCleanup) {
	t.Helper()
	phase := "sourced"
	if bound {
		phase = "bound"
	}
	return failedPlanFixtureAt(t, phase, known)
}

func failedPlanFixtureAt(t *testing.T, phase string, known bool, projected ...bool) (*fx.Fixture, api.Transaction, []api.PlanCleanup) {
	t.Helper()
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	if phase != "sourced" {
		if len(projected) == 1 && projected[0] {
			f.BuildPlanForIdentity(t, true, uint32(os.Geteuid())+1000, uint32(os.Getegid())+1000)
		} else {
			f.BuildPlan(t, true)
		}
		f.Spec(t)
		f.PrepareJob(t)
		if len(projected) == 1 && projected[0] {
			n, request := installCredentialFixture(t, f)
			reserved, err := f.State.ReserveCredentialProjection(context.Background(), f.Execution, request)
			if err != nil {
				t.Fatal("cleanup could not reserve actual projection", err)
			}
			if _, err := f.State.CommitCredentialProjection(context.Background(), f.Execution, credentialHeld(t, n, reserved)); err != nil {
				t.Fatal("cleanup could not commit actual projection", err)
			}
		}
		if phase == "bound" {
			f.Bind(t)
		}
	}
	bound := phase == "bound"
	r := f.Reservation
	profile := f.Record.Inputs.Grants.Profiles[0]
	slot := api.CredentialSlot{ID: fx.ID(t), LeaseID: fx.ID(t), ProfileGrantID: profile.ID, ProfileID: profile.ProfileID, Mode: "codex-file", ExpiresAt: fx.Expiry()}
	if f.Record.Plan != nil {
		slot = f.Plan.Runner.Slot
	}
	inputSlot := retainCleanupStage(t, f, "input-credential-slot", struct{ Target api.LifeRef }{r.Target})
	result := func(input api.BlobRef, value any) any {
		return struct {
			Schema string          `json:"schema"`
			Input  api.Digest      `json:"input"`
			Value  json.RawMessage `json:"value"`
		}{"laneboss.launch-stage.v2", input.SHA256, fx.JSON(t, value)}
	}
	var slotOutcome any = result(inputSlot, slot)
	uncertainty := &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-secrets", Message: "component slot outcome requires reconciliation"}
	if !known {
		slotOutcome = struct {
			Schema string     `json:"schema"`
			Input  api.Digest `json:"input"`
			Error  *api.Error `json:"error"`
		}{"laneboss.launch-stage.v2", inputSlot.SHA256, uncertainty}
	}
	slotResult := retainCleanupStage(t, f, "result-credential-slot", slotOutcome)
	injection := api.Injection{Target: r.Target, SlotIDs: []api.ID{slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{},
		GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}
	var in, out api.BlobRef
	if known {
		in = retainCleanupStage(t, f, "input-injection", struct{ Slot api.ID }{slot.ID})
		out = retainCleanupStage(t, f, "result-injection", result(in, injection))
	}
	cause := f.Intent(t, api.InternalLaunchPlan)
	cause.ID = cleanupID(r.ID, "cause-write")
	cause.LogicalTurnID = f.Claim.Record.Effect.Context.LogicalTurnID
	next := f.Record
	next.Phase, next.Generation = "failed", next.Generation+1
	next.Error = &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-lifecycle", Message: "component retained planning refusal"}
	input := api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: f.Record.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
	kinds := []string{"release", "revoke_injection"}
	if bound {
		kinds = []string{"withdraw"}
	}
	jobs := make([]api.PlanCleanup, 0, len(kinds))
	for _, kind := range kinds {
		jobCause := cause
		jobCause.ID = cleanupID(r.ID, "cause-cleanup-"+kind)
		jobCause.Kind, jobCause.EffectID = api.InternalHelperRelease, cleanupID(r.ID, "cleanup-"+kind)
		job := api.PlanCleanup{ID: jobCause.EffectID, Kind: kind, Cause: jobCause, ReservationID: r.ID, LaunchID: r.LaunchID,
			Slot: slot, SlotKnown: true, SlotResult: slotResult, Injection: &injection, InjectionIn: &in, InjectionOut: &out}
		if !known {
			job.Slot, job.SlotKnown, job.Injection, job.InjectionIn, job.InjectionOut = api.CredentialSlot{}, false, nil, nil, nil
			job.Issues = []*api.Error{uncertainty}
		}
		if bound {
			job.Cause.Kind, job.Prepared = api.InternalHelperAbort, &f.Prepared
			projection, lookupErr := f.State.CredentialProjection(context.Background(), r.Config, f.Prepared.ID)
			if lookupErr == nil {
				job.Withdrawal = &api.CredentialWithdrawalRequest{ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Cause: job.Cause, Reason: "refused"}
			} else {
				var refusal *api.Error
				if !errors.As(lookupErr, &refusal) || refusal.Code != api.CodeNotFound {
					t.Fatal("projection uncertainty fixture lost its actual owning refusal", lookupErr)
				}
				job.Issues = []*api.Error{refusal}
			}
		}
		jobs = append(jobs, job)
	}
	if err := api.ValidateFailedPlanWrite(input, jobs); err != nil {
		t.Fatal("failed plan preflight setup failed", err)
	}
	if err := api.ValidateTransactionShape(input); err == nil {
		t.Fatal("ordinary transaction preflight accepted a failed planner revision")
	} else {
		launchCode(t, err, api.CodeInvalid)
	}
	// Check actual required identities before the atomicity control. An absent
	// logical turn or unused resource is retained as absent, never filled with
	// an invented ID to make an internal request look like a public RPC.
	for _, job := range jobs {
		for _, id := range []api.ID{job.ID, job.ReservationID, job.LaunchID, job.Cause.ID, job.Cause.Actor.ID,
			job.Cause.CauseOperationID, job.Cause.CauseRequestID, job.Cause.EffectID, job.Cause.Target.LifeID, job.SlotResult.ID} {
			if !wire.ValidID(string(id)) {
				t.Fatal("cleanup fixture has an invalid retained selector")
			}
		}
		if job.Cause.LogicalTurnID != f.Claim.Record.Effect.Context.LogicalTurnID {
			t.Fatal("cleanup fixture changed its original planning turn")
		}
		for _, ref := range []*api.BlobRef{job.InjectionIn, job.InjectionOut} {
			if ref != nil && !wire.ValidID(string(ref.ID)) {
				t.Fatal("cleanup fixture has an invalid retained stage ID")
			}
		}
		if job.SlotKnown {
			var retained api.CredentialSlot
			if err := wire.Decode(fx.JSON(t, job.Slot), &retained); err != nil || retained != job.Slot {
				t.Fatal("cleanup fixture has an invalid known slot", err)
			}
		}
	}
	return f, input, jobs
}

func cleanupDDL(t *testing.T, f *fx.Fixture, statement string) {
	t.Helper()
	// Fault injection changes only this test's trigger. Production immutability
	// triggers remain installed; there is no second production state writer.
	db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := db.Exec(statement)
	closeErr := db.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("cleanup transaction fault fixture failed", writeErr, closeErr)
	}
}

func TestFailedPlanAtomic(t *testing.T) {
	for _, mode := range []string{"commit", "rollback", "policy", "withdraw", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f, input, jobs := failedPlanFixtureKnown(t, mode == "withdraw", mode != "unknown")
			ctx := context.Background()
			// The lifecycle caller reuses its deterministic write cause. Its
			// earlier generic receipt must coexist with this private-port receipt.
			prior := api.Transaction{Scope: input.Scope, Internal: input.Internal, Guards: input.Guards}
			if _, err := f.State.Transact(ctx, prior); err != nil {
				t.Fatal("prior planner receipt setup failed", err)
			}
			if mode == "policy" {
				publishFixturePolicy(t, f)
			}
			installed := false
			if mode == "rollback" {
				cleanupDDL(t, f, "CREATE TRIGGER component_cleanup_failure BEFORE INSERT ON projection_history WHEN NEW.kind='plan_cleanup' BEGIN SELECT RAISE(ABORT, 'component cleanup append denied'); END")
				installed = true
				t.Cleanup(func() {
					if installed {
						cleanupDDL(t, f, "DROP TRIGGER component_cleanup_failure")
					}
				})
			}
			commit, writeErr := f.State.FailPlan(ctx, input, jobs)
			var invalid *api.Error
			if errors.As(writeErr, &invalid) && invalid.Code == api.CodeInvalid {
				t.Fatal("private cleanup copy rejected retained selectors", writeErr)
			}
			if mode == "rollback" {
				actual, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
				if err != nil {
					t.Fatal("cleanup rollback read-back failed", err)
				}
				pending, err := f.State.PendingPlanCleanup(ctx, f.Execution)
				if err != nil {
					t.Fatal("cleanup rollback inventory failed", err)
				}
				if writeErr == nil || !reflect.DeepEqual(actual, f.Record) || len(pending) != 0 {
					t.Fatal("cleanup append failure left a partial plan", writeErr)
				}
				if !strings.Contains(writeErr.Error(), "component cleanup append denied") {
					t.Fatal("cleanup rollback refused before its intended append", writeErr)
				}
				cleanupDDL(t, f, "DROP TRIGGER component_cleanup_failure")
				installed = false
				commit, writeErr = f.State.FailPlan(ctx, input, jobs)
			}
			if writeErr != nil || commit.Operation.ID != f.Reservation.OperationID {
				t.Fatal("failed plan and cleanup did not commit together", writeErr)
			}
			actual, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
			if err != nil || !reflect.DeepEqual(actual, input.Writes.LaunchPlans[0]) {
				t.Fatal("failed cleanup commit changed the retained plan", err)
			}
			for _, job := range jobs {
				retained, err := f.State.PlanCleanup(ctx, f.Execution, job.ID)
				// Compare the complete durable value. Private error diagnostics
				// intentionally do not cross the store's JSON boundary.
				if err != nil || !bytes.Equal(fx.JSON(t, retained), fx.JSON(t, job)) {
					t.Fatal("failed plan lost an atomic cleanup request", err)
				}
			}
			requests, err := f.State.DispatchRequests(ctx)
			if err != nil || len(requests) != 1 || requests[0] != f.Reservation.OperationID {
				t.Fatal("pending cleanup disappeared from drain inventory", err)
			}
			targets, err := f.State.DispatchTargets(ctx)
			found := false
			for _, target := range targets {
				found = found || target == f.Reservation.Target
			}
			if err != nil || !found {
				t.Fatal("pending cleanup lost its original dispatch target", err)
			}
			if verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
				t.Fatal("atomic cleanup broke store verification", err)
			}
			if err := f.State.Close(); err != nil {
				t.Fatal(err)
			}
			f.State, err = store.New(f.Deps)
			if err != nil {
				t.Fatal("atomic cleanup did not survive writer reopen", err)
			}
			pending, err := f.State.PendingPlanCleanup(ctx, f.Execution)
			if err != nil || len(pending) != len(jobs) {
				t.Fatal("writer reopen lost pending cleanup", err)
			}
			if mode == "commit" {
				f.ExpireClaim(t)
			}
			if replay, err := f.State.FailPlan(ctx, input, jobs); err != nil || !replay.Replayed || replay.Operation.ID != commit.Operation.ID {
				t.Fatal("exact failed-plan cleanup did not replay", err)
			}
			changed := append([]api.PlanCleanup(nil), jobs...)
			for i := range changed {
				changed[i].Issues = append(append([]*api.Error(nil), changed[i].Issues...), &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-service", Message: "component changed retry"})
			}
			if err := api.ValidateFailedPlanWrite(input, changed); err != nil {
				t.Fatal("changed cleanup replay lost its valid shared shape", err)
			}
			if _, err := f.State.FailPlan(ctx, input, changed); err == nil {
				t.Fatal("cleanup replay accepted changed request bytes")
			} else {
				launchCode(t, err, api.CodeIdempotencyConflict)
			}
		})
	}
}

func TestFailedPlanGuards(t *testing.T) {
	for _, mode := range []string{"claim", "epoch", "selector", "injection", "projection", "unbound_projection", "generic"} {
		t.Run(mode, func(t *testing.T) {
			phase := "sourced"
			if mode == "epoch" || mode == "projection" {
				phase = "bound"
			} else if mode == "unbound_projection" {
				phase = "prepared"
			}
			f, input, jobs := failedPlanFixtureAt(t, phase, true, mode == "projection" || mode == "unbound_projection")
			want := api.CodeForbidden
			switch mode {
			case "claim":
				f.ExpireClaim(t)
				want = api.CodeConflict
			case "epoch":
				lane := f.Lane
				lane.CancellationEpoch++
				f.Replace(t, "lane", lane.LifeID, lane.Generation, lane)
				want = api.CodeConflict
			case "selector":
				jobs[0].LaunchID = fx.ID(t)
				want = api.CodeInvalid
			case "injection":
				for i := range jobs {
					jobs[i].Injection, jobs[i].InjectionOut = nil, nil
				}
				want = api.CodeIntegrity
			case "generic":
				want = api.CodeInvalid
			case "unbound_projection":
				// The real unbound holding requires withdrawal before ordinary release.
			case "projection":
				projection, err := f.State.CredentialProjection(context.Background(), f.Deps.Config, f.Prepared.ID)
				if err != nil {
					t.Fatal("cleanup lost its actual projection", err)
				}
				jobs[0].Withdrawal = &api.CredentialWithdrawalRequest{ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Cause: jobs[0].Cause, Reason: "refused"}
				if err := api.ValidateCredentialWithdrawalRequest(projection, *jobs[0].Withdrawal); err != nil {
					t.Fatal("projection revision control setup failed", err)
				}
				jobs[0].Withdrawal.ExpectedGeneration++
				want = api.CodeInvalid
			}
			if mode != "selector" {
				if err := api.ValidateFailedPlanWrite(input, jobs); err != nil {
					t.Fatal("cleanup guard fixture lost its valid shared shape", err)
				}
			}
			var err error
			if mode == "generic" {
				_, err = f.State.Transact(context.Background(), input)
			} else {
				_, err = f.State.FailPlan(context.Background(), input, jobs)
			}
			if err == nil {
				t.Fatal("failed-plan cleanup guard accepted " + mode)
			}
			launchCode(t, err, want)
			actual, err := f.State.LaunchPlan(context.Background(), f.Execution, f.Reservation.ID)
			if err != nil || !reflect.DeepEqual(actual, f.Record) {
				t.Fatal("failed cleanup guard partially changed its plan", err)
			}
			pending, err := f.State.PendingPlanCleanup(context.Background(), f.Execution)
			if err != nil || len(pending) != 0 {
				t.Fatal("failed cleanup guard partially queued requests", err)
			}
		})
	}
}
