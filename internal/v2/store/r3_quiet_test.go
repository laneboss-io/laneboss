//go:build linux

package store

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestOwnedRefusesLiveWorker(t *testing.T) {
	for _, mode := range []string{"running", "unknown", "survivors", "unknown_survivors", "missing_status", "ambiguous_status", "nil_started", "nil_handoff", "foreign_process", "future_time"} {
		t.Run(mode, func(t *testing.T) {
			f := newArch(t)
			ctx := context.Background()
			zero, one, exit, signal := uint64(0), uint64(1), 7, 15
			observation := &api.ProcessObservation{Handle: f.record.Process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "cut", ObservedAt: archStamp()}
			switch mode {
			case "running":
				observation.State, observation.ExitCode = "running", nil
			case "unknown":
				observation.State = "unknown"
			case "survivors":
				observation.Survivors = &one
			case "unknown_survivors":
				observation.Survivors = nil
			case "missing_status":
				observation.ExitCode = nil
			case "ambiguous_status":
				observation.Signal = &signal
			case "nil_started":
				observation = nil
			case "nil_handoff":
				f.record.Process = api.ProcessHandle{}
				f.record.Handoff = &api.PreparedSpecHandoff{}
				archSave(t, f.s, f.record)
				observation = nil
			case "foreign_process":
				observation.Handle.ID = testID(t)
			case "future_time":
				observation.ObservedAt = api.Timestamp(time.Now().Add(time.Minute).UTC().Format(timeFormat))
			}
			before, err := f.s.Effect(ctx, f.executor, f.record.Claim.Record.Effect.ID)
			if err != nil {
				t.Fatal(err)
			}
			var worker api.WorkerLease
			if err := storedProjection(ctx, f.s.db, "worker_lease", f.record.Job.Lease.ID, &worker); err != nil {
				t.Fatal(err)
			}
			failure := &api.Error{Code: api.CodeDeadline, Message: "archive attempt exceeded its budget", Instead: "Obtain native quiescence before release."}
			_, err = callOwnedFailure(f.s, ctx, f.executor, f.record.Claim, failure, observation)
			if err == nil {
				t.Fatal("live or uncertain worker sealed an owned failed completion")
			}
			expectCode(t, err, api.CodeContainmentUnknown)
			after, err := f.s.Effect(ctx, f.executor, before.Effect.ID)
			if err != nil || !sameValue(before, after) || after.Outcome != nil {
				t.Fatal("quiescence refusal changed or completed the pending effect", err)
			}
			var retained archiveRecord
			if err := storedProjection(ctx, f.s.db, "archive_job", f.record.Job.Intent.OperationID, &retained); err != nil || retained.Commit != nil || retained.Failure != nil || retained.Allocation != f.record.Allocation {
				t.Fatal("quiescence refusal retired the original containment allocation", err)
			}
			var lease api.WorkerLease
			if err := storedProjection(ctx, f.s.db, "worker_lease", worker.ID, &lease); err != nil || lease != worker {
				t.Fatal("quiescence refusal released or changed the worker lease", err)
			}
			public, err := f.s.lookupReceipt(ctx, f.s.db, f.record.Scope, requestKey(f.record.Request))
			if err != nil || public.Reply != nil || public.Operation.Status != "pending" {
				t.Fatal("quiescence refusal sealed the public failure reply", err)
			}
			if mode == "running" {
				observation.State, observation.ExitCode = "exited", &exit
				if _, err := callOwnedFailure(f.s, ctx, f.executor, f.record.Claim, failure, observation); err != nil {
					t.Fatal("terminal zero-survivor observation could not finish the original claim", err)
				}
			}
		})
	}
}

func TestOwnedFailureBeforeStart(t *testing.T) {
	f := newFreshArch(t)
	ctx := context.Background()
	job, err := f.s.sealArchive(ctx, f.record)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.s.ClaimEffect(ctx, f.executor, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.executor.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	failure := &api.Error{Code: api.CodeBudget, Message: "allocation was refused before native handoff", Instead: "Repair the approved allocation budget."}
	commit, err := callOwnedFailure(f.s, ctx, f.executor, claim, failure, nil)
	if err != nil || commit.Operation.Status != "failed" {
		t.Fatal("failure before worker handoff could not seal without a process observation", err)
	}
}
