//go:build linux

package store

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// Native release/abort facts are component inputs. Claim, retained evidence and
// terminal operation are written by the real SQLite store.
func retiredProof(t *testing.T, f *archFixture) archivejob.Retirement {
	t.Helper()
	zero, exit := uint64(0), 9
	at := api.Timestamp(f.s.deps.Clock.Now().UTC().Format(timeFormat))
	observation := api.ProcessObservation{Handle: f.record.Process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "cut", ObservedAt: at}
	return archivejob.Retirement{JobID: f.record.Job.ID, OperationID: f.record.Job.Intent.OperationID, EffectID: f.record.Job.Lease.EffectID, Target: f.record.Job.Intent.Request.Target, Allocation: f.record.Allocation, ObservedAt: at,
		Release: &api.ReleaseReceipt{ID: testID(t), LeaseID: f.record.Allocation.ID, ContainmentID: f.record.Allocation.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: f.record.Job.Intent.OperationID, EffectID: f.record.Job.Lease.EffectID, Quiescence: observation, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: at}}
}

func TestArchiveRetireAfterExpiry(t *testing.T) {
	f := newArch(t)
	ctx := context.Background()
	expires, err := time.Parse(time.RFC3339Nano, string(f.record.Job.Lease.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	f.s.deps.Clock = &r2Clock{at: expires.Add(time.Second)}
	current, err := f.s.Effect(ctx, f.executor, f.record.Job.Lease.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.s.ClaimOwnedRecovery(ctx, f.executor, api.EffectClaimRequest{EffectID: current.Effect.ID, ExpectedGeneration: current.Generation, ClaimantID: f.executor.Actor.ID, Deadline: api.Timestamp(expires.Add(time.Minute).UTC().Format(timeFormat))})
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.s.ArchiveRecovery(ctx, f.executor, claim)
	if err != nil || state.Process != f.record.Process || state.Job.ID != f.record.Job.ID {
		t.Fatal("expired worker could not be measured under its original recovery claim", err)
	}
	proof := retiredProof(t, f)
	one := uint64(1)
	proof.Release.Quiescence.Survivors = &one
	if err := f.s.RecordArchiveRetirement(ctx, f.executor, claim, proof); err == nil {
		t.Fatal("native release with survivors authorized archive retirement")
	} else {
		expectCode(t, err, api.CodeContainmentUnknown)
	}
	proof = retiredProof(t, f)
	if err := f.s.RecordArchiveRetirement(ctx, f.executor, claim, proof); err != nil {
		t.Fatal("measured expired worker could not retain its release", err)
	}
	failure := &api.Error{Code: api.CodeDeadline, Message: "archive work budget expired", Instead: "Inspect the retained native release and preserve the archive sources."}
	commit, err := callOwnedFailure(f.s, ctx, f.executor, claim, failure, &proof.Release.Quiescence)
	if err != nil || commit.Operation.Status != "failed" {
		t.Fatal("measured expired archive stayed pending forever", err)
	}
}

func TestArchiveAllocationMustRetire(t *testing.T) {
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
	if err := f.s.BeginArchiveAllocation(ctx, f.executor, claim); err != nil {
		t.Fatal(err)
	}
	failure := &api.Error{Code: api.CodeBudget, Message: "allocation reply was lost", Instead: "Reconcile the original helper allocation."}
	if _, err := callOwnedFailure(f.s, ctx, f.executor, claim, failure, nil); err == nil {
		t.Fatal("unmeasured allocation intent sealed a nil-observation failure")
	} else {
		expectCode(t, err, api.CodeContainmentUnknown)
	}
	allocation := api.HelperLease{ID: testID(t), UID: 31001, GID: 31001, ContainmentID: testID(t), EndpointGeneration: 1}
	if err := f.s.RecordArchiveAllocation(ctx, f.executor, claim, allocation); err != nil {
		t.Fatal(err)
	}
	at := archStamp()
	proof := archivejob.Retirement{JobID: job.ID, OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID, Target: job.Intent.Request.Target, ObservedAt: at, Absent: true}
	if err := f.s.RecordArchiveRetirement(ctx, f.executor, claim, proof); err == nil {
		t.Fatal("absence proof erased an actually recorded helper allocation")
	}
	zero := uint64(0)
	proof.Absent, proof.Allocation = false, allocation
	proof.Abort = &api.AbortReceipt{ID: testID(t), LeaseID: allocation.ID, AgentExecuted: false, ObservedAt: at,
		Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{Target: job.Intent.Request.Target, ContainmentID: allocation.ContainmentID}, State: "not_started", Survivors: &zero, PromptStatus: "not_written", ObservedAt: at}}
	if err := f.s.RecordArchiveRetirement(ctx, f.executor, claim, proof); err != nil {
		t.Fatal("native unopened allocation abort could not be retained", err)
	}
	commit, err := callOwnedFailure(f.s, ctx, f.executor, claim, failure, nil)
	if err != nil || commit.Operation.Status != "failed" {
		t.Fatal("measured allocation abort could not finish its original failure", err)
	}
}

func TestCollectCountsEffectOutcome(t *testing.T) {
	f := newCollect(t)
	ctx := context.Background()
	archived, err := f.arch.s.Effect(ctx, f.arch.executor, f.arch.record.Job.Lease.EffectID)
	if err != nil || archived.Outcome == nil {
		t.Fatal(err)
	}
	// A reference in the actual durable outcome is a root even when no input
	// or projection mentions it. This is a negative reference-source fixture.
	archived.Outcome.Output = &f.scratch
	raw, err := encodeEffectState(archived)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.arch.s.db.ExecContext(ctx, "UPDATE effect_states SET data=? WHERE id=?", raw, string(archived.Effect.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.arch.s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory); err == nil {
		t.Fatal("effect-only output reference was omitted from the cleanup fence")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
	if _, _, err := objectRow(ctx, f.arch.s.db, f.scratch.ID); err != nil {
		t.Fatal("effect-referenced bytes were removed", err)
	}
}

func TestRetirementCutsWorkerReads(t *testing.T) {
	f := newArch(t)
	ctx := context.Background()
	if _, err := f.s.WorkerInput(ctx, f.worker, api.WorkerInputRequest{LeaseID: f.record.Job.Lease.ID}); err != nil {
		t.Fatal("original live worker could not read its fixed input", err)
	}
	if err := f.s.RecordArchiveRetirement(ctx, f.executor, f.record.Claim, retiredProof(t, f)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.WorkerInput(ctx, f.worker, api.WorkerInputRequest{LeaseID: f.record.Job.Lease.ID}); err == nil {
		t.Fatal("retired archive retained worker socket authority")
	} else {
		expectCode(t, err, api.CodeForbidden)
	}
}
