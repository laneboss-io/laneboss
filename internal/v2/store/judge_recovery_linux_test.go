//go:build linux

package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The HTTP measurement is real. Native acknowledgement/retirement fields are
// declared component inputs here; the root gate test measures native ownership.
func TestJudgeMeasuredRecovery(t *testing.T) {
	for _, mode := range []string{"measured", "unknown", "foreign", "survivors", "changed"} {
		t.Run(mode, func(t *testing.T) {
			f, input := judgeExecutionFixture(t)
			e, audit := measuredJudgeAudit(t, f, input)
			scope := api.Scope{Config: f.Deps.Config, Actor: e.Intent.Actor, PolicyGeneration: e.Request.Context.PolicyGeneration, Source: "worker"}
			control, ok := any(f.State).(interface {
				PrepareJudgeWorker(context.Context, api.Scope, api.JudgeExecution, api.BlobRef, api.Executable) (api.WorkerLease, error)
				JudgeWorkerJob(context.Context, api.Scope, api.JudgeExecution) (job.Job, error)
				RecoverJudgeExecution(context.Context, api.Scope, api.JudgeExecution) (api.JudgeAudit, error)
			})
			if !ok {
				t.Fatal("native judge measured recovery is not implemented")
			}
			runtime := f.Plan.Inputs.Sources.Runtime.Manifest
			chunk, err := f.State.Blob(context.Background(), f.Execution, api.BlobReadRequest{ObjectID: runtime.ID, Limit: api.MaxChunkBytes})
			if err != nil {
				t.Fatal(err)
			}
			var manifest api.RuntimeManifest
			if json.Unmarshal(chunk.Data, &manifest) != nil {
				t.Fatal("runtime input is invalid")
			}
			lease, err := control.PrepareJudgeWorker(context.Background(), scope, e, runtime, manifest.Bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			native, err := control.JudgeWorkerJob(context.Background(), scope, e)
			if err != nil {
				t.Fatal(err)
			}
			sealed := e
			sealed.Acquired = false
			result := job.Result{Reply: audit.Reply, Fit: audit.Fit}
			if mode == "changed" {
				result.Reply.InputBytes++
			}
			raw := fx.JSON(t, result)
			ref := f.Retain(t, "worker_result", raw, scope.Actor, f.Lane.LifeID)
			ack := map[string]any{"Submission": api.WorkerResultSubmission{LeaseID: lease.ID, ExpectedGeneration: 2, InputSHA256: lease.Input.SHA256, Result: raw},
				"Receipt": api.WorkerResultReceipt{LeaseID: lease.ID, StageID: lease.ID, Generation: 3, Result: ref, CommittedSeq: 1}}
			zero, exit := uint64(0), 0
			observed := api.ProcessObservation{Handle: api.ProcessHandle{ID: native.LaunchID, Target: lease.Target, ContainmentID: "native-group", Generation: "native-generation"},
				State: "exited", Survivors: &zero, ExitCode: &exit, ObservedAt: audit.CompletedAt}
			if mode == "survivors" {
				one := uint64(1)
				observed.Survivors = &one
			}
			stage := map[string]any{"Execution": sealed, "Worker": lease, "Plan": native.Plan, "Claim": native.Claim, "LaunchID": native.LaunchID, "Actor": native.Actor,
				"Observation": observed, "Ack": ack, "ReceivedAt": audit.CompletedAt}
			if mode == "unknown" {
				delete(stage, "Ack")
			}
			f.Replace(t, "judge_native", e.ID, 2, stage)
			if mode == "foreign" {
				e.ClaimID = fx.ID(t)
			}
			// Reopen the real service-owned store before recovering the original
			// retained result. Recovery is not an in-memory worker return.
			if err := f.State.Close(); err != nil {
				t.Fatal(err)
			}
			f.State, err = store.New(f.Deps)
			if err != nil {
				t.Fatal(err)
			}
			control = any(f.State).(interface {
				PrepareJudgeWorker(context.Context, api.Scope, api.JudgeExecution, api.BlobRef, api.Executable) (api.WorkerLease, error)
				JudgeWorkerJob(context.Context, api.Scope, api.JudgeExecution) (job.Job, error)
				RecoverJudgeExecution(context.Context, api.Scope, api.JudgeExecution) (api.JudgeAudit, error)
			})
			got, err := control.RecoverJudgeExecution(context.Background(), scope, e)
			if mode != "measured" {
				if err == nil {
					t.Fatal("judge recovery accepted an unknown, foreign or changed result")
				}
				pending, readErr := f.State.ReserveJudgeExecution(context.Background(), f.Human, input)
				if readErr != nil || pending.Acquired || pending.Audit != nil || pending.UsageKnown || pending.Outcome != "pending" || pending.Request.MaxCostMicros != input.Request.MaxCostMicros {
					t.Fatal("failed judge recovery released its original unknown-cost reservation", readErr)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, audit) {
				t.Fatal("judge restart lost the original measured audit", err)
			}
			replay, err := f.State.ReserveJudgeExecution(context.Background(), f.Human, input)
			if err != nil || replay.Acquired || replay.Audit == nil || !replay.UsageKnown || !reflect.DeepEqual(*replay.Audit, audit) {
				t.Fatal("judge recovery authorized a new send or changed measured cost", err)
			}
		})
	}
}
