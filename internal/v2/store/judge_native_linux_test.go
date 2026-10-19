//go:build linux

package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type nativeJudgeStore interface {
	PrepareJudgeWorker(context.Context, api.Scope, api.JudgeExecution, api.BlobRef, api.Executable) (api.WorkerLease, error)
	JudgeWorkerPlan(context.Context, api.Scope, api.JudgeExecution) (api.WorkerPlan, error)
}

func TestJudgeNativeReservation(t *testing.T) {
	f, request := judgeExecutionFixture(t)
	ctx := context.Background()
	execution, err := f.State.ReserveJudgeExecution(ctx, f.Human, request)
	if err != nil || !execution.Acquired {
		t.Fatal("native fixture did not acquire its real durable execution", err)
	}
	control, ok := any(f.State).(nativeJudgeStore)
	if !ok {
		t.Fatal("native judge worker reservation is not implemented")
	}
	scope := api.Scope{Config: f.Deps.Config, Actor: execution.Intent.Actor,
		PolicyGeneration: execution.Request.Context.PolicyGeneration, Source: "worker"}
	runtime := f.Plan.Inputs.Sources.Runtime.Manifest
	chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: runtime.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var manifest api.RuntimeManifest
	if err := json.Unmarshal(chunk.Data, &manifest); err != nil {
		t.Fatal(err)
	}
	worker, err := control.PrepareJudgeWorker(ctx, scope, execution, runtime, manifest.Bootstrap)
	if err != nil {
		t.Fatal("native judge did not retain its original bounded worker", err)
	}
	if worker.Kind != "judge" || worker.Target != execution.Intent.Target ||
		worker.OperationID != execution.Intent.CauseOperationID || worker.EffectID == "" ||
		worker.GrantSetID == f.Lane.GrantSetID || worker.Input.Class != "worker_input" ||
		worker.ExpiresAt != execution.Deadline || worker.ConsumedBy != "" {
		t.Fatal("native worker lost its exact cause, deadline or narrow grants")
	}
	plan, err := control.JudgeWorkerPlan(ctx, scope, execution)
	if err != nil || plan.Kind != "judge" || plan.Executable != manifest.Bootstrap ||
		plan.Input != worker.Input || plan.GrantSetID != worker.GrantSetID ||
		!reflect.DeepEqual(plan.Argv, []string{"laneboss", "internal", "judge", "--binding", "/runtime/laneboss-worker.json", "--lease", string(worker.ID)}) {
		t.Fatal("native worker plan changed its fixed entry, executable or sealed input", err)
	}
	second, err := control.PrepareJudgeWorker(ctx, scope, execution, runtime, manifest.Bootstrap)
	if err != nil || second != worker {
		t.Fatal("native retry created another worker lease", err)
	}
	grants, err := f.State.Grants(ctx, worker.GrantSetID)
	if err != nil || len(grants.Data)+len(grants.Resources)+len(grants.Secrets)+len(grants.Profiles)+len(grants.Channels) != 0 ||
		len(grants.Network) != 1 || grants.Network[0].Delegate {
		t.Fatal("native worker inherited unrelated lane authority", err)
	}
	input, err := f.State.Blob(ctx, scope, api.BlobReadRequest{ObjectID: worker.Input.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var sealed api.JudgeExecution
	if err := json.Unmarshal(input.Data, &sealed); err != nil || sealed.Acquired ||
		sealed.ID != execution.ID || sealed.ClaimID != execution.ClaimID || sealed.Pin != execution.Pin ||
		!reflect.DeepEqual(sealed.Request, execution.Request) {
		t.Fatal("native input changed the exact execution or copied its acquisition authority", err)
	}
	for _, fault := range []string{"claim", "attempt", "input", "observed", "artifact"} {
		t.Run(fault, func(t *testing.T) {
			altered, artifact := execution, manifest.Bootstrap
			switch fault {
			case "claim":
				altered.ClaimID += "changed"
			case "attempt":
				altered.AttemptID += "changed"
			case "input":
				altered.Request.Task = append(append([]byte{}, altered.Request.Task...), 'x')
			case "observed":
				altered.Acquired = false
			case "artifact":
				artifact.ID += "changed"
			}
			if _, err := control.PrepareJudgeWorker(ctx, scope, altered, runtime, artifact); err == nil {
				t.Fatal("native retry accepted a foreign or observed execution")
			}
		})
	}
}
