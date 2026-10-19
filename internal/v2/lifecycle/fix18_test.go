package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReviewPendingTarget(t *testing.T) {
	for _, mode := range []string{"pending", "running", "assigned", "partial", "foreign", "done", "check"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			request := reviewRequest(fixtureReview(f), f.target)
			scope := f.scope("lane.review", request, f.parent)
			key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
			operation := f.store.receipts[fixtureReceiptKey(scope, key)].Operation
			verifier := true
			switch mode {
			case "running":
				operation.Status = "running"
			case "assigned":
				operation.LifeID, operation.Run = f.target.LifeID, f.target.Run
			case "partial":
				operation.LifeID = f.target.LifeID
			case "foreign":
				operation.LifeID, operation.Run = "foreign-life", f.target.Run
			case "done":
				operation.Status = "succeeded"
			case "check":
				verifier = false
			}
			f.store.operations[operation.ID] = operation
			err := f.service.reviewJob(context.Background(), scope, api.WorkerLease{OperationID: operation.ID},
				api.ReviewSubject{Target: f.target}, verifier)
			if mode == "pending" || mode == "running" || mode == "assigned" {
				if err != nil {
					t.Fatalf("review rejected its unassigned verifier: %s: %v", mode, err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("review accepted an uncorrelated worker operation: %s: %v", mode, err)
			}
		})
	}
}

func archiveJobFixture(t *testing.T) (*terminalFixture, api.Scope, ArchiveJob) {
	t.Helper()
	f := newTerminalFixture(t)
	request := api.ArchiveRequest{Target: f.target, ExpectedGeneration: f.child.Generation}
	scope := f.fixture.scope("lane.archive", request, f.parent)
	pending, err := f.service.pendingMutation(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := f.service.facts(context.Background(), scope, f.child, f.target)
	if err != nil {
		t.Fatal(err)
	}
	intent := ArchiveIntent{Request: request, OperationID: pending.Operation.ID,
		CancellationEpoch: f.child.CancellationEpoch, EndEventID: facts.endID, EndSeq: facts.endSeq}
	job, err := f.store.ReserveArchive(context.Background(), scope, intent)
	if err != nil {
		t.Fatal(err)
	}
	return f, scope, job
}

func TestArchExpiry(t *testing.T) {
	for _, mode := range []string{"expired", "at-now", "bad", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, job := archiveJobFixture(t)
			grants := f.store.grants[job.Lease.GrantSetID]
			switch mode {
			case "expired":
				grants.ExpiresAt = "2029-01-01T00:00:00Z"
			case "at-now":
				grants.ExpiresAt = api.Timestamp(f.service.deps.Clock.Now().Format(time.RFC3339Nano))
			case "bad":
				grants.ExpiresAt = "invalid"
			}
			f.store.grants[grants.ID] = grants
			err := f.service.archiveJob(context.Background(), scope, f.store, f.child, job.Intent, job)
			if mode == "valid" {
				if err != nil {
					t.Fatalf("archive rejected current worker grants: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
				t.Fatalf("archive accepted expired worker grants: %s: %v", mode, err)
			}
		})
	}
}

func TestArchFinish(t *testing.T) {
	for _, mode := range []string{"lease", "revision", "revoked", "containment", "generation", "time", "prompt", "signal", "handle", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, job := archiveJobFixture(t)
			receipt := f.finishArchive(t, job.Intent.OperationID, "valid")
			worker := f.store.workers[job.Lease.ID]
			principal := f.store.launches[worker.ConsumedBy]
			effect := f.store.effects[job.Lease.EffectID]
			switch mode {
			case "lease":
				worker.OperationID = "foreign-operation"
			case "revision":
				worker.Generation = job.Lease.Generation + 2
			case "revoked":
				principal.Revoked = true
			case "containment":
				principal.ContainmentID, effect.Outcome.Observation.Handle.ContainmentID = "", ""
			case "generation":
				principal.ProcessGeneration, effect.Outcome.Observation.Handle.Generation = "", ""
			case "time":
				effect.Outcome.Observation.ObservedAt = "invalid"
			case "prompt":
				effect.Outcome.Observation.PromptStatus = "invented"
			case "signal":
				signal := 9
				effect.Outcome.Observation.Signal = &signal
			case "handle":
				effect.Outcome.Observation.Handle.ID = ""
			}
			f.store.workers[job.Lease.ID], f.store.launches[principal.ID], f.store.effects[job.Lease.EffectID] = worker, principal, effect
			err := f.service.archiveCompletion(context.Background(), scope, f.child, job, receipt)
			if mode == "valid" {
				if err != nil {
					t.Fatalf("archive rejected its retained completion: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("archive completion accepted stale authority: %s: %v", mode, err)
			}
		})
	}
}

type inputBoundary struct {
	InputControl
	reads int
	after func()
}

func (control *inputBoundary) InputChannel(ctx context.Context, scope api.Scope, id api.ID) (InputChannel, error) {
	channel, err := control.InputControl.InputChannel(ctx, scope, id)
	if err != nil {
		return InputChannel{}, err
	}
	control.reads++
	if control.reads == 2 {
		control.after()
	}
	return channel, nil
}

func readyInput(t *testing.T) (*inputFixture, api.Scope, api.EffectLease) {
	t.Helper()
	control := newInputFixture(t)
	f := control.f
	request := api.AttachInputRequest{Target: f.target, ChannelID: control.channel.ID, Input: []byte("bounded input")}
	scope := f.fixture.scope("lane.input", request, f.parent)
	operation, err := f.service.LaneInput(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	internal, lease := inputClaim(t, control, operation)
	return control, internal, lease
}

func TestInputRecheck(t *testing.T) {
	for _, mode := range []string{"expired", "replaced"} {
		t.Run(mode, func(t *testing.T) {
			control, scope, lease := readyInput(t)
			f := control.f
			boundary := &inputBoundary{InputControl: control}
			boundary.after = func() {
				if mode == "expired" {
					expiry, err := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
					if err != nil {
						t.Fatal(err)
					}
					f.service.deps.Clock = &movingClock{now: expiry}
				} else {
					current := f.store.effects[lease.Record.Effect.ID]
					current.ClaimID = "replacement-claim"
					f.store.effects[current.Effect.ID] = current
				}
			}
			f.service.deps.Input = boundary
			_, err := f.service.ApplyInput(context.Background(), scope, lease)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict ||
				boundary.reads != 2 || control.calls != 0 || control.output.Len() != 0 {
				t.Fatalf("input crossed its current prewrite claim: %s: %v", mode, err)
			}
		})
	}
}

func TestInputPrincipal(t *testing.T) {
	control, scope, lease := readyInput(t)
	f := control.f
	job := control.jobs[lease.Record.Effect.OperationID]
	worker := f.store.launches[f.store.workers[job.Lease.ID].ConsumedBy]
	agent := f.store.launches[f.child.LaunchID]
	agent.HostUID = worker.HostUID
	f.store.launches[agent.ID] = agent
	_, err := f.service.ApplyInput(context.Background(), scope, lease)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || control.calls != 0 || control.output.Len() != 0 {
		t.Fatalf("input reused its agent principal: %v", err)
	}
}

func TestInputObservation(t *testing.T) {
	for _, mode := range []string{"time", "prompt", "handle", "signal", "valid"} {
		t.Run(mode, func(t *testing.T) {
			control, scope, lease := readyInput(t)
			control.writeHook = func(result *InputReceipt) {
				switch mode {
				case "time":
					result.Observation.ObservedAt = "invalid"
				case "prompt":
					result.Observation.PromptStatus = "invented"
				case "handle":
					result.Observation.Handle.ID = ""
				case "signal":
					signal := 9
					result.Observation.Signal = &signal
				}
			}
			_, err := control.f.service.ApplyInput(context.Background(), scope, lease)
			if mode == "valid" {
				if err != nil || control.calls != 1 {
					t.Fatalf("input rejected measured worker completion: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("input accepted malformed worker observation: %s: %v", mode, err)
			}
		})
	}
}

func cleanReplayFixture(t *testing.T) (*terminalFixture, api.Scope, api.EffectLease, api.CleanEvent, api.ID) {
	t.Helper()
	f := newTerminalFixture(t)
	extra := f.fixture.blob("retained-export", "manifest", []byte("retained export evidence"))
	f.fixture.add("data.materialized", api.Materialization{GrantSetID: f.child.GrantSetID, Manifest: extra, Objects: []api.MaterializedObject{}},
		f.target.Run, "service", f.parent)
	archive := fixtureArchive(f.fixture)
	f.fixture.add("archive.verified", archive, f.target.Run, "service", f.parent)
	request := api.CleanRequest{Target: f.target, ExpectedGeneration: f.child.Generation, ArchiveReceiptID: archive.ID}
	public := f.fixture.scope("lane.clean", request, f.parent)
	operation, err := f.service.LaneClean(context.Background(), public, request)
	if err != nil {
		t.Fatal(err)
	}
	var effect api.EffectRecord
	for _, candidate := range f.store.effects {
		if candidate.Effect.OperationID == operation.ID {
			effect = candidate
		}
	}
	if effect.Effect.Context == nil {
		t.Fatal("clean replay fixture has no original effect")
	}
	scope := api.Scope{Config: public.Config, Actor: effect.Effect.Context.Actor, PolicyGeneration: public.PolicyGeneration}
	lease, err := f.store.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.Effect.ID,
		ExpectedGeneration: effect.Generation, ClaimantID: scope.Actor.ID, Deadline: "2031-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	retained, err := f.service.cleanRetainedObjects(context.Background(), scope, f.child, archive)
	if err != nil {
		t.Fatal(err)
	}
	result := api.CleanEvent{ArchiveReceipt: archive, RemovedObjectIDs: []api.ID{f.child.Workspace.ID},
		RetainedObjectIDs: retained, Quiescence: f.launcher.observation}
	lane := f.store.lanes[f.child.LifeID]
	lane.Cleaned, lane.Generation = true, lane.Generation+1
	f.store.lanes[lane.LifeID] = lane
	event, err := f.service.event(public, lane, "lane.cleaned", result, scope.Actor)
	if err != nil {
		t.Fatal(err)
	}
	f.store.seq++
	event.Seq, event.OperationID = f.store.seq, operation.ID
	f.store.events = append(f.store.events, event)
	return f, scope, lease, result, extra.ID
}

func TestCleanReplayPins(t *testing.T) {
	for _, mode := range []string{"archive", "handle", "retained", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, lease, result, extra := cleanReplayFixture(t)
			switch mode {
			case "archive":
				result.ArchiveReceipt.StoreID = "unverified-store"
			case "handle":
				result.Quiescence.Handle.ID = "foreign-process"
			case "retained":
				ids := []api.ID{}
				for _, id := range result.RetainedObjectIDs {
					if id != extra {
						ids = append(ids, id)
					}
				}
				result.RetainedObjectIDs = ids
			}
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			f.store.events[len(f.store.events)-1].Payload = raw
			before, observed := len(f.store.transactions), f.launcher.observed.Load()
			got, err := f.service.CollectClean(context.Background(), scope, lease)
			if mode == "valid" {
				if err != nil || !reflect.DeepEqual(got, result) || len(f.store.transactions) != before || f.launcher.observed.Load() != observed {
					t.Fatalf("clean replay repeated removal or lost retained evidence: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(f.store.transactions) != before {
				t.Fatalf("clean replay trusted its own unverified evidence: %s: %v", mode, err)
			}
		})
	}
}

func TestArchiveManifest(t *testing.T) {
	for _, mode := range []string{"invalid", "null", "schema", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newTerminalFixture(t)
			receipt := fixtureArchive(f.fixture)
			switch mode {
			case "invalid":
				receipt.Manifest = f.fixture.blob("bad-manifest", "manifest", []byte("not a manifest"))
			case "null":
				raw, err := json.Marshal(api.ObjectManifest{Schema: "laneboss.object-manifest.v2"})
				if err != nil {
					t.Fatal(err)
				}
				receipt.Manifest = f.fixture.blob("null-manifest", "manifest", raw)
			case "schema":
				raw, err := json.Marshal(api.ObjectManifest{Entries: []api.ObjectEntry{}})
				if err != nil {
					t.Fatal(err)
				}
				receipt.Manifest = f.fixture.blob("no-schema", "manifest", raw)
			}
			f.fixture.add("archive.verified", receipt, f.target.Run, "service", f.parent)
			request := api.CleanRequest{Target: f.target, ExpectedGeneration: f.child.Generation, ArchiveReceiptID: receipt.ID}
			_, err := f.service.LaneClean(context.Background(), f.fixture.scope("lane.clean", request, f.parent), request)
			if mode == "valid" {
				if err != nil || len(f.store.transactions) != 1 {
					t.Fatalf("clean rejected a structured archive manifest: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(f.store.transactions) != 0 {
				t.Fatalf("clean accepted an unstructured archive manifest: %s: %v", mode, err)
			}
		})
	}
}

func TestAttachPages(t *testing.T) {
	f, store := newIOFixture(t)
	request := api.AttachRequest{Target: f.target, Mode: "read"}
	stream, err := f.service.OpenAttach(context.Background(), f.scope("lane.attach", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	captureCommit(t, store, "stdout-stream", nil, true)
	captureCommit(t, store, "stderr-stream", nil, true)
	for range 201 {
		f.add("run.observed", f.launcher.observation, f.target.Run, "service", f.parent)
	}
	f.add("capture.gap", api.CaptureGap{Target: f.target, BindingID: store.state.Binding.ID, Stream: "stdout",
		Reason: "primary range lost", ObservedAt: "2030-01-02T03:04:05Z"}, f.target.Run, "service", f.parent)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before := f.store.eventCalls
	frame, err := stream.Next(ctx)
	if err != nil || frame.Error == nil || frame.Error.Code != api.CodeIntegrity || frame.End || f.store.eventCalls < before+2 {
		t.Fatalf("attach ended before its remaining gap page: %v", err)
	}
}

func TestAttachCurrent(t *testing.T) {
	f, store := newIOFixture(t)
	request := api.AttachRequest{Target: f.target, Mode: "read"}
	stream, err := f.service.OpenAttach(context.Background(), f.scope("lane.attach", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A protected projection refresh precedes newly committed events. The
	// original binding stays unchanged; event selection uses the fresh lane.
	lane := f.store.lanes[f.child.LifeID]
	lane.Generation++
	lane.RootLifeID, lane.StarterChain = "root-current", []api.ID{"root-current", lane.ParentLifeID}
	f.store.lanes[lane.LifeID], f.child = lane, lane
	captureCommit(t, store, "stdout-stream", nil, true)
	captureCommit(t, store, "stderr-stream", nil, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	frame, err := stream.Next(ctx)
	if err != nil || frame.Error != nil || !frame.End {
		t.Fatalf("attach used its stale lane projection: %v", err)
	}
}

func TestReplayRun(t *testing.T) {
	for _, method := range []string{"input", "mark", "stop", "clean", "loop"} {
		t.Run(method, func(t *testing.T) {
			f := newFixture(t)
			var request any
			var call func(api.Scope) error
			switch method {
			case "input":
				value := api.AttachInputRequest{Target: f.target, ChannelID: "channel", Input: []byte("x")}
				request = value
				call = func(scope api.Scope) error {
					_, err := f.service.LaneInput(context.Background(), scope, value)
					return err
				}
			case "mark":
				value := api.MarkRequest{Target: f.target, ExpectedGeneration: f.child.Generation, State: "abandoned",
					Review: api.ReviewReceipt{Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}}}
				request = value
				call = func(scope api.Scope) error {
					_, err := f.service.LaneMark(context.Background(), scope, value)
					return err
				}
			case "stop":
				value := api.StopRequest{Target: f.target, ExpectedGeneration: f.child.Generation, Reason: f.blob("stop", "task", []byte("stop"))}
				request = value
				call = func(scope api.Scope) error {
					_, err := f.service.LaneStop(context.Background(), scope, value)
					return err
				}
			case "clean":
				value := api.CleanRequest{Target: f.target, ExpectedGeneration: f.child.Generation, ArchiveReceiptID: "archive"}
				request = value
				call = func(scope api.Scope) error {
					_, err := f.service.LaneClean(context.Background(), scope, value)
					return err
				}
			case "loop":
				value := api.LoopRequest{Target: f.target, ExpectedGeneration: f.child.Generation, BackoffMS: 100}
				request = value
				call = func(scope api.Scope) error {
					_, err := f.service.LaneLoop(context.Background(), scope, value)
					return err
				}
			}
			scope := f.scope(api.Method("lane."+method), request, f.parent)
			original := api.Operation{ID: "retained-operation", LifeID: f.target.LifeID, Run: f.target.Run - 1, Status: "succeeded"}
			fixtureRetainedReply(f, scope, original)
			if typed, ok := call(scope).(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(f.store.transactions) != 0 {
				t.Fatalf("replay accepted another requested run: %s: %v", method, typed)
			}
		})
	}
}

func TestReplayArchive(t *testing.T) {
	for _, mode := range []string{"store", "class", "time", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			request := api.ArchiveRequest{Target: f.target, ExpectedGeneration: f.child.Generation}
			scope := f.scope("lane.archive", request, f.parent)
			receipt := fixtureArchive(f)
			switch mode {
			case "store":
				receipt.StoreID = ""
			case "class":
				receipt.Manifest.Class = "artifact"
			case "time":
				receipt.VerifiedAt = "invalid"
			}
			fixtureRetainedReply(f, scope, receipt)
			got, err := f.service.LaneArchive(context.Background(), scope, request)
			if mode == "valid" {
				if err != nil || !reflect.DeepEqual(got, receipt) || len(f.store.transactions) != 0 {
					t.Fatalf("archive replay lost its exact receipt: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(f.store.transactions) != 0 {
				t.Fatalf("archive replay accepted invalid receipt metadata: %s: %v", mode, err)
			}
		})
	}
}
