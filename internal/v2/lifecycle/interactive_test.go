package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type movingClock struct{ now time.Time }

func (clock *movingClock) Now() time.Time { return clock.now }

func TestLoopConfig(t *testing.T) {
	f := newFixture(t)
	f.ended()
	idle := f.blob("idle-task", "task", []byte("idle task bytes"))
	request := api.LoopRequest{Target: f.target, ExpectedGeneration: f.child.Generation, Enabled: true, IdleMessage: &idle, BackoffMS: 100}
	scope := f.scope("lane.loop", request, f.parent)
	operation, err := f.service.LaneLoop(context.Background(), scope, request)
	if err != nil || operation.Status != "succeeded" || len(f.store.transactions) != 1 || f.store.lanes[f.child.LifeID].Generation != f.child.Generation+1 {
		t.Fatalf("loop setting was not durably committed: %v", err)
	}
	var retained api.LoopRequest
	last := f.store.events[len(f.store.events)-1]
	if last.Kind != "lane.loop" || api.DecodeObject(last.Payload, &retained) != nil || !reflect.DeepEqual(retained, request) ||
		len(f.store.transactions[0].Effects) != 0 || f.store.lanes[f.child.LifeID].Run != f.child.Run {
		t.Fatal("loop setting changed its exact request or claimed an unexecuted run")
	}
	clock := &movingClock{now: fixtureClock{}.Now().Add(99 * time.Millisecond)}
	f.service.deps.Clock = clock
	internal := api.Scope{Config: "example", Actor: api.Actor{Kind: "scheduler", ID: "scheduler"}, PolicyGeneration: 1}
	_, due, err := f.service.LoopDue(context.Background(), internal, f.target)
	if err != nil || due {
		t.Fatalf("loop backoff ignored its committed end: %v", err)
	}
	clock.now = clock.now.Add(time.Millisecond)
	restarted, err := New(f.service.deps)
	if err != nil {
		t.Fatal(err)
	}
	setting, due, err := restarted.LoopDue(context.Background(), internal, f.target)
	if err != nil || !due || !reflect.DeepEqual(setting, request) {
		t.Fatalf("loop schedule was lost after component restart: %v", err)
	}
	disabled := api.LoopRequest{Target: f.target, ExpectedGeneration: f.store.lanes[f.child.LifeID].Generation, BackoffMS: 100}
	if _, err := f.service.LaneLoop(context.Background(), f.scope("lane.loop", disabled, f.parent), disabled); err != nil {
		t.Fatal(err)
	}
	_, due, err = restarted.LoopDue(context.Background(), internal, f.target)
	if err != nil || due {
		t.Fatalf("disabled loop was scheduled: %v", err)
	}
	before := len(f.store.transactions)
	replay, err := f.service.LaneLoop(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replay, operation) || len(f.store.transactions) != before {
		t.Fatalf("loop replay replaced its original setting operation: %v", err)
	}
}

// The input fixture owns an actual byte buffer and terminal dimensions, plus
// a durable model job/claim/result. It is not a native PTY/worker acceptance.
type inputFixture struct {
	f         *terminalFixture
	channel   InputChannel
	jobs      map[api.ID]InputJob
	results   map[api.ID]InputReceipt
	output    bytes.Buffer
	columns   uint16
	rows      uint16
	calls     int
	plans     int
	hook      func(*InputJob)
	writeHook func(*InputReceipt)
}

func newInputFixture(t *testing.T) *inputFixture {
	f := newFixture(t)
	fixtureActiveRun(f)
	observation := f.launcher.observation
	one := uint64(1)
	observation.State, observation.ExitCode, observation.Survivors = "running", nil, &one
	f.launcher.observation = observation
	base := &launchFixtureStore{fixtureStore: f.store, effects: map[api.ID]api.EffectRecord{}, workers: map[api.ID]api.WorkerLease{},
		fences: map[api.ID]api.Generation{f.child.LifeID: f.child.CancellationEpoch}, plans: map[api.ID]api.LaunchPlanRecord{}}
	store := &terminalStore{launchFixtureStore: base}
	store.bootstrap = api.Executable{ID: "input-worker", Version: "fixture-1", SHA256: digestOf([]byte("installed input worker bytes"))}
	raw, err := json.Marshal(api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: store.bootstrap, Bootstrap: store.bootstrap,
		Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}})
	if err != nil {
		t.Fatal(err)
	}
	store.runtime = f.blob("input-runtime", "manifest", raw)
	terminal := &terminalFixture{fixture: f, store: store}
	control := &inputFixture{f: terminal, jobs: map[api.ID]InputJob{}, results: map[api.ID]InputReceipt{},
		channel: InputChannel{ID: "input-channel", LaunchID: f.child.LaunchID, Process: observation.Handle, Generation: 1, ExpiresAt: "2031-01-01T00:00:00Z"}}
	f.service.deps.Store, f.service.deps.Input = store, control
	return control
}

func (control *inputFixture) PlanInput(_ context.Context, scope api.Scope, intent InputIntent) (InputJob, error) {
	store := control.f.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if job, ok := control.jobs[intent.OperationID]; ok {
		return job, nil
	}
	control.plans++
	intent.Request.Input = append([]byte{}, intent.Request.Input...)
	job := InputJob{Intent: intent, Channel: control.channel}
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		return InputJob{}, err
	}
	job.OriginalRequest = store.put("manifest", raw, intent.OperationID, intent.Request.Target)
	raw, err = json.Marshal(intent)
	if err != nil {
		return InputJob{}, err
	}
	job.Lease = api.WorkerLease{ID: launchIDForTest(), Kind: "channel", Target: intent.Request.Target, OperationID: intent.OperationID,
		EffectID: launchIDForTest(), Input: store.put("manifest", raw, intent.OperationID, intent.Request.Target), RuntimeManifest: store.runtime,
		GrantSetID: launchIDForTest(), Generation: 1, ExpiresAt: control.channel.ExpiresAt}
	job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "channel", Executable: store.bootstrap, Input: job.Lease.Input,
		GrantSetID: job.Lease.GrantSetID, Budget: control.f.budget,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)}}
	store.grants[job.Lease.GrantSetID] = api.GrantSet{ID: job.Lease.GrantSetID, LifeID: intent.Request.Target.LifeID,
		Generation: 1, PolicyGeneration: scope.PolicyGeneration, ExpiresAt: job.Lease.ExpiresAt,
		SHA256: digestOf(raw), Channels: []api.ChannelGrant{{ID: "input-grant", ChannelID: control.channel.ID, ExpiresAt: job.Lease.ExpiresAt}}}
	if control.hook != nil {
		control.hook(&job)
	}
	control.jobs[intent.OperationID] = job
	return job, nil
}

func (control *inputFixture) InputJob(_ context.Context, _ api.Scope, operation api.ID) (InputJob, error) {
	job, ok := control.jobs[operation]
	if !ok {
		return InputJob{}, launchMissing()
	}
	return job, nil
}

func (control *inputFixture) InputChannel(_ context.Context, _ api.Scope, id api.ID) (InputChannel, error) {
	if id != control.channel.ID {
		return InputChannel{}, launchMissing()
	}
	return control.channel, nil
}

func (control *inputFixture) WriteInput(_ context.Context, _ api.Scope, lease api.EffectLease, job InputJob) (InputReceipt, error) {
	control.calls++
	if old, ok := control.results[lease.Record.Effect.ID]; ok {
		return old, nil
	}
	current := control.f.store.effects[lease.Record.Effect.ID]
	if current.ClaimID != lease.ClaimID || control.channel != job.Channel || control.channel.Closed {
		return InputReceipt{}, launchConflict()
	}
	n, err := control.output.Write(job.Intent.Request.Input)
	if err != nil {
		return InputReceipt{}, err
	}
	if job.Intent.Request.Columns != 0 {
		control.columns, control.rows = job.Intent.Request.Columns, job.Intent.Request.Rows
	}
	write := InputWrite{OperationID: job.Intent.OperationID, EffectID: lease.Record.Effect.ID, ChannelID: job.Channel.ID,
		ChannelGeneration: job.Channel.Generation, LaunchID: job.Intent.LaunchID, InputSHA256: digestOfBytes(job.Intent.Request.Input),
		AcceptedBytes: int64(n), Columns: job.Intent.Request.Columns, Rows: job.Intent.Request.Rows, ObservedAt: "2030-01-02T03:04:05Z"}
	worker := control.f.store.launches[control.f.store.workers[job.Lease.ID].ConsumedBy]
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: "input-process", Target: job.Intent.Request.Target,
		ContainmentID: worker.ContainmentID, Generation: worker.ProcessGeneration}, State: "exited", ExitCode: &exit, Survivors: &zero,
		PromptStatus: "completed", ObservedAt: write.ObservedAt}
	result := InputReceipt{Write: write, Observation: observation}
	if control.writeHook != nil {
		control.writeHook(&result)
	}
	raw, err := json.Marshal(inputEvidence{Write: result.Write, Observation: result.Observation})
	if err != nil {
		return InputReceipt{}, err
	}
	result.Evidence = control.f.store.put("manifest", raw, job.Intent.OperationID, job.Intent.Request.Target)
	control.results[lease.Record.Effect.ID] = result
	return result, nil
}

func inputClaim(t *testing.T, control *inputFixture, operation api.Operation) (api.Scope, api.EffectLease) {
	t.Helper()
	store := control.f.store
	job := control.jobs[operation.ID]
	worker := store.workers[job.Lease.ID]
	worker.ConsumedBy = launchIDForTest()
	store.workers[worker.ID] = worker
	store.launches[worker.ConsumedBy] = api.LaunchRecord{ID: worker.ConsumedBy, Kind: "worker", Config: "example", Target: job.Intent.Request.Target,
		Actor: api.Actor{Kind: "worker", ID: "input-worker-actor"}, HostUID: 60001, GrantSetID: worker.GrantSetID,
		ContainmentID: "input-worker-group", ProcessGeneration: "input-worker-generation"}
	scope := api.Scope{Config: "example", Actor: api.Actor{Kind: "service", ID: "lifecycle"}, PolicyGeneration: 1}
	effect := store.effects[job.Lease.EffectID]
	lease, err := store.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.Effect.ID,
		ExpectedGeneration: effect.Generation, ClaimantID: scope.Actor.ID, Deadline: "2031-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	return scope, lease
}

func TestInputDelivery(t *testing.T) {
	for _, mode := range []string{"bytes", "resize", "partial", "epoch", "exit"} {
		t.Run(mode, func(t *testing.T) {
			control := newInputFixture(t)
			f := control.f
			data := []byte{0, 255, 'x', '\n'}
			request := api.AttachInputRequest{Target: f.target, ChannelID: control.channel.ID, Input: data, Columns: 80, Rows: 24}
			if mode == "resize" {
				request.Input = []byte{}
			}
			scope := f.fixture.scope("lane.input", request, f.parent)
			operation, err := f.service.LaneInput(context.Background(), scope, request)
			if err != nil || operation.Status != "pending" || control.calls != 0 || control.plans != 1 || len(f.store.transactions) != 1 {
				t.Fatalf("input did not retain its unexecuted worker intent: %v", err)
			}
			before := len(f.store.transactions)
			replay, err := f.service.LaneInput(context.Background(), scope, request)
			if err != nil || !reflect.DeepEqual(replay, operation) || control.plans != 1 || len(f.store.transactions) != before {
				t.Fatalf("input retry replaced its original worker: %v", err)
			}
			internal, lease := inputClaim(t, control, operation)
			if mode == "partial" {
				control.writeHook = func(receipt *InputReceipt) { receipt.Write.AcceptedBytes-- }
			}
			if mode == "exit" {
				control.writeHook = func(receipt *InputReceipt) { exit := 9; receipt.Observation.ExitCode = &exit }
			}
			if mode == "epoch" {
				lane := f.store.lanes[f.target.LifeID]
				lane.CancellationEpoch++
				f.store.lanes[lane.LifeID] = lane
			}
			result, err := f.service.ApplyInput(context.Background(), internal, lease)
			if mode == "epoch" {
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || control.calls != 0 || control.output.Len() != 0 {
					t.Fatalf("input crossed its cancelled run fence: %v", err)
				}
				return
			}
			if mode == "partial" {
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
					t.Fatalf("partial input was reported as complete: %v", err)
				}
				return
			}
			if mode == "exit" {
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
					t.Fatalf("input worker failure was reported complete: %v", err)
				}
				return
			}
			if err != nil || !bytes.Equal(control.output.Bytes(), request.Input) || control.columns != request.Columns || control.rows != request.Rows || result.Write.AcceptedBytes != int64(len(request.Input)) {
				t.Fatalf("input effect lost its actual bytes or resize: %v", err)
			}
			again, err := f.service.ApplyInput(context.Background(), internal, lease)
			if err != nil || !reflect.DeepEqual(again, result) || !bytes.Equal(control.output.Bytes(), request.Input) {
				t.Fatalf("input reconciliation repeated a native write: %v", err)
			}
		})
	}
}

func TestInputPins(t *testing.T) {
	for _, mode := range []string{"channel", "bytes", "runtime", "grants"} {
		t.Run(mode, func(t *testing.T) {
			control := newInputFixture(t)
			f := control.f
			control.hook = func(job *InputJob) {
				switch mode {
				case "channel":
					job.Channel.Process.Generation = "foreign-process"
				case "bytes":
					job.Intent.Request.Input[0] ^= 1
				case "runtime":
					job.Plan.Executable.SHA256 = digestOf([]byte("foreign worker bytes"))
				case "grants":
					grants := f.store.grants[job.Lease.GrantSetID]
					grants.Channels[0].Delegate = true
					f.store.grants[grants.ID] = grants
				}
			}
			request := api.AttachInputRequest{Target: f.target, ChannelID: control.channel.ID, Input: []byte("input bytes")}
			_, err := f.service.LaneInput(context.Background(), f.fixture.scope("lane.input", request, f.parent), request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(f.store.transactions) != 0 || control.calls != 0 {
				t.Fatalf("input accepted a foreign protected job pin: %s: %v", mode, err)
			}
		})
	}
}
