//go:build linux

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only scheduling is controlled here. Both pages come from the real store;
// the original owner runs between them, after the reconciler sees the child.
type materializationReconcileStore struct {
	*store.Service
	pages int
	owner func()
}

func (s *materializationReconcileStore) PendingEffects(ctx context.Context, request api.CursorRequest) ([]api.Effect, error) {
	effects, err := s.Service.PendingEffects(ctx, request)
	if err != nil {
		return nil, err
	}
	s.pages++
	if s.pages == 2 {
		s.owner()
	}
	return effects, nil
}

func TestMaterializationReconcilerOwner(t *testing.T) {
	d := datafx.NewData(t)
	s, h := dataServer(t, d)
	ctx := context.Background()
	var err error
	// Seal creates the actual immutable child without claiming or opening it.
	d.Stage, err = d.F.State.SealDataStage(ctx, d.F.Execution, d.Stage.ID, d.Projection, d.Allocation)
	if err != nil {
		t.Fatal(err)
	}
	before, err := d.F.State.Effect(ctx, d.F.Execution, d.Stage.Worker.EffectID)
	if err != nil || before.State != api.EffectPending || before.ClaimID != "" {
		t.Fatal("materialization regression did not start at a pending real child", err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	state := &materializationReconcileStore{Service: d.F.State}
	s.deps.Store, s.runtime.Store = state, state
	// A fresh installed bind inventories unexpired parent and child claims as
	// well as pending effects. The original stage must be recognized there too.
	s.bound = false
	runtime := api.RuntimeServices{Store: state, Identity: s.deps.Authenticator, Config: s.options.Config,
		Socket: s.deps.Binding.Socket, ArtifactSHA256: s.deps.Binding.ArtifactSHA256,
		Helper: h, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}, LaunchPlanner: &lifecycle.Service{}}
	if err := s.BindRuntime(ctx, runtime); err != nil {
		t.Fatal("installed bind rejected the retained materialization owner", err)
	}
	changed := before.Effect
	worker := *changed.Worker
	worker.Argv = append(append([]string{}, worker.Argv...), "foreign-argument")
	changed.Worker = &worker
	if owned, err := d.F.State.MaterializationOwnsEffect(ctx, d.F.Execution, changed); owned || err == nil {
		t.Fatal("materialization owner accepted changed immutable worker input")
	}
	completed := false
	state.owner = func() {
		current, err := d.F.State.Effect(ctx, d.F.Execution, before.Effect.ID)
		if err != nil || !reflect.DeepEqual(current, before) || s.fault != nil || !s.reconciling {
			t.Fatal("reconciler stole or faulted the retained planning child's claim", s.fault, err)
		}
		d.Stage, err = s.MaterializationStage(ctx, d.Request)
		if err != nil {
			t.Fatal("original materialization owner could not resume", err)
		}
		d.BindWorker(t)
		_, raw := d.Result(t)
		if _, err := d.F.State.WorkerResult(ctx, d.Worker, d.Submission(raw)); err != nil {
			t.Fatal(err)
		}
		result, err := s.AwaitMaterialization(ctx, d.Stage.ID)
		if err != nil || result.StageID != d.Stage.ID || result.ReadBackSHA256 != result.Manifest.SHA256 {
			t.Fatal("original materialization owner lost measured completion", err)
		}
		replay, err := s.MaterializationStage(ctx, d.Request)
		if err != nil || !reflect.DeepEqual(replay, d.Stage) {
			t.Fatal("materialization replay changed the original stage", err)
		}
		completed = true
		cancel()
	}
	s.reconcileLoop(runCtx)
	if s.fault != nil || !completed || state.pages != 2 || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		t.Fatal("reconciler halted before the retained planning stage completed", s.fault)
	}
	after, err := d.F.State.Effect(ctx, d.F.Execution, before.Effect.ID)
	if err != nil || after.State != api.EffectCompleted || after.Outcome == nil || after.Outcome.Output == nil || after.Outcome.Observation == nil ||
		h.registers != 1 || h.prepares != 1 || h.opens != 1 || h.measures != 1 {
		t.Fatal("materialization did not complete once through its original owner", err)
	}
}

func TestUnownedWorkerDoesNotHalt(t *testing.T) {
	for _, kind := range []string{"render", "materialize"} {
		t.Run(kind, func(t *testing.T) { unownedWorkerDoesNotHalt(t, kind) })
	}
}

func unownedWorkerDoesNotHalt(t *testing.T, kind string) {
	t.Helper()
	host, state, scope, ctx, active := reconcileFixture(t, "", nil)
	next, err := state.Service.Effect(context.Background(), scope, state.next)
	if err != nil {
		t.Fatal(err)
	}
	cause := *next.Effect.Context
	cause.ID, cause.EffectID, cause.CauseOperationID = fx.ID(t), fx.ID(t), fx.ID(t)
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: kind,
		Executable: api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte(fx.ID(t))), Version: "component-worker"},
		Argv:       []string{"component-worker"}, Input: api.BlobRef{ID: fx.ID(t), Class: "artifact", SHA256: fx.Digest([]byte(fx.ID(t))), Bytes: 1},
		GrantSetID: fx.ID(t), Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 1, DiskBytes: 4096, SpendMicros: 1, Currency: "USD"}}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Worker: &plan}
	if _, err := state.Service.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("unowned Worker control did not create its real outbox intent", err)
	}
	state.blocked = effect.ID
	host.reconcileLoop(ctx)
	if host.fault != nil || !*active || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("unowned Worker refusal stopped unrelated real work", host.fault)
	}
	failed, err := state.Service.Effect(context.Background(), scope, effect.ID)
	if err != nil || failed.State != api.EffectFailed || failed.Outcome == nil || failed.Outcome.Error == nil ||
		failed.Outcome.Error.Code != api.CodeNotImplemented || failed.Outcome.Error.Owner != "lb-v2-service" ||
		failed.Outcome.Error.Message != "effect execution requires its owning coordinator is not implemented" ||
		failed.Outcome.Process != nil || failed.Outcome.Output != nil || failed.Outcome.Observation != nil {
		t.Fatal("unowned Worker did not retain its exact typed refusal", err)
	}
}
