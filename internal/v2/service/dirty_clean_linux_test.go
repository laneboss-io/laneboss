//go:build linux

package service

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only native observations are component inputs. Stop's end/release outbox,
// archive bytes/readback, Clean claims, collector and terminal writes are real.
type cleanupStopObserver struct {
	api.Launcher
	f       *fx.Fixture
	t       *testing.T
	stopped bool
}

type dirtyBeforeCollection struct {
	api.WorkspaceCollector
	scene *fx.CleanupRun
}

func (w *dirtyBeforeCollection) InspectCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	read, err := w.WorkspaceCollector.InspectCleanupWorkspace(ctx, job)
	if err == nil {
		w.scene.SetDirty(true)
	}
	return read, err
}

type observedCleanupWorker struct {
	*dataworker.Service
	job api.CleanupJob
}

func (w *observedCleanupWorker) CollectCleanup(ctx context.Context, job api.CleanupJob) (api.CleanupReceipt, error) {
	w.job = job
	return w.Service.CollectCleanup(ctx, job)
}

func (o *cleanupStopObserver) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if handle != o.f.Process {
		return api.ProcessObservation{}, serviceError(api.CodeConflict, "component stop selected another process")
	}
	state := "running"
	if o.stopped {
		state = "exited"
	}
	return o.f.Observation(o.t, state).Observation, nil
}

func (o *cleanupStopObserver) Stop(ctx context.Context, handle api.ProcessHandle, _ string) (api.ProcessObservation, error) {
	if handle != o.f.Process || o.stopped {
		return api.ProcessObservation{}, serviceError(api.CodeConflict, "component stop repeated or selected another process")
	}
	o.stopped = true
	return o.Observe(ctx, handle)
}

func stopBeforeCleanup(t *testing.T, f *fx.Fixture) {
	t.Helper()
	ctx := context.Background()
	host := launchServer(t, f)
	observer := &cleanupStopObserver{f: f, t: t}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	host.runtime = api.RuntimeServices{Store: f.State, Launcher: observer, Lifecycle: coordinator}
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.EffectID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &f.Process}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal(err)
	}
	if host.reconcileEffect(ctx, effect, make(effectRetries)) != attemptNext || host.fault != nil {
		t.Fatal("stop effect did not finish before archive", host.fault)
	}
	actual, err := f.State.Effect(ctx, f.Execution, effect.ID)
	if err != nil || !observer.stopped || actual.State != api.EffectCompleted || actual.Outcome == nil || actual.Outcome.Observation == nil || actual.Outcome.Observation.Survivors == nil || *actual.Outcome.Observation.Survivors != 0 {
		t.Fatal("stop did not retain its measured quiescent outcome", err)
	}
	f.Lane, err = f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || f.Lane.State != "verifying" || f.Lane.Containment != "quiescent" {
		t.Fatal("stop did not commit the end before archive", err)
	}
}

func TestStopArchiveDirtyClean(t *testing.T) {
	for _, name := range []string{"dirty", "became-dirty", "clean"} {
		t.Run(name, func(t *testing.T) {
			dirty := name != "clean"
			f := fx.Ready(t, true)
			f.Child(t)
			scene := f.PrepareCleanup(t, func(ctx context.Context, scope api.Scope, principal api.WorkerPrincipal) (api.WorkerResultReceipt, error) {
				return dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: principal, Scope: scope, Bootstrap: f.State,
					Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
						return f.State.WorkerObject(ctx, scope, q)
					}, Sink: f.State, Clock: f.Deps.Clock})
			}, func() { stopBeforeCleanup(t, f) }, name == "dirty")
			host := launchServer(t, f)
			workspace := scene.Workspace
			if name == "became-dirty" {
				workspace = &dirtyBeforeCollection{WorkspaceCollector: workspace, scene: scene}
			}
			worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: f.State,
				Helper: &recoveryGroup{}, Launcher: &reconcileObserver{}, Clock: f.Deps.Clock, Workspace: workspace})
			if err != nil {
				t.Fatal(err)
			}
			observed := &observedCleanupWorker{Service: worker}
			host.runtime = api.RuntimeServices{Store: f.State, Worker: observed}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if host.reconcileEffect(ctx, scene.Effect, make(effectRetries)) != attemptNext || host.fault != nil {
				t.Fatal("cleanup halted the reconciler", host.fault)
			}
			actual, err := f.State.Effect(ctx, f.Execution, scene.Effect.ID)
			if err != nil {
				t.Fatal(err)
			}
			lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
			if err != nil {
				t.Fatal(err)
			}
			operation, err := f.State.Operation(ctx, f.Execution, scene.Effect.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if dirty {
				if actual.State != api.EffectFailed || actual.Outcome == nil || actual.Outcome.Error == nil || actual.Outcome.Error.Code != api.CodePrerequisite || operation.Status != "failed" || operation.Error == nil || lane.Cleaned {
					t.Fatalf("dirty cleanup remained pending instead of retaining a terminal refusal: state=%s operation=%s cleaned=%t", actual.State, operation.Status, lane.Cleaned)
				}
				read, err := scene.Workspace.InspectCleanupWorkspace(ctx, observed.job)
				if err != nil || read.Dirty == nil || !*read.Dirty || read.WorktreeState != "present" || read.BranchState != "present" {
					t.Fatal("dirty refusal removed or relabeled the native workspace", err)
				}
			} else if actual.State != api.EffectCompleted || operation.Status != "succeeded" || !lane.Cleaned {
				t.Fatal("clean control did not complete through the same collector")
			}
			// Both outcomes preserve the exact verified archive, including the
			// captured workspace content; a terminal refusal is no cleanup receipt.
			chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: scene.Archive.Manifest.ID, Limit: api.MaxChunkBytes})
			if err != nil || fx.Digest(chunk.Data) != scene.Archive.Manifest.SHA256 {
				t.Fatal("cleanup changed its retained archive bytes", err)
			}
			if dirty {
				// An explicitly repaired native workspace needs a fresh public
				// operation. The refused operation and its archive stay retained.
				scene.SetDirty(false)
				worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: f.State,
					Helper: &recoveryGroup{}, Launcher: &reconcileObserver{}, Clock: f.Deps.Clock, Workspace: scene.Workspace})
				if err != nil {
					t.Fatal(err)
				}
				host.runtime.Worker = worker
				next := scene.Request(t)
				if host.reconcileEffect(ctx, next, make(effectRetries)) != attemptNext || host.fault != nil {
					t.Fatal("fresh cleanup halted after explicit repair", host.fault)
				}
				cleaned, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
				if err != nil || !cleaned.Cleaned {
					t.Fatal("retained then repaired workspace could not clean", err)
				}
				kept, err := f.State.Operation(ctx, f.Execution, scene.Effect.OperationID)
				if err != nil || kept.Status != "failed" || kept.Error == nil {
					t.Fatal("fresh cleanup rewrote the retained refusal", err)
				}
			}
		})
	}
}
