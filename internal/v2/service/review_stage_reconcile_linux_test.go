//go:build linux

package service

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only the native process observation is a component fixture. Dispatch,
// claiming, control-intent selection, admin preflight and CAS use real code.
type reviewStageLauncher struct {
	api.Launcher
	f        *fx.Fixture
	stop     context.CancelFunc
	calls    int
	stageErr error
	lease    api.EffectLease
	result   *api.ProcessObservation
}

func (l *reviewStageLauncher) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if handle.ID != l.f.Reservation.LaunchID || handle.Target != l.f.Reservation.Target ||
		handle.ContainmentID != l.f.Prepared.ContainmentID || handle.Generation != l.f.Prepared.ProcessGeneration {
		return api.ProcessObservation{}, serviceError(api.CodeForbidden, "component observation selected another process")
	}
	return api.ProcessObservation{Handle: handle, State: "running"}, nil
}

func (l *reviewStageLauncher) Stop(ctx context.Context, handle api.ProcessHandle, reason string) (api.ProcessObservation, error) {
	l.calls++
	defer l.stop()
	var ok bool
	l.lease, ok = api.EffectLeaseFromContext(ctx)
	if !ok || l.lease.Record.Effect.Stop == nil || *l.lease.Record.Effect.Stop != handle || reason == "" {
		l.stageErr = serviceError(api.CodeIntegrity, "reconciler omitted its actual stage lease")
		return api.ProcessObservation{}, l.stageErr
	}
	cause, claim, err := l.f.State.LaunchControlIntent(ctx, api.InternalHelperStop, l.f.Reservation.LaunchID)
	if err == nil && !reflect.DeepEqual(claim, l.lease.Record) {
		err = serviceError(api.CodeIntegrity, "control source substituted another live stage")
	}
	if err == nil {
		_, err = admin.CheckLaunchStageAuthority(ctx, l.f.State, l.f.Deps.Config, cause, api.InternalHelperStop)
	}
	if err == nil {
		scope := l.f.Execution
		scope.Actor = api.Actor{Kind: "service", ID: claim.ClaimantID}
		_, err = l.f.State.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause,
			Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: l.f.Reservation.ID, Generation: l.f.Record.Generation}},
			Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: cause.Target.LifeID, Epoch: cause.CancellationEpoch}}}})
	}
	l.stageErr = err
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if l.result != nil {
		return *l.result, nil
	}
	return api.ProcessObservation{}, api.NotImplemented("component-native", "process execution boundary")
}

func TestReviewStageRealReconciler(t *testing.T) {
	f := fx.Ready(t, true)
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	handle := api.ProcessHandle{ID: f.Reservation.LaunchID, Target: f.Reservation.Target, ContainmentID: f.Prepared.ContainmentID, Generation: f.Prepared.ProcessGeneration}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &handle}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	launcher := &reviewStageLauncher{f: f, stop: cancel}
	host := fixtureServer(t)
	host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, f.State, f.Deps.Clock
	host.runtime = api.RuntimeServices{Store: f.State, Launcher: launcher}
	host.reconcileLoop(ctx)
	if launcher.calls != 1 || launcher.stageErr != nil || host.fault != nil || launcher.lease.Record.ClaimantID == cause.Actor.ID {
		t.Fatal("real reconciler did not authorize the fresh stage under its exact attempt", launcher.stageErr, host.fault)
	}
	current, err := f.State.Effect(context.Background(), f.Execution, effect.ID)
	if err != nil || current.Outcome != nil || !bytes.Equal(fx.JSON(t, current.Effect), fx.JSON(t, effect)) {
		t.Fatal("stage preflight changed immutable input or invented native completion", err)
	}
}

func TestReviewStageNeedsEndCoordinator(t *testing.T) {
	f := fx.Ready(t, true)
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	handle := api.ProcessHandle{ID: f.Reservation.LaunchID, Target: f.Reservation.Target, ContainmentID: f.Prepared.ContainmentID, Generation: f.Prepared.ProcessGeneration}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &handle}
	claim := claimControl(t, f, effect)
	zero, exit := uint64(0), 0
	observed := api.ProcessObservation{Handle: handle, State: "exited", Survivors: &zero, ExitCode: &exit,
		PromptStatus: "completed", ObservedAt: api.Timestamp(f.Deps.Clock.Now().UTC().Format(time.RFC3339Nano))}
	launcher := &reviewStageLauncher{f: f, stop: func() {}, result: &observed}
	host := fixtureServer(t)
	host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, f.State, f.Deps.Clock
	host.runtime = api.RuntimeServices{Store: f.State, Launcher: launcher}
	outcome, err := host.runEffect(context.Background(), f.Execution, claim)
	var typed *api.Error
	if launcher.calls != 1 || launcher.stageErr != nil || !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || outcome.Observation != nil {
		t.Fatal("native preflight must run, but a terminal stop cannot complete without its lifecycle coordinator", launcher.calls, launcher.stageErr, err)
	}
	current, err := f.State.Effect(context.Background(), f.Execution, effect.ID)
	if err != nil || current.Outcome != nil || !bytes.Equal(fx.JSON(t, current.Effect), fx.JSON(t, effect)) {
		t.Fatal("missing coordinator completed or changed the original Stop effect", err)
	}
}
