//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Refusals are injected at a named boundary for one retained effect. The next
// effect uses real SQLite claim/completion; no completed outcome is fabricated.
type reconcileFenceStore struct {
	*store.Service
	stage    string
	failure  error
	blocked  api.ID
	next     api.ID
	finished func()
}

func (s *reconcileFenceStore) PendingEffects(ctx context.Context, request api.CursorRequest) ([]api.Effect, error) {
	if s.stage == "pending" {
		return nil, s.failure
	}
	effects, err := s.Service.PendingEffects(ctx, request)
	if err != nil {
		return nil, err
	}
	for i := range effects {
		if effects[i].ID == s.blocked {
			effects[0], effects[i] = effects[i], effects[0]
			break
		}
	}
	return effects, nil
}

func (s *reconcileFenceStore) RecoverGuidance(ctx context.Context) error {
	if s.stage == "recovery" {
		return s.failure
	}
	return s.Service.RecoverGuidance(ctx)
}

func (s *reconcileFenceStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if s.stage == "lookup" && id == s.blocked {
		return api.EffectRecord{}, s.failure
	}
	return s.Service.Effect(ctx, scope, id)
}

func (s *reconcileFenceStore) ClaimEffect(ctx context.Context, scope api.Scope, request api.EffectClaimRequest) (api.EffectLease, error) {
	if s.stage == "claim" && request.EffectID == s.blocked {
		return api.EffectLease{}, s.failure
	}
	return s.Service.ClaimEffect(ctx, scope, request)
}

func (s *reconcileFenceStore) CompleteEffect(ctx context.Context, scope api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	if s.stage == "complete" && outcome.EffectID == s.blocked {
		return api.Commit{}, s.failure
	}
	commit, err := s.Service.CompleteEffect(ctx, scope, outcome)
	if err == nil && outcome.EffectID == s.next {
		s.finished()
	}
	return commit, err
}

type reconcileObserver struct {
	api.Launcher
	blocked api.ID
	failure error
}

func (l *reconcileObserver) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if handle.ID == l.blocked && l.failure != nil {
		return api.ProcessObservation{}, l.failure
	}
	zero, exit := uint64(0), 0
	return api.ProcessObservation{Handle: handle, State: "exited", Survivors: &zero, ExitCode: &exit,
		PromptStatus: "completed", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}, nil
}

func (l *reconcileObserver) Stop(ctx context.Context, handle api.ProcessHandle, reason string) (api.ProcessObservation, error) {
	if reason == "" {
		return api.ProcessObservation{}, serviceError(api.CodeInvalid, "component stop requires its recorded reason")
	}
	return l.Observe(ctx, handle)
}

func reconcileFixture(t *testing.T, stage string, failure error) (*Server, *reconcileFenceStore, api.Scope, context.Context, *bool) {
	t.Helper()
	ctx := context.Background()
	directory := privateHostDirectory(t)
	actual, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := actual.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := api.Scope{Config: "service-fixture", Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "worker"}
	state := &reconcileFenceStore{Service: actual, stage: stage, failure: failure}
	observer := &reconcileObserver{}
	for i := 0; i < 2; i++ {
		f := fx.NewIn(t, actual, store.Dependencies{Config: scope.Config, Directory: directory, Clock: fixtureClock{}})
		f.Reserve(t)
		f.Source(t)
		f.BuildPlan(t, true)
		f.Spec(t)
		f.Bind(t)
		f.Opened(t)
		actual, state.Service = f.State, f.State
		target, lane, handle := f.Reservation.Target, f.Lane, f.Process
		id, operation := fixtureID(t), fixtureID(t)
		intent := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalLifecycleEffect, Config: scope.Config,
			Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: operation, CauseRequestID: fixtureID(t),
			EffectID: id, Target: target, CancellationEpoch: lane.CancellationEpoch}
		effect := api.Effect{ID: id, OperationID: operation, Context: &intent, Stop: &handle}
		if _, err := actual.Transact(ctx, api.Transaction{Scope: scope, Internal: &intent, Effects: []api.Effect{effect}}); err != nil {
			t.Fatal("reconcile pending effect control failed", err)
		}
		if i == 0 {
			state.blocked = id
			if stage == "run" {
				observer.blocked, observer.failure = handle.ID, failure
			}
		} else {
			state.next = id
		}
	}
	host := fixtureServer(t)
	host.deps.Store = state
	host.runtime.Launcher = observer
	host.runtime.Lifecycle, err = lifecycle.New(lifecycle.Dependencies{Store: state, Identity: &authFixture{}, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	t.Cleanup(cancel)
	active := new(bool)
	state.finished = func() {
		host.mu.RLock()
		*active = host.reconciling && host.fault == nil
		host.mu.RUnlock()
		cancel()
	}
	return host, state, scope, runCtx, active
}

func TestReconcileSkipsEffectFences(t *testing.T) {
	for _, row := range []struct {
		name, stage string
		failure     error
	}{
		{"claim_forbidden", "claim", serviceError(api.CodeForbidden, "component launch revoked")},
		{"claim_conflict", "claim", serviceError(api.CodeConflict, "component claim changed")},
		{"complete_forbidden", "complete", serviceError(api.CodeForbidden, "component grant revoked")},
		{"complete_conflict", "complete", serviceError(api.CodeConflict, "component claim expired")},
		{"run_forbidden", "run", serviceError(api.CodeForbidden, "component execution revoked")},
		{"run_conflict", "run", serviceError(api.CodeConflict, "component execution claim expired")},
		{"wrapped_claim", "claim", fmt.Errorf("claim boundary: %w", serviceError(api.CodeForbidden, "component launch revoked"))},
	} {
		t.Run(row.name, func(t *testing.T) {
			host, state, scope, ctx, active := reconcileFixture(t, row.stage, row.failure)
			host.reconcileLoop(ctx)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("reconcile fence fixture exceeded its bound")
			}
			next, err := state.Service.Effect(context.Background(), scope, state.next)
			if err != nil {
				t.Fatal("reconcile outcome lookup failed", err)
			}
			if next.Outcome == nil || next.State != api.EffectCompleted || next.Outcome.Status != "succeeded" || next.Outcome.Observation == nil || next.Outcome.Observation.Handle != *next.Effect.Stop {
				t.Fatal("per-effect refusal stopped later work")
			}
			blocked, err := state.Service.Effect(context.Background(), scope, state.blocked)
			if err != nil {
				t.Fatal("refused effect lookup failed", err)
			}
			host.mu.RLock()
			fault := host.fault
			host.mu.RUnlock()
			if fault != nil || !*active {
				t.Fatal("per-effect fence latched host fault", fault)
			}
			var refused *api.Error
			if row.stage == "run" && errors.As(row.failure, &refused) && refused.Code == api.CodeForbidden {
				if blocked.Outcome == nil || blocked.State != "failed" || blocked.Outcome.Error == nil || blocked.Outcome.Error.Code != api.CodeForbidden {
					t.Fatal("execution refusal was not retained as failed")
				}
			} else if blocked.Outcome != nil {
				t.Fatal("unowned or stale effect was falsely completed")
			}
		})
	}
}

func TestReconcileKeepsStoreFailures(t *testing.T) {
	storageFailure := errors.New("component storage read failed")
	integrity := serviceError(api.CodeIntegrity, "component effect bytes changed")
	mixed := errors.Join(serviceError(api.CodeForbidden, "component launch revoked"), storageFailure)
	for _, row := range []struct {
		name, stage string
		failure     error
	}{
		{"claim_integrity", "claim", integrity},
		{"claim_store", "claim", storageFailure},
		{"complete_integrity", "complete", integrity},
		{"complete_store", "complete", storageFailure},
		{"run_integrity", "run", integrity},
		{"run_store", "run", storageFailure},
		{"claim_mixed", "claim", mixed},
		{"complete_mixed", "complete", mixed},
		{"run_mixed", "run", mixed},
		{"pending_store", "pending", storageFailure},
		{"lookup_store", "lookup", storageFailure},
		{"recovery_store", "recovery", storageFailure},
		{"pending_forbidden", "pending", serviceError(api.CodeForbidden, "component inventory authority failed")},
		{"lookup_forbidden", "lookup", serviceError(api.CodeForbidden, "component store authority failed")},
		{"recovery_forbidden", "recovery", serviceError(api.CodeForbidden, "component recovery authority failed")},
	} {
		t.Run(row.name, func(t *testing.T) {
			host, state, scope, ctx, _ := reconcileFixture(t, row.stage, row.failure)
			host.reconcileLoop(ctx)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("reconcile store fixture exceeded its bound")
			}
			host.mu.RLock()
			fault := host.fault
			host.mu.RUnlock()
			if !errors.Is(fault, row.failure) {
				t.Fatal("reconciler lost a store or integrity failure", fault)
			}
			next, err := state.Service.Effect(context.Background(), scope, state.next)
			if err != nil || next.Outcome != nil {
				t.Fatal("reconciler continued after a fatal store failure", err)
			}
		})
	}
}
