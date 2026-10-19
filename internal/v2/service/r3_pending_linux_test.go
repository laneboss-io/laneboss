//go:build linux

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Inject a refusal at the owning store boundary. Claim, pending state and the
// next effect's observation/completion still use the real SQLite fixture.
type pendingOwnedStore struct {
	*reconcileFenceStore
	refusal error
	called  bool
}

func (s *pendingOwnedStore) FailOwnedEffect(ctx context.Context, scope api.Scope, lease api.EffectLease, failure *api.Error, observation *api.ProcessObservation) (api.Commit, error) {
	current, err := s.Service.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return api.Commit{}, err
	}
	if current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || current.State != api.EffectClaimed {
		return api.Commit{}, serviceError(api.CodeConflict, "injected refusal lost its actual claim")
	}
	if current.Effect.ID == s.blocked {
		s.called = true
		return api.Commit{}, s.refusal
	}
	return s.Service.FailOwnedEffect(ctx, scope, lease, failure, observation)
}

func TestOwnedPendingDoesNotHalt(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "quiescence"
		if mixed {
			name = "mixed_storage"
		}
		t.Run(name, func(t *testing.T) {
			host, state, scope, ctx, active := reconcileFixture(t, "", nil)
			next, err := state.Service.Effect(context.Background(), scope, state.next)
			if err != nil {
				t.Fatal(err)
			}
			lane, err := state.Service.Lane(context.Background(), scope, next.Effect.Context.Target)
			if err != nil {
				t.Fatal(err)
			}
			clean := api.CleanRequest{Target: next.Effect.Context.Target, ExpectedGeneration: lane.Generation, ArchiveReceiptID: fixtureID(t)}
			request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config, Method: "lane.clean", RequestID: fixtureID(t), IdempotencyKey: fixtureID(t), Params: fixtureJSON(t, clean)}
			request.RequestSHA256, err = api.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			caller := scope
			caller.Request = request
			receipt, _, err := state.Service.ReserveMutation(context.Background(), api.RequestReservation{Scope: caller, RawRequest: fixtureJSON(t, request), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
			if err != nil {
				t.Fatal(err)
			}
			cause := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalLifecycleEffect, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: receipt.Operation.ID, CauseRequestID: request.RequestID, EffectID: fixtureID(t), Target: clean.Target, CancellationEpoch: lane.CancellationEpoch}
			effect := api.Effect{ID: cause.EffectID, OperationID: receipt.Operation.ID, Context: &cause, Clean: &clean}
			if _, err := state.Service.Transact(context.Background(), api.Transaction{Scope: caller, Effects: []api.Effect{effect}, Reply: &api.RPCReply{Result: fixtureJSON(t, receipt.Operation)}}); err != nil {
				t.Fatal(err)
			}
			state.blocked = effect.ID
			refusal := error(serviceError(api.CodeContainmentUnknown, "original native worker is still live"))
			storage := errors.New("owning writer evidence read failed")
			if mixed {
				refusal = errors.Join(refusal, storage)
			}
			pending := &pendingOwnedStore{reconcileFenceStore: state, refusal: refusal}
			host.deps.Store = pending
			host.reconcileLoop(ctx)
			current, err := state.Service.Effect(context.Background(), scope, effect.ID)
			if err != nil || current.Outcome != nil || current.State != api.EffectClaimed || !pending.called {
				t.Fatal("containment refusal did not preserve its actual pending claim", err)
			}
			next, err = state.Service.Effect(context.Background(), scope, state.next)
			if err != nil {
				t.Fatal(err)
			}
			host.mu.RLock()
			fault := host.fault
			host.mu.RUnlock()
			if mixed {
				if !errors.Is(fault, storage) || next.Outcome != nil {
					t.Fatal("pending containment swallowed a joined storage failure", fault)
				}
			} else if errors.Is(ctx.Err(), context.DeadlineExceeded) || fault != nil || !*active || next.State != api.EffectCompleted || next.Outcome == nil || next.Outcome.Observation == nil {
				t.Fatal("pending containment halted unrelated real effect processing", fault)
			}
		})
	}
}
