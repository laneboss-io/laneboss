package lifecycle

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type insertedState struct {
	*launchFixtureStore
	state api.EffectState
}

func (store insertedState) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	commit, err := store.launchFixtureStore.Transact(ctx, tx)
	if err != nil {
		return api.Commit{}, err
	}
	for _, effect := range tx.Effects {
		if effect.HelperAllocate == nil {
			continue
		}
		scope := tx.Scope
		claim, err := store.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
			ClaimantID: scope.Actor.ID, Deadline: "2030-01-02T03:09:05Z"})
		if err != nil {
			return api.Commit{}, err
		}
		if store.state == api.EffectCompleted {
			// Deliberately corrupt the newly inserted state to model a store
			// that returns a terminal receipt instead of its pending insert.
			record := claim.Record
			record.State, record.Generation = api.EffectCompleted, record.Generation+1
			record.Outcome = &api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID,
				ExpectedGeneration: claim.Record.Generation, Status: "succeeded", HelperLease: &api.HelperLease{ID: "unearned-lease"}}
			store.effects[effect.ID] = record
		}
	}
	return commit, nil
}

func TestChildInsert(t *testing.T) {
	for _, state := range []api.EffectState{api.EffectClaimed, api.EffectCompleted} {
		t.Run(string(state), func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			f.service.deps.Store = insertedState{f.store, state}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["allocate"] != 0 || f.ports.calls["materialize-entry"] != 0 {
				t.Fatalf("new child effect skipped its pending insert: %v", err)
			}
		})
	}
}

type changedClaim struct {
	*launchFixtureStore
	mode string
}

func (store changedClaim) ClaimEffect(ctx context.Context, scope api.Scope, request api.EffectClaimRequest) (api.EffectLease, error) {
	lease, err := store.launchFixtureStore.ClaimEffect(ctx, scope, request)
	if err != nil {
		return api.EffectLease{}, err
	}
	switch store.mode {
	case "id":
		lease.ClaimID, lease.Record.ClaimID = "", ""
	case "effect":
		lease.Record.Effect.OperationID = "foreign-operation"
	case "generation":
		lease.Record.Generation = request.ExpectedGeneration
	case "outcome":
		lease.Record.Outcome = &api.EffectOutcome{EffectID: request.EffectID, Error: api.NotImplemented("store-owner", "unearned outcome")}
	}
	store.effects[request.EffectID] = lease.Record
	return lease, nil
}

func TestChildClaim(t *testing.T) {
	for _, mode := range []string{"valid", "id", "effect", "generation", "outcome", "terminal"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			child := api.EffectRecord{Effect: launchClone(t, request.Lease.Record.Effect), State: api.EffectPending, Generation: 1}
			child.Effect.ID = launchIDForTest()
			child.Effect.Context.EffectID = child.Effect.ID
			f.store.effects[child.Effect.ID] = child
			if mode == "terminal" {
				child.State = api.EffectCompleted
			}
			f.service.deps.Store = changedClaim{f.store, mode}
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: record}
			got, err := execution.claimChild(context.Background(), child)
			if mode == "valid" {
				if err != nil || got.Record.State != api.EffectClaimed || got.Record.Generation <= child.Generation || got.ClaimID == "" {
					t.Fatalf("child claim lost its valid transition: %v", err)
				}
			} else if err == nil {
				t.Fatal("child claim accepted a skipped or replaced transition")
			}
		})
	}
}

func TestCompleteLease(t *testing.T) {
	for _, mode := range []string{"pending", "claim", "outcome"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			lease := launchClone(t, request.Lease)
			switch mode {
			case "pending":
				lease.Record.State = api.EffectPending
			case "claim":
				lease.Record.ClaimID = "foreign-claim"
			case "outcome":
				lease.Record.Outcome = &api.EffectOutcome{EffectID: lease.Record.Effect.ID, Status: "succeeded"}
			}
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: record}
			err := execution.completeChild(context.Background(), lease, api.EffectOutcome{Status: "succeeded"})
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.store.effects[lease.Record.Effect.ID].Outcome != nil {
				t.Fatalf("child completion accepted an unclaimed lease: %v", err)
			}
		})
	}
}

type changedCompletion struct {
	*launchFixtureStore
	mode string
}

func (store changedCompletion) CompleteEffect(ctx context.Context, scope api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	commit, err := store.launchFixtureStore.CompleteEffect(ctx, scope, outcome)
	if err != nil {
		return api.Commit{}, err
	}
	record := store.effects[outcome.EffectID]
	if store.mode == "claim" {
		record.ClaimID, record.Outcome.ClaimID = "foreign-claim", "foreign-claim"
	} else {
		record.ClaimantID = "foreign-service"
	}
	store.effects[outcome.EffectID] = record
	return commit, nil
}

func TestCompletionClaim(t *testing.T) {
	for _, mode := range []string{"claim", "claimant"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			f.service.deps.Store = changedCompletion{f.store, mode}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["materialize-entry"] != 0 {
				t.Fatalf("child completion replaced its original claim: %v", err)
			}
		})
	}
}

func TestReceiptClaim(t *testing.T) {
	for _, mode := range []string{"alloc-claim", "alloc-gen", "data-claim", "data-gen", "data-error"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			id := launchObjectID(plan.Reservation.ID, "allocate-effect")
			if mode == "data-claim" || mode == "data-gen" || mode == "data-error" {
				id = f.store.dataStages[plan.Reservation.ID].Worker.EffectID
			}
			effect := launchClone(t, f.store.effects[id])
			switch mode {
			case "alloc-claim":
				effect.ClaimID, effect.Outcome.ClaimID = "", ""
			case "alloc-gen":
				effect.Outcome.ExpectedGeneration = 1
			case "data-claim":
				effect.ClaimID, effect.Outcome.ClaimID = "foreign-claim", "foreign-claim"
			case "data-gen":
				effect.Outcome.ExpectedGeneration++
				effect.Generation++
			case "data-error":
				effect.State = api.EffectClaimed
				effect.Outcome.Error = api.NotImplemented("worker-owner", "forged failure on a claimed record")
			}
			f.store.effects[id] = effect
			_, err = f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["allocate"] != 1 || f.ports.calls["materialize-entry"] != 1 {
				t.Fatalf("retained plan trusted an unearned terminal effect: %v", err)
			}
		})
	}
}

func TestArchiveState(t *testing.T) {
	for _, mode := range []string{"pending", "completed", "invalid", "claim", "generation"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, job := archiveJobFixture(t)
			if mode == "claim" || mode == "generation" {
				receipt := f.finishArchive(t, job.Intent.OperationID, "valid")
				effect := launchClone(t, f.store.effects[job.Lease.EffectID])
				if mode == "claim" {
					effect.ClaimID, effect.Outcome.ClaimID = "", ""
				} else {
					effect.Outcome.ExpectedGeneration = 1
				}
				f.store.effects[effect.Effect.ID] = effect
				if err := f.service.archiveCompletion(context.Background(), scope, f.child, job, receipt); err == nil {
					t.Fatal("archive completion skipped its claimed transition")
				}
				return
			}
			effect := f.store.effects[job.Lease.EffectID]
			if mode == "completed" {
				effect.State = api.EffectCompleted
			}
			if mode == "invalid" {
				effect.State = "invalid"
			}
			f.store.effects[effect.Effect.ID] = effect
			err := f.service.archiveJob(context.Background(), scope, f.store, f.child, job.Intent, job)
			if mode == "pending" {
				if err != nil {
					t.Fatalf("archive rejected its pending reservation: %v", err)
				}
			} else if err == nil {
				t.Fatal("archive reservation skipped its pending transition")
			}
		})
	}
}

func TestWriterClaimState(t *testing.T) {
	for _, mode := range []string{"terminal", "pending-claim", "claimed-id"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			effect := launchClone(t, request.Lease.Record)
			switch mode {
			case "terminal":
				effect.State = api.EffectCompleted
			case "pending-claim":
				effect.State = api.EffectPending
			case "claimed-id":
				effect.ClaimID = ""
			}
			f.store.effects[effect.Effect.ID] = effect
			_, err := f.store.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.Effect.ID,
				ExpectedGeneration: effect.Generation, ClaimantID: scope.Actor.ID, Deadline: request.Lease.ExpiresAt})
			if err == nil || f.store.effects[effect.Effect.ID].Generation != effect.Generation {
				t.Fatalf("fixture writer bypassed the effect transition table: %v", err)
			}
		})
	}
}
