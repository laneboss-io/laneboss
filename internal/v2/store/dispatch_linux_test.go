//go:build linux

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The trusted coordinator setup is component input, not a human approval or
// deployment test. The barrier itself uses real SQLite transactions/reopening.
func dispatchFixture(t *testing.T, s *Service) (api.Scope, api.FreezeRequest, api.Effect) {
	t.Helper()
	input := testPendingTransaction(t)
	commit, err := s.Transact(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	scope := input.Scope
	scope.Request = api.Request{}
	bytes := []byte(testID(t))
	reason, err := s.RetainObject(context.Background(), scope, api.RetainObjectRequest{
		Intent: api.InternalIntent{ID: testID(t), Kind: api.InternalObjectRetain, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: commit.Operation.ID},
		Object: api.ObjectWrite{ObjectKey: testID(t), Class: "report", Bytes: bytes, SHA256: testDigest(bytes), Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal("committed freeze reason control failed", err)
	}
	plan := api.DeploymentPlan{ID: testID(t), Config: scope.Config, Actor: scope.Actor, InstallationGeneration: 1,
		EndpointGeneration: 1, Generation: 1, Phase: "freezing", OperationID: commit.Operation.ID}
	intent := api.InternalIntent{ID: testID(t), Kind: api.InternalUpgradeApply, Config: scope.Config, Actor: scope.Actor,
		RequestedBy: scope.Actor, CauseOperationID: commit.Operation.ID, CauseRequestID: input.Scope.Request.RequestID}
	if _, err := s.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &intent, Writes: api.StateWrites{Deployments: []api.DeploymentPlan{plan}}}); err != nil {
		t.Fatal("retained deployment phase control failed", err)
	}
	return scope, api.FreezeRequest{OperationID: commit.Operation.ID, ExpectedInstallationGeneration: 1, Reason: reason}, input.Effects[0]
}

func TestFreezeSurvivesRestart(t *testing.T) {
	s, deps := testStore(t)
	scope, request, effect := dispatchFixture(t, s)
	claim, err := s.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: testID(t), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	runnable, err := s.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil || len(runnable) != 0 {
		t.Fatal("unexpired claim remained runnable", err)
	}
	all, err := s.DispatchEffects(context.Background())
	if err != nil || len(all) != 1 || all[0].ClaimID != claim.ClaimID {
		t.Fatal("dispatch inventory lost a claimed effect", err)
	}
	freeze, err := s.FreezeDispatch(context.Background(), scope, request)
	if err != nil || freeze.ID == "" || freeze.DispatchEpoch == 0 {
		t.Fatal("durable freeze control failed", err)
	}
	retry, err := s.FreezeDispatch(context.Background(), scope, request)
	if err != nil || retry != freeze {
		t.Fatal("freeze retry changed its retained receipt", err)
	}
	changed := request
	changed.Reason.SHA256 = testDigest([]byte("different reason"))
	if _, err := s.FreezeDispatch(context.Background(), scope, changed); err == nil {
		t.Fatal("freeze operation accepted changed input")
	} else {
		expectCode(t, err, api.CodeIdempotencyConflict)
	}
	newWork := testTransaction(t)
	if _, err := s.Transact(context.Background(), newWork); err == nil {
		t.Fatal("frozen store committed new public work")
	} else {
		expectCode(t, err, api.CodeUnavailable)
	}
	raw, err := json.Marshal(newWork.Scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveRequest(context.Background(), api.RequestReservation{Scope: newWork.Scope, RawRequest: raw,
		Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}); err == nil {
		t.Fatal("frozen store reserved new public work")
	} else {
		expectCode(t, err, api.CodeUnavailable)
	}
	if _, err := s.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: claim.Record.Generation,
		ClaimantID: testID(t), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}); err == nil {
		t.Fatal("frozen store admitted another effect claim")
	} else {
		expectCode(t, err, api.CodeUnavailable)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("durable freeze broke state verification", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(deps)
	if err != nil {
		t.Fatal("frozen state could not reopen", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	active, err := s.ActiveDispatchFreeze(context.Background())
	if err != nil || active == nil || *active != freeze {
		t.Fatal("restart lost durable dispatch freeze", err)
	}
	wrong := freeze
	wrong.ID = testID(t)
	if err := s.ThawDispatch(context.Background(), scope, wrong); err == nil {
		t.Fatal("forged freeze receipt opened dispatch")
	} else {
		expectCode(t, err, api.CodeForbidden)
	}
	if err := s.ThawDispatch(context.Background(), scope, freeze); err != nil {
		t.Fatal("exact thaw control failed", err)
	}
	if err := s.ThawDispatch(context.Background(), scope, freeze); err != nil {
		t.Fatal("exact thaw retry failed", err)
	}
	active, err = s.ActiveDispatchFreeze(context.Background())
	if err != nil || active != nil {
		t.Fatal("thaw did not retain a readable open barrier", err)
	}
	if _, err := s.Transact(context.Background(), newWork); err != nil {
		t.Fatal("thawed store did not admit new work", err)
	}
	nextScope, next, _ := dispatchFixture(t, s)
	newFreeze, err := s.FreezeDispatch(context.Background(), nextScope, next)
	if err != nil || newFreeze.DispatchEpoch <= freeze.DispatchEpoch {
		t.Fatal("later freeze did not advance its epoch", err)
	}
	if err := s.ThawDispatch(context.Background(), scope, freeze); err == nil {
		t.Fatal("stale thaw opened a later deployment freeze")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
	if err := s.ThawDispatch(context.Background(), nextScope, newFreeze); err != nil {
		t.Fatal("later deployment thaw failed", err)
	}
	if err := s.ThawDispatch(context.Background(), scope, freeze); err == nil {
		t.Fatal("stale thaw ignored intervening dispatch epochs")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
}

func TestFrozenReservationCanFinish(t *testing.T) {
	s, _ := testStore(t)
	scope, request, _ := dispatchFixture(t, s)
	input := testTransaction(t)
	raw, err := json.Marshal(input.Scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := s.ReserveRequest(context.Background(), api.RequestReservation{Scope: input.Scope, RawRequest: raw,
		Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal("reservation control failed", err)
	}
	if _, err := s.FreezeDispatch(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	requests, err := s.DispatchRequests(context.Background())
	if err != nil || len(requests) != 1 || requests[0] != reserved.Operation.ID {
		t.Fatal("drain inventory lost a reserved request", err)
	}
	completed, err := s.Transact(context.Background(), input)
	if err != nil || completed.Operation.ID != reserved.Operation.ID {
		t.Fatal("freeze stranded an admitted reservation", err)
	}
	requests, err = s.DispatchRequests(context.Background())
	if err != nil || len(requests) != 0 {
		t.Fatal("completed reservation remained in drain inventory", err)
	}
	replay, err := s.Transact(context.Background(), input)
	if err != nil || !replay.Replayed || replay.Operation.ID != completed.Operation.ID {
		t.Fatal("freeze changed a completed reservation replay", err)
	}
}
