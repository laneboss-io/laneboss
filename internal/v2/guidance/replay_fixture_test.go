package guidance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Replay setup uses the stateful reservation/completion ports and shared
// contract validators. It deliberately avoids GuidanceSelect, completeClaim
// and sealReplay: mutations of replay must reach the test's own assertion,
// rather than failing while that same replay code constructs its fixture.
// This is a unit fixture, not evidence from the production store or provider.
func pendingFixture(t *testing.T, candidates ...api.DecisionCandidate) (*Service, *claimStore, *judgeProbe, api.Scope, api.GuidanceRequest, api.Guidance) {
	t.Helper()
	service, store, judge, owner := claimFixture(t)
	store.candidates = append([]api.DecisionCandidate{}, candidates...)
	request := store.request
	all, snapshot, err := service.candidateSnapshot(context.Background(), owner, request.Target, store.policy.Generation)
	if err != nil {
		t.Fatalf("seed candidate snapshot: %v", err)
	}
	task, err := service.taskBytes(context.Background(), owner, request.Task)
	if err != nil {
		t.Fatalf("seed retained task: %v", err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	claim := api.GuidanceReservationRequest{AttemptID: api.ID(hex.EncodeToString(nonce[:])), Target: request.Target,
		LogicalTurnID: request.LogicalTurnID, ExpectedTask: request.Task, ExpectedTurnGeneration: store.turn.Generation,
		PolicyGeneration: store.policy.Generation, CandidateSnapshotID: snapshot, CancellationEpoch: store.lane.CancellationEpoch,
		MaxCostMicros: store.lane.BudgetRemaining.SpendMicros, Deadline: api.Timestamp(store.clock.Now().Add(5 * time.Second).Format(time.RFC3339Nano))}
	r, err := store.ReserveGuidance(context.Background(), owner, claim)
	if err != nil || !api.GuidanceCanEvaluate(claim, r, store.clock.Now()) {
		t.Fatalf("seed did not acquire a valid owner claim: %v", err)
	}
	result, err := service.evaluateBatchesAt(context.Background(), owner, api.JudgeRequest{
		ID: claim.AttemptID, Purpose: "guidance", Rules: []api.JudgeRule{}, Decisions: all, Task: task,
		Config: store.policy.Judge, MaxCostMicros: r.MaxCostMicros,
		Context: api.JudgeContext{Config: owner.Config, Target: r.Target, LogicalTurnID: r.LogicalTurnID,
			Role: store.policy.Context, PolicyGeneration: r.PolicyGeneration, GrantSetID: store.grants.ID,
			GrantsSHA256: store.grants.SHA256, CWD: store.lane.Workspace.LogicalCWD}}, store.policy, store.clock.Now())
	if err != nil {
		t.Fatalf("seed evaluation: %v", err)
	}
	result.ID = api.ID(string(digestBytes([]byte(string(r.ID) + ":" + string(r.ClaimID))))[:32])
	result.Target, result.Task, result.LogicalTurnID = r.Target, r.Task, r.LogicalTurnID
	result.PolicyGeneration, result.CandidateSnapshotID, result.ReservationID = r.PolicyGeneration, r.CandidateSnapshotID, r.ID
	observer := owner
	observer.Request.RequestID, observer.Request.IdempotencyKey = "replay-request", "replay-key"
	observer = scopeForGuidance(t, observer, request)
	resetReplayObservations(store, judge)
	return service, store, judge, observer, request, result
}

func completeFixtureClaim(t *testing.T, store *claimStore, result api.Guidance) {
	t.Helper()
	store.mu.Lock()
	r, turn := *store.r, store.turn
	store.mu.Unlock()
	selection := api.GuidanceSelection{AttemptID: r.OwnerAttemptID, ReservationID: r.ID, ClaimID: r.ClaimID,
		ExpectedGeneration: r.Generation, Result: result}
	cause := api.InternalIntent{ID: "seed-completion", Kind: api.InternalGuidanceComplete, Config: r.Config,
		Actor: api.Actor{Kind: "service", ID: "guidance"}, RequestedBy: r.RequestedBy,
		CauseOperationID: r.OwnerOperationID, CauseRequestID: r.OwnerRequestID, Target: r.Target,
		LogicalTurnID: r.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	if err := api.ValidateGuidanceCompletion(r, selection, cause, store.clock.Now()); err != nil {
		t.Fatalf("seed completion contract: %v", err)
	}
	turn.GuidanceID, turn.PolicyGeneration, turn.Generation = result.ID, r.PolicyGeneration, turn.Generation+1
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	tx := api.Transaction{Scope: api.Scope{Config: r.Config, Actor: r.RequestedBy, PolicyGeneration: r.PolicyGeneration}, Internal: &cause,
		Writes:  api.StateWrites{Guidance: []api.GuidanceSelection{selection}, Turns: []api.TurnSnapshot{turn}},
		Compare: []api.Compare{{Kind: api.CompareGuidance, ID: r.ID, Generation: r.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}},
		Events: []api.Event{{Kind: "guidance.selected", Config: r.Config, Origin: "service", LifeID: r.Target.LifeID,
			Run: r.Target.Run, LogicalTurnID: r.LogicalTurnID, Actor: cause.Actor, RequestedBy: r.RequestedBy,
			OperationID: r.OwnerOperationID, RequestID: r.OwnerRequestID, Payload: payload}}}
	commit, err := store.Transact(context.Background(), tx)
	if err != nil || commit.Operation.Status != "succeeded" {
		t.Fatalf("seed completion transaction: %v", err)
	}
	store.mu.Lock()
	err = api.ValidateGuidanceReservation(*store.r)
	store.mu.Unlock()
	if err != nil {
		t.Fatalf("seed retained claim contract: %v", err)
	}
}

func retainedFixture(t *testing.T, candidates ...api.DecisionCandidate) (*Service, *claimStore, *judgeProbe, api.Scope, api.GuidanceRequest, api.Guidance) {
	t.Helper()
	service, store, judge, scope, request, result := pendingFixture(t, candidates...)
	completeFixtureClaim(t, store, result)
	resetReplayObservations(store, judge)
	return service, store, judge, scope, request, result
}

func scopeForGuidance(t *testing.T, scope api.Scope, request api.GuidanceRequest) api.Scope {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request.Protocol, scope.Request.Schema, scope.Request.Config = api.Protocol, api.SchemaVersion, scope.Config
	scope.Request.Params = raw
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func resetReplayObservations(store *claimStore, judge *judgeProbe) {
	// Keep reserveRequests, txs, receipts and state as the actual setup trace.
	// Only counters for operations observed by the replay assertion are reset.
	store.laneCalls, store.policyCalls, store.historyReads = 0, 0, 0
	store.reservationCalls, store.reserveCalls, store.awaitCalls = 0, 0, 0
	store.candidateCalls, store.candidateReads, store.transactions = 0, 0, 0
	store.lastTransaction = api.Transaction{}
	judge.fitCalls, judge.evalCalls = 0, 0
}
