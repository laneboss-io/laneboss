package guidance

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Stateful contract fixture, not the production store or a native boundary.
// It compares actual inputs, grants, CAS and epoch and signals real waiters.
type claimStore struct {
	ceiling  int64
	request  api.GuidanceRequest
	taskData []byte
	api.StateStore
	mu               sync.Mutex
	lane             api.Lane
	turn             api.TurnSnapshot
	policy           api.EffectivePolicy
	policies         map[api.Generation]api.EffectivePolicy
	clock            *fixedClock
	candidates       []api.DecisionCandidate
	r                *api.GuidanceReservation
	done             chan struct{}
	awaitEntered     chan struct{}
	receipts         map[claimReceiptKey]api.MutationReceipt
	reserveRequests  []api.GuidanceReservationRequest
	awaitRequests    []api.GuidanceAwaitRequest
	txs              []api.Transaction
	grants           api.GrantSet
	wrongOwner       bool
	forceObserver    bool
	expireAwait      bool
	advanceReserve   bool
	observerResult   *api.Guidance
	lookupMisses     int
	refreshes        int
	candidateReads   int
	commits          int
	events           int
	laneCalls        int
	policyCalls      int
	historyReads     int
	reservationCalls int
	reserveCalls     int
	awaitCalls       int
	candidateCalls   int
	transactions     int
	lastTransaction  api.Transaction
}

type claimReceiptKey struct {
	Config string
	Actor  api.Actor
	Key    api.RequestKey
}

func (store *claimStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if result, found := store.receipts[claimReceiptKey{scope.Config, scope.Actor, key}]; found {
		return result, nil
	}
	return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound}
}

func (store *claimStore) Lane(context.Context, api.Scope, api.LifeRef) (api.Lane, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.laneCalls++
	return store.lane, nil
}
func (store *claimStore) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.policyCalls++
	store.policies[store.policy.Generation] = store.policy
	return store.policy, nil
}
func (store *claimStore) PolicyAt(_ context.Context, _ api.Scope, generation api.Generation) (api.EffectivePolicy, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.historyReads++
	if result, found := store.policies[generation]; found {
		return result, nil
	}
	return api.EffectivePolicy{}, &api.Error{Code: api.CodeNotFound}
}
func (store *claimStore) RefreshLanePolicy(_ context.Context, _ api.Scope, request api.PolicyAdvanceRequest) (api.PolicyAdvanceReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	before := store.lane
	if request.ExpectedLaneGeneration != before.Generation || request.CancellationEpoch != before.CancellationEpoch {
		return api.PolicyAdvanceReceipt{}, &api.Error{Code: api.CodeConflict}
	}
	store.lane.PolicyGeneration = store.policy.Generation
	store.lane.Generation++
	store.lane.LastSeq++
	store.refreshes++
	return api.PolicyAdvanceReceipt{Changed: true, Lane: store.lane, EventID: "policy-event", CommittedSeq: store.lane.LastSeq,
		Event: api.PolicyAdvanceEvent{FromGeneration: before.PolicyGeneration, ToGeneration: store.policy.Generation,
			LaneGeneration: store.lane.Generation, PolicySHA256: store.policy.SHA256, GrantSetID: store.lane.GrantSetID}}, nil
}
func (store *claimStore) Turn(context.Context, api.Scope, api.LifeRef, api.ID) (api.TurnSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.turn, nil
}
func (store *claimStore) DecisionCandidates(_ context.Context, _ api.Scope, query api.DecisionQuery) (api.DecisionPage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.candidateReads++
	store.candidateCalls++
	items := []api.DecisionCandidate{}
	for _, item := range store.candidates {
		if item.Binding == (query.Kind == "binding") {
			items = append(items, item)
		}
	}
	return api.DecisionPage{SnapshotID: "snapshot-a", PolicyGeneration: store.policy.Generation,
		AsOf: api.Timestamp(store.clock.Now().UTC().Format(time.RFC3339Nano)), Candidates: items, Complete: true}, nil
}
func (store *claimStore) Source(_ context.Context, _ api.Scope, source api.SourceRef) (api.RetainedSource, error) {
	return api.RetainedSource{Source: source, Content: api.BlobRef{ID: source.ID, SHA256: source.SHA256, Class: "record", Bytes: 1}}, nil
}
func (store *claimStore) Decision(_ context.Context, _ api.Scope, id api.ID) (api.DecisionProjection, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, item := range store.candidates {
		if item.ID == id && item.Authority.Kind == "human" {
			return api.DecisionProjection{RecordID: item.ID, Candidate: item, Status: "active"}, nil
		}
	}
	return api.DecisionProjection{}, &api.Error{Code: api.CodeNotFound}
}
func (store *claimStore) ObjectMetadata(context.Context, api.Scope, api.ID) (api.ObjectMetadata, error) {
	return api.ObjectMetadata{Ref: store.request.Task}, nil
}
func (store *claimStore) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if request.ObjectID != store.request.Task.ID || request.Offset < 0 || request.Offset > int64(len(store.taskData)) {
		return api.BlobChunk{}, integrity("fixture task read changed its object or offset")
	}
	end := min(len(store.taskData), int(request.Offset)+request.Limit)
	data := store.taskData[int(request.Offset):end]
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: digestBytes(data)}, nil
}
func (store *claimStore) Grants(context.Context, api.ID) (api.GrantSet, error) {
	return store.grants, nil
}
func (store *claimStore) GuidanceReservation(context.Context, api.Scope, api.LifeRef, api.ID) (api.GuidanceReservation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.reservationCalls++
	if store.lookupMisses > 0 {
		store.lookupMisses--
		return api.GuidanceReservation{}, &api.Error{Code: api.CodeNotFound}
	}
	if store.r == nil {
		return api.GuidanceReservation{}, &api.Error{Code: api.CodeNotFound}
	}
	result := *store.r
	result.Acquired = false
	return result, nil
}
func (store *claimStore) ReserveGuidance(_ context.Context, scope api.Scope, request api.GuidanceReservationRequest) (api.GuidanceReservation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.reserveCalls++
	store.reserveRequests = append(store.reserveRequests, request)
	if store.r != nil {
		result := *store.r
		result.Acquired = false
		return result, nil
	}
	limit := store.lane.BudgetRemaining.SpendMicros
	if store.ceiling > 0 {
		limit = min(limit, store.ceiling)
	}
	if request.ExpectedTask != store.turn.Task || request.ExpectedTurnGeneration != store.turn.Generation ||
		request.CancellationEpoch != store.lane.CancellationEpoch || request.PolicyGeneration != store.policy.Generation ||
		request.MaxCostMicros != limit {
		return api.GuidanceReservation{}, &api.Error{Code: api.CodeConflict}
	}
	baseline, err := rankSelection(store.clock.Now(), 0, store.candidates, api.JudgeReply{})
	if err != nil {
		return api.GuidanceReservation{}, err
	}
	r := api.GuidanceReservation{Config: scope.Config, ID: api.ID("reservation-" + string(request.AttemptID)), ClaimID: api.ID("claim-" + string(request.AttemptID)),
		Target: request.Target, LogicalTurnID: request.LogicalTurnID, Task: request.ExpectedTask, PolicyGeneration: request.PolicyGeneration,
		CandidateSnapshotID: request.CandidateSnapshotID, TurnGeneration: request.ExpectedTurnGeneration, Generation: 1, Status: "pending",
		OwnerAttemptID: request.AttemptID, OwnerOperationID: api.ID("operation-" + string(scope.Request.RequestID)), OwnerRequestID: scope.Request.RequestID,
		OwnerKey: requestKey(scope), RequestedBy: scope.Actor, CancellationEpoch: request.CancellationEpoch, MaxCostMicros: request.MaxCostMicros,
		ReservedAt: api.Timestamp(store.clock.Now().UTC().Format(time.RFC3339Nano)), Deadline: request.Deadline, BindingItems: baseline.Items}
	if err := api.ValidateGuidanceReservation(r); err != nil {
		return api.GuidanceReservation{}, err
	}
	store.r = &r
	if store.advanceReserve {
		store.clock.value = store.clock.value.Add(2 * time.Second)
	}
	result := r
	result.Acquired = !store.forceObserver
	if store.wrongOwner {
		result.OwnerAttemptID = "foreign-attempt"
	}
	return result, nil
}

func TestItem4GuidanceApprovedCeiling(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	service.deps.MaxCostMicros, store.ceiling = 19, 19
	store.lane.BudgetRemaining.SpendMicros = 100
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil || result.Status != "scored" || judge.fitCalls == 0 {
		t.Fatal("guidance did not judge under its approved smaller ceiling", err)
	}
	if len(store.reserveRequests) != 1 || store.reserveRequests[0].MaxCostMicros != 19 || store.lane.BudgetRemaining.SpendMicros != 100 {
		t.Fatal("guidance lost its positive approved ceiling or reset lane budget")
	}
}
func (store *claimStore) AwaitGuidance(ctx context.Context, _ api.Scope, request api.GuidanceAwaitRequest) (api.GuidanceReservation, error) {
	store.mu.Lock()
	store.awaitCalls++
	store.awaitRequests = append(store.awaitRequests, request)
	select {
	case store.awaitEntered <- struct{}{}:
	default:
	}
	if store.r == nil || request.ReservationID != store.r.ID || request.Deadline != store.r.Deadline {
		store.mu.Unlock()
		return api.GuidanceReservation{}, integrity("fixture await selector changed")
	}
	if store.expireAwait {
		store.clock.value = store.clock.value.Add(6 * time.Second)
		store.mu.Unlock()
		return api.GuidanceReservation{}, &api.Error{Code: api.CodeDeadline}
	}
	if store.observerResult != nil {
		result := *store.observerResult
		result.ID, result.Target, result.Task, result.LogicalTurnID = "observed-result", store.r.Target, store.r.Task, store.r.LogicalTurnID
		result.PolicyGeneration, result.ReservationID, result.CandidateSnapshotID = store.r.PolicyGeneration, store.r.ID, store.r.CandidateSnapshotID
		store.r.Result, store.r.Status, store.r.Generation = &result, "completed", 2
	}
	if store.r.Status == "completed" {
		result := *store.r
		store.mu.Unlock()
		return result, nil
	}
	done := store.done
	store.mu.Unlock()
	select {
	case <-done:
		store.mu.Lock()
		defer store.mu.Unlock()
		return *store.r, nil
	case <-ctx.Done():
		return api.GuidanceReservation{}, contextError(ctx)
	}
}
func (store *claimStore) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	if err := contextError(ctx); err != nil {
		return api.Commit{}, err
	}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.transactions++
	store.lastTransaction = tx
	store.txs = append(store.txs, tx)
	if tx.Reply != nil {
		var result api.Guidance
		if err := api.DecodeObject(tx.Reply.Result, &result); err != nil {
			return api.Commit{}, err
		}
		operation := api.Operation{Status: "succeeded"}
		key := requestKey(tx.Scope)
		store.receipts[claimReceiptKey{tx.Scope.Config, tx.Scope.Actor, key}] = api.MutationReceipt{Config: tx.Scope.Config, Actor: tx.Scope.Actor,
			Key: key, PolicyGeneration: result.PolicyGeneration, Reply: tx.Reply, Operation: operation}
		return api.Commit{Reply: tx.Reply, Operation: operation}, nil
	}
	if store.r == nil || store.r.Status != "pending" || len(tx.Writes.Guidance) != 1 || len(tx.Writes.Turns) != 1 {
		return api.Commit{}, &api.Error{Code: api.CodeConflict}
	}
	if store.turn.Generation != store.r.TurnGeneration {
		return api.Commit{}, &api.Error{Code: api.CodeConflict}
	}
	selection := tx.Writes.Guidance[0]
	if tx.Guards[0].Cancellation.Epoch != store.lane.CancellationEpoch {
		return api.Commit{}, &api.Error{Code: api.CodeConflict}
	}
	if err := api.ValidateGuidanceCompletion(*store.r, selection, *tx.Internal, store.clock.Now()); err != nil {
		return api.Commit{}, err
	}
	store.r.Status, store.r.Generation, store.r.Acquired, store.r.Result = "completed", 2, false, &selection.Result
	store.turn = tx.Writes.Turns[0]
	store.commits++
	store.events += len(tx.Events)
	close(store.done)
	return api.Commit{Operation: api.Operation{ID: tx.Internal.CauseOperationID, Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
}

func claimFixture(t *testing.T) (*Service, *claimStore, *judgeProbe, api.Scope) {
	t.Helper()
	_, probe, _, scope := serviceFixture(t)
	policy, _ := probe.Policy(context.Background(), scope)
	clock := &fixedClock{value: testTime()}
	data := []byte("Review the complete guidance claim and retained policy inputs.\n")
	request := guidanceRequest()
	request.Task.Bytes, request.Task.SHA256 = int64(len(data)), digestBytes(data)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request.Protocol, scope.Request.Schema, scope.Request.Config, scope.Request.Params = api.Protocol, api.SchemaVersion, scope.Config, raw
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	store := &claimStore{request: request, taskData: data, lane: probe.lane, turn: api.TurnSnapshot{Target: request.Target, LogicalTurnID: request.LogicalTurnID, Task: request.Task, Generation: 1, PolicyGeneration: 3},
		policy: policy, policies: map[api.Generation]api.EffectivePolicy{3: policy}, clock: clock, done: make(chan struct{}), awaitEntered: make(chan struct{}, 4),
		receipts: make(map[claimReceiptKey]api.MutationReceipt), candidates: []api.DecisionCandidate{candidate("binding", testTime().Add(-time.Hour), true), candidate("history", testTime(), false)},
		grants: api.GrantSet{ID: "grants-a", LifeID: "life-demo", SHA256: digestBytes([]byte("fixture grants")), Generation: 1, PolicyGeneration: 3}}
	judge := &judgeProbe{fit: fixtureFit, evaluate: func(_ context.Context, request api.JudgeRequest) (api.JudgeReply, error) {
		if !bytes.Equal(request.Task, store.taskData) || request.Context.GrantSetID != store.grants.ID || request.Context.GrantsSHA256 != store.grants.SHA256 || request.Context.CWD != store.lane.Workspace.LogicalCWD {
			return api.JudgeReply{}, integrity("fresh judge lost actual task or grant context")
		}
		answers := []api.Judgment{}
		for _, item := range request.Decisions {
			answers = append(answers, answer(string(item.ID), .8))
		}
		reply := stageReply(request, answers...)
		reply.CostMicros = 2
		return reply, nil
	}}
	service, err := New(Dependencies{Store: store, Judge: judge, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, judge, scope
}

func TestFreshGuidanceClaim(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil || result.Status != "scored" || result.PolicyGeneration != 3 || len(result.JudgmentIDs) != 1 || len(result.Items) != 2 ||
		judge.evalCalls != 1 || store.commits != 1 || store.events != 1 || store.turn.GuidanceID != result.ID {
		t.Fatalf("fresh guidance did not complete one actual claim: %v", err)
	}
	tx := store.txs[0]
	if tx.Internal.Kind != api.InternalGuidanceComplete || tx.Internal.CauseOperationID != store.r.OwnerOperationID ||
		tx.Internal.CauseRequestID != store.r.OwnerRequestID || tx.Internal.RequestedBy != scope.Actor ||
		len(tx.Compare) != 1 || tx.Compare[0].Kind != api.CompareGuidance || tx.Compare[0].Generation != 1 ||
		len(tx.Guards) != 1 || tx.Guards[0].Cancellation.Epoch != store.r.CancellationEpoch {
		t.Fatal("completion lost its original cause or CAS/epoch fence")
	}
	before := store.candidateReads
	store.policy.Generation, scope.PolicyGeneration = 4, 4
	store.policy.SHA256 = digestBytes([]byte("D6 advanced fixture policy"))
	replay, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil || !reflect.DeepEqual(replay, result) || judge.evalCalls != 1 || store.candidateReads != before || len(store.reserveRequests) != 1 {
		t.Fatalf("D6 replay selected or reserved again: %v", err)
	}
	human, _ := humanScope()
	human.PolicyGeneration = 4
	human = scopeForGuidance(t, human, store.request)
	preview, err := service.GuidanceSelect(context.Background(), human, store.request)
	if err != nil || !reflect.DeepEqual(preview, result) || judge.evalCalls != 1 {
		t.Fatalf("human D6 preview changed retained selection: %v", err)
	}
}

func TestFreshPolicyGeneration(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	store.policy.Generation, scope.PolicyGeneration = 4, 4
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil || result.PolicyGeneration != 4 || store.reserveRequests[0].PolicyGeneration != 4 || store.refreshes != 1 || judge.lastScope.PolicyGeneration != 4 {
		t.Fatalf("fresh selection did not use current D6 policy: %v", err)
	}
	if store.reserveRequests[0].MaxCostMicros != store.lane.BudgetRemaining.SpendMicros || store.reserveRequests[0].MaxCostMicros <= 0 {
		t.Fatal("judge claim lost its authoritative positive budget")
	}
}

func TestClaimObserver(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	store.forceObserver = true
	baseline, err := rankSelection(testTime(), 0, store.candidates, scored(answer("history", .7)))
	if err != nil {
		t.Fatal(err)
	}
	store.observerResult = &baseline
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if len(store.awaitRequests) != 1 || judge.fitCalls != 0 || judge.evalCalls != 0 {
		t.Fatal("observed claim bypassed retained await or became an evaluator")
	}
	if err != nil || result.ID != "observed-result" || store.commits != 0 {
		t.Fatalf("claim observer failed to replay its awaited result: %v", err)
	}
}

func TestClaimOwnerMismatch(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	store.wrongOwner = true
	_, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if judge.fitCalls != 0 || judge.evalCalls != 0 || store.commits != 0 {
		t.Fatal("foreign attempt reached judge or completion")
	}
	assertCode(t, err, api.CodeIntegrity)
}

func TestClaimRecovery(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	interrupted := &api.Error{Code: api.CodeCancelled, Owner: "fixture", Message: "interrupted original evaluator"}
	judge.fit = func(context.Context, api.JudgeRequest) (api.TokenFit, error) { return api.TokenFit{}, interrupted }
	_, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != interrupted || store.r == nil || store.r.Status != "pending" {
		t.Fatal("interruption lost its original pending claim")
	}
	beforeFit, beforeEval := judge.fitCalls, judge.evalCalls
	store.clock.value = testTime().Add(6 * time.Second)
	scope.Request.RequestID, scope.Request.IdempotencyKey = "recovery-request", "recovery-key"
	result, err := service.RecoverGuidance(context.Background(), scope, store.request)
	if judge.fitCalls != beforeFit || judge.evalCalls != beforeEval {
		t.Fatal("interrupted recovery judged again")
	}
	if err != nil || result.Status != "unavailable" || result.WeightedScore != nil || len(result.JudgmentIDs) != 0 || result.Notice == "" ||
		result.AsOf != store.r.ReservedAt || !reflect.DeepEqual(result.Items, store.r.BindingItems) || store.commits != 1 || store.events != 1 {
		t.Fatalf("recovery did not retain one unavailable result: %v", err)
	}
	var internal *api.InternalIntent
	for _, tx := range store.txs {
		if tx.Internal != nil {
			internal = tx.Internal
		}
	}
	if internal == nil || internal.Kind != api.InternalGuidanceRecover || internal.CauseRequestID != store.r.OwnerRequestID || internal.CauseOperationID != store.r.OwnerOperationID {
		t.Fatal("recovery replaced the original cause")
	}
	again, err := service.RecoverGuidance(context.Background(), scope, store.request)
	if err != nil || !reflect.DeepEqual(again, result) || store.events != 1 || len(store.reserveRequests) != 1 {
		t.Fatalf("completed recovery was not immutable: %v", err)
	}
}

func TestClaimEpochCancellation(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	judge.fit = func(context.Context, api.JudgeRequest) (api.TokenFit, error) {
		return api.TokenFit{}, &api.Error{Code: api.CodeCancelled}
	}
	_, err := service.GuidanceSelect(context.Background(), scope, store.request)
	assertCode(t, err, api.CodeCancelled)
	store.clock.value = testTime().Add(6 * time.Second)
	store.lane.CancellationEpoch++
	_, err = service.RecoverGuidance(context.Background(), scope, store.request)
	assertCode(t, err, api.CodeForbidden)
	if store.commits != 0 || store.events != 0 || len(store.reserveRequests) != 1 || judge.evalCalls != 0 {
		t.Fatal("cancelled claim was revived or rejudged")
	}
}

func TestTwoClaimKeys(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseOwner := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseOwner)
	judge.evaluate = func(ctx context.Context, request api.JudgeRequest) (api.JudgeReply, error) {
		select {
		case entered <- struct{}{}:
		case <-ctx.Done():
			return api.JudgeReply{}, contextError(ctx)
		}
		select {
		case <-release:
			return stageReply(request, answer("history", .8)), nil
		case <-ctx.Done():
			return api.JudgeReply{}, contextError(ctx)
		}
	}
	type outcome struct {
		result api.Guidance
		err    error
	}
	out := make(chan outcome, 2)
	go func() {
		result, err := service.GuidanceSelect(context.Background(), scope, store.request)
		out <- outcome{result, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first claim did not reach its evaluator")
	}
	other := scope
	other.Request.RequestID, other.Request.IdempotencyKey = "request-b", "key-b"
	go func() {
		result, err := service.GuidanceSelect(context.Background(), other, store.request)
		out <- outcome{result, err}
	}()
	select {
	case <-store.awaitEntered:
	case premature := <-out:
		t.Fatalf("second key returned before pending completion: %v", premature.err)
	case <-time.After(2 * time.Second):
		t.Fatal("second claim key did not await the pending evaluator")
	}
	releaseOwner()
	first, second := <-out, <-out
	if first.err != nil || second.err != nil || !reflect.DeepEqual(first.result, second.result) || judge.evalCalls != 1 || store.commits != 1 || store.events != 1 || len(store.reserveRequests) != 1 {
		t.Fatalf("two keys did not share one evaluator and result: %v, %v", first.err, second.err)
	}
}

type clockFunc func() time.Time

func (clock clockFunc) Now() time.Time { return clock() }

func TestEmptyAfterRankingCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	judge := &judgeProbe{}
	service := stage(judge)
	service.deps.Clock = clockFunc(func() time.Time { cancel(); return testTime() })
	request := stageRequest()
	request.Decisions = request.Decisions[1:]
	result, err := service.evaluateBatches(ctx, stageScope(), request, stagePolicy())
	if err != nil || result.Status != "empty" || result.WeightedScore == nil || *result.WeightedScore != 0 || judge.fitCalls != 0 {
		t.Fatalf("known empty history became unavailable after ranking: %v", err)
	}
}

func TestInternalMethodContract(t *testing.T) {
	service, store, _, scope, request, retained := retainedFixture(t)
	scope.Request.Method = "lane.turn"
	_, err := service.GuidanceSelect(context.Background(), scope, request)
	assertCode(t, err, api.CodeForbidden)
	if store.laneCalls != 0 {
		t.Fatal("lifecycle method was silently relabelled as guidance")
	}
	scope.Request = api.Request{}
	result, err := service.GuidanceSelect(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(result, retained) || store.transactions != 0 {
		t.Fatalf("in-process empty-method replay failed: %v", err)
	}
}

func TestClaimEventBytes(t *testing.T) {
	service, store, _, scope := claimFixture(t)
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded api.Guidance
	if err := api.DecodeObject(store.txs[0].Events[0].Payload, &decoded); err != nil || !reflect.DeepEqual(decoded, result) {
		t.Fatalf("selection event did not contain its actual receipt: %v", err)
	}
}

func TestExactReceiptAfterD6(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil {
		t.Fatal(err)
	}
	store.policy.Generation, scope.PolicyGeneration = 4, 4
	store.policy.SHA256 = digestBytes([]byte("new fixture policy"))
	store.lane.LogicalTurnID, store.turn.LogicalTurnID = "next-turn", "next-turn"
	store.turn.Task.ID = "next-task"
	replay, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil || !reflect.DeepEqual(replay, result) || judge.evalCalls != 1 || len(store.reserveRequests) != 1 || store.events != 1 {
		t.Fatalf("exact receipt replay used fresh turn or policy preflight: %v", err)
	}
}

func TestRecoveryDoesNotReserve(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	_, err := service.RecoverGuidance(context.Background(), scope, store.request)
	if len(store.reserveRequests) != 0 || judge.fitCalls != 0 || judge.evalCalls != 0 {
		t.Fatal("recovery created a fresh evaluator")
	}
	assertCode(t, err, api.CodeNotFound)
}

func TestEarlyRecoveryRefused(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	judge.fit = func(context.Context, api.JudgeRequest) (api.TokenFit, error) {
		return api.TokenFit{}, &api.Error{Code: api.CodeCancelled}
	}
	_, err := service.GuidanceSelect(context.Background(), scope, store.request)
	assertCode(t, err, api.CodeCancelled)
	_, err = service.RecoverGuidance(context.Background(), scope, store.request)
	if store.commits != 0 || judge.fitCalls != 1 || judge.evalCalls != 0 {
		t.Fatal("early recovery completed or rejudged the pending claim")
	}
	assertCode(t, err, api.CodeIntegrity)
}

func TestClaimBudget(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	store.lane.BudgetRemaining.SpendMicros = 0
	_, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if len(store.reserveRequests) != 0 || judge.fitCalls != 0 {
		t.Fatal("exhausted budget reached claim or judge")
	}
	assertCode(t, err, api.CodeBudget)
}

func TestAwaitExpiryRecovery(t *testing.T) {
	service, store, judge, scope := claimFixture(t)
	store.forceObserver, store.expireAwait = true, true
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil || result.Status != "unavailable" || result.WeightedScore != nil || result.AsOf != store.r.ReservedAt ||
		store.commits != 1 || store.events != 1 || judge.fitCalls != 0 || judge.evalCalls != 0 {
		t.Fatalf("expired await did not recover the original claim without judging: %v", err)
	}
}

func TestClaimClockSnapshot(t *testing.T) {
	service, store, _, scope := claimFixture(t)
	store.advanceReserve = true
	result, err := service.GuidanceSelect(context.Background(), scope, store.request)
	if err != nil || result.AsOf != store.r.ReservedAt {
		t.Fatalf("claim ranking replaced its retained clock snapshot: %v", err)
	}
	if result.Items[1].AgeSeconds != 0 || result.Items[1].Weight != 1 {
		t.Fatal("claim clock wait changed retained ranking ages")
	}
}
