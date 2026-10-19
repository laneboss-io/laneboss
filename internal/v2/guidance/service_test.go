package guidance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type storeProbe struct {
	api.StateStore
	lane             api.Lane
	laneErr          error
	policyErr        error
	policy           *api.EffectivePolicy
	laneCalls        int
	policyCalls      int
	transactions     int
	scope            api.Scope
	target           api.LifeRef
	turn             *api.TurnSnapshot
	reservation      *api.GuidanceReservation
	reservationErr   error
	pages            func(api.DecisionQuery) (api.DecisionPage, error)
	data             []byte
	metadata         *api.ObjectMetadata
	decisions        map[api.ID]api.DecisionProjection
	decisionCalls    int
	sourceCalls      int
	reservationCalls int
	candidateCalls   int
	objectCalls      int
	blobCalls        int
	reserveCalls     int
	awaitCalls       int
	lastTransaction  api.Transaction
}

func (store *storeProbe) Lane(_ context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	store.laneCalls++
	store.scope, store.target = scope, target
	return store.lane, store.laneErr
}

func (store *storeProbe) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	store.policyCalls++
	if store.policy != nil {
		return *store.policy, store.policyErr
	}
	return api.EffectivePolicy{Generation: 3, SHA256: digestBytes([]byte("fixture policy")), Judge: stageRequest().Config, Context: stageRequest().Context.Role, GuidanceMinRelevance: .5}, store.policyErr
}

func (store *storeProbe) PolicyAt(_ context.Context, _ api.Scope, generation api.Generation) (api.EffectivePolicy, error) {
	return api.EffectivePolicy{Generation: generation, SHA256: digestBytes([]byte("retained fixture policy"))}, nil
}

func (store *storeProbe) LookupReceipt(context.Context, api.Scope, api.RequestKey) (api.MutationReceipt, error) {
	return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound}
}

func (store *storeProbe) ReserveGuidance(context.Context, api.Scope, api.GuidanceReservationRequest) (api.GuidanceReservation, error) {
	store.reserveCalls++
	return api.GuidanceReservation{}, api.NotImplemented("lb-v2-service", "store.ReserveGuidance")
}

func (store *storeProbe) AwaitGuidance(context.Context, api.Scope, api.GuidanceAwaitRequest) (api.GuidanceReservation, error) {
	store.awaitCalls++
	return api.GuidanceReservation{}, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-guidance", Retryable: true,
		Message: "logical-turn guidance is reserved but has no completed result"}
}

func (store *storeProbe) Decision(_ context.Context, _ api.Scope, id api.ID) (api.DecisionProjection, error) {
	store.decisionCalls++
	projection, exists := store.decisions[id]
	if !exists {
		return api.DecisionProjection{}, &api.Error{Code: api.CodeNotFound}
	}
	return projection, nil
}

func (store *storeProbe) Transact(_ context.Context, transaction api.Transaction) (api.Commit, error) {
	store.transactions++
	store.lastTransaction = transaction
	if transaction.Reply != nil {
		return api.Commit{Reply: transaction.Reply, Operation: api.Operation{Status: "succeeded"}}, nil
	}
	return api.Commit{}, api.NotImplemented("unit-fixture", "unexpected Transact")
}

func (store *storeProbe) Turn(_ context.Context, _ api.Scope, target api.LifeRef, turn api.ID) (api.TurnSnapshot, error) {
	if store.turn != nil {
		return *store.turn, nil
	}
	return api.TurnSnapshot{Target: target, LogicalTurnID: turn, Task: guidanceRequest().Task,
		Generation: 1, PolicyGeneration: 3}, nil
}

func (store *storeProbe) GuidanceReservation(context.Context, api.Scope, api.LifeRef, api.ID) (api.GuidanceReservation, error) {
	store.reservationCalls++
	if store.reservationErr != nil {
		return api.GuidanceReservation{}, store.reservationErr
	}
	if store.reservation != nil {
		return *store.reservation, nil
	}
	return api.GuidanceReservation{}, &api.Error{Code: api.CodeNotFound, Message: "fixture has no reservation"}
}

func (store *storeProbe) DecisionCandidates(_ context.Context, _ api.Scope, request api.DecisionQuery) (api.DecisionPage, error) {
	store.candidateCalls++
	if store.pages != nil {
		return store.pages(request)
	}
	return api.DecisionPage{SnapshotID: "snapshot-a", PolicyGeneration: 3,
		AsOf: api.Timestamp(testTime().Format(time.RFC3339Nano)), Candidates: []api.DecisionCandidate{}, Complete: true}, nil
}

func (store *storeProbe) ObjectMetadata(context.Context, api.Scope, api.ID) (api.ObjectMetadata, error) {
	store.objectCalls++
	if store.metadata != nil {
		return *store.metadata, nil
	}
	return api.ObjectMetadata{Ref: guidanceRequest().Task}, nil
}

func (store *storeProbe) Source(_ context.Context, _ api.Scope, source api.SourceRef) (api.RetainedSource, error) {
	store.sourceCalls++
	return api.RetainedSource{Source: source, Content: api.BlobRef{
		ID: source.ID, SHA256: source.SHA256, Class: "record", Bytes: 1,
	}}, nil
}

func (store *storeProbe) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	store.blobCalls++
	if request.Offset > int64(len(store.data)) {
		return api.BlobChunk{}, integrity("fixture offset exceeds actual object")
	}
	end := min(int64(len(store.data)), request.Offset+int64(request.Limit))
	data := store.data[request.Offset:end]
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: digestBytes(data)}, nil
}

type registryProbe struct {
	handlers map[api.Method]api.Handler
	err      error
}

func (registry *registryProbe) Register(method api.Method, handler api.Handler) error {
	if registry.err != nil {
		return registry.err
	}
	if registry.handlers == nil {
		registry.handlers = make(map[api.Method]api.Handler)
	}
	if _, exists := registry.handlers[method]; exists {
		return errors.New("duplicate fixture handler")
	}
	registry.handlers[method] = handler
	return nil
}

func (*registryProbe) RegisterStream(api.Method, api.StreamHandler) error {
	return errors.New("guidance must not register a stream")
}

func guidanceRequest() api.GuidanceRequest {
	return api.GuidanceRequest{
		Target: api.LifeRef{LifeID: "life-demo", Run: 1}, LogicalTurnID: "turn-a",
		Task: api.BlobRef{ID: "task-a", SHA256: digestBytes(nil), Bytes: 0, Class: "task"},
	}
}

func serviceFixture(t *testing.T) (*Service, *storeProbe, *judgeProbe, api.Scope) {
	t.Helper()
	store := &storeProbe{lane: api.Lane{LifeID: "life-demo", Run: 1, LogicalTurnID: "turn-a", PolicyGeneration: 3,
		Generation: 1, CancellationEpoch: 1, GrantSetID: "grants-a", State: "running", BudgetRemaining: api.Budget{SpendMicros: 100}, Workspace: api.Workspace{LogicalCWD: "/workspace"}}}
	judge := &judgeProbe{}
	service, err := New(Dependencies{Store: store, Judge: judge, Clock: &fixedClock{value: testTime()}})
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{
		Config: "example", PolicyGeneration: 3, Actor: api.Actor{Kind: "lane", ID: "actor-demo", LifeID: "life-demo", Level: 3, Role: "reviewer"},
		Request: api.Request{Method: "guidance.select", RequestID: "request-a", IdempotencyKey: "key-a", RequestSHA256: digestBytes([]byte("fixture request"))},
	}
	return service, store, judge, scope
}

func TestNewRequiresDependencies(t *testing.T) {
	var absentStore *storeProbe
	var absentJudge *judgeProbe
	var absentClock *fixedClock
	for _, deps := range []Dependencies{
		{}, {Store: &storeProbe{}}, {Store: &storeProbe{}, Judge: &judgeProbe{}},
		{Store: absentStore, Judge: &judgeProbe{}, Clock: &fixedClock{}},
		{Store: &storeProbe{}, Judge: absentJudge, Clock: &fixedClock{}},
		{Store: &storeProbe{}, Judge: &judgeProbe{}, Clock: absentClock},
	} {
		service, err := New(deps)
		assertCode(t, err, api.CodePrerequisite)
		if service != nil {
			t.Fatal("missing dependency installed a fallback service")
		}
	}
}

func TestRegisterFrozenMethod(t *testing.T) {
	service, store, judge, scope := serviceFixture(t)
	registry := &registryProbe{}
	if err := service.Register(registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.handlers) != 1 || registry.handlers["guidance.select"] == nil {
		t.Fatal("guidance did not register exactly its frozen method")
	}
	raw, err := json.Marshal(guidanceRequest())
	if err != nil {
		t.Fatal(err)
	}
	response, err := registry.handlers["guidance.select"](context.Background(), scope, raw)
	assertCode(t, err, api.CodeNotImplemented)
	if len(response) != 0 || store.transactions != 0 || judge.fitCalls != 0 || judge.evalCalls != 0 {
		t.Fatal("missing authoritative contract produced a receipt, transaction or inference")
	}
	if !reflect.DeepEqual(store.scope, scope) || store.target != guidanceRequest().Target {
		t.Fatal("request widened or changed the authenticated store scope")
	}
	failure := errors.New("fixture registration failed")
	if err := service.Register(&registryProbe{err: failure}); err != failure {
		t.Fatal("registry failure was swallowed")
	}
	assertCode(t, service.Register(nil), api.CodeInvalid)
}

func TestSelectContractIsUnavailable(t *testing.T) {
	service, store, judge, scope := serviceFixture(t)
	result, err := service.GuidanceSelect(context.Background(), scope, guidanceRequest())
	assertCode(t, err, api.CodeNotImplemented)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-service" || typed.Message != "store.ReserveGuidance is not implemented" || result.ID != "" || result.WeightedScore != nil ||
		store.laneCalls != 1 || store.policyCalls != 1 || store.transactions != 0 || judge.evalCalls != 0 ||
		store.reserveCalls != 1 || store.candidateCalls != 2 || store.objectCalls != 1 || store.blobCalls != 1 {
		t.Fatal("reserve dependency failure was hidden behind success or skipped authoritative inputs")
	}
}

func TestSelectRejectsStaleTurn(t *testing.T) {
	changes := map[string]func(*storeProbe){
		"life":    func(store *storeProbe) { store.lane.LifeID = "other-life" },
		"run":     func(store *storeProbe) { store.lane.Run++ },
		"turn":    func(store *storeProbe) { store.lane.LogicalTurnID = "other-turn" },
		"cleaned": func(store *storeProbe) { store.lane.Cleaned = true },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			service, store, judge, scope := serviceFixture(t)
			change(store)
			_, err := service.GuidanceSelect(context.Background(), scope, guidanceRequest())
			assertCode(t, err, api.CodeConflict)
			if store.policyCalls != 0 || store.transactions != 0 || judge.fitCalls != 0 {
				t.Fatal("stale turn continued into policy, inference or persistence")
			}
		})
	}
}

func TestSelectPropagatesStoreError(t *testing.T) {
	for _, atPolicy := range []bool{false, true} {
		service, store, _, scope := serviceFixture(t)
		failure := api.NotImplemented("lb-v2-service", "fixture projection")
		if atPolicy {
			store.policyErr = failure
		} else {
			store.laneErr = failure
		}
		_, err := service.GuidanceSelect(context.Background(), scope, guidanceRequest())
		if err != failure {
			t.Fatal("store dependency error was replaced or swallowed")
		}
	}
}

func TestSelectChecksScopeAndContext(t *testing.T) {
	service, store, _, scope := serviceFixture(t)
	_, err := service.GuidanceSelect(context.Background(), api.Scope{}, guidanceRequest())
	assertCode(t, err, api.CodeUnauthenticated)
	request := guidanceRequest()
	request.Target.Run = 0
	_, err = service.GuidanceSelect(context.Background(), scope, request)
	assertCode(t, err, api.CodeInvalid)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = service.GuidanceSelect(cancelled, scope, guidanceRequest())
	assertCode(t, err, api.CodeCancelled)
	expired, end := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer end()
	_, err = service.GuidanceSelect(expired, scope, guidanceRequest())
	assertCode(t, err, api.CodeDeadline)
	if store.laneCalls != 0 || store.policyCalls != 0 {
		t.Fatal("invalid or interrupted request queried the store")
	}
}

func TestRequestShape(t *testing.T) {
	request := guidanceRequest()
	valid, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRequest(append([]byte(" \n"), valid...))
	if err != nil || !reflect.DeepEqual(decoded, request) {
		t.Fatalf("complete file request including zero-byte task was rejected: %v", err)
	}
	changes := map[string][]byte{
		"empty":       []byte(`{}`),
		"null":        []byte(`null`),
		"array":       []byte(`[]`),
		"trailing":    append(append([]byte{}, valid...), []byte(` {}`)...),
		"unknown":     []byte(strings.Replace(string(valid), `"run":1`, `"run":1,"extra":1`, 1)),
		"duplicate":   []byte(strings.Replace(string(valid), `"run":1`, `"run":1,"run":1`, 1)),
		"escaped-key": []byte(strings.Replace(string(valid), `"run":1`, `"run":1,"r\u0075n":1`, 1)),
		"missing":     []byte(strings.Replace(string(valid), `"bytes":0,`, ``, 1)),
		"nested-null": []byte(strings.Replace(string(valid), `"bytes":0`, `"bytes":null`, 1)),
		"fraction":    []byte(strings.Replace(string(valid), `"run":1`, `"run":1.0`, 1)),
		"large-run":   []byte(strings.Replace(string(valid), `"run":1`, `"run":9007199254740992`, 1)),
		"large-task":  []byte(strings.Replace(string(valid), `"bytes":0`, `"bytes":67108865`, 1)),
		"negative":    []byte(strings.Replace(string(valid), `"bytes":0`, `"bytes":-1`, 1)),
		"class":       []byte(strings.Replace(string(valid), `"class":"task"`, `"class":"policy"`, 1)),
		"unpaired":    []byte(strings.Replace(string(valid), `"turn-a"`, `"\ud800"`, 1)),
		"UTF8":        append([]byte{0xff}, valid...),
		"oversize":    []byte(strings.Repeat(" ", api.MaxFrameBytes+1)),
	}
	for name, raw := range changes {
		t.Run(name, func(t *testing.T) {
			_, err := decodeRequest(raw)
			assertCode(t, err, api.CodeInvalid)
		})
	}
}
