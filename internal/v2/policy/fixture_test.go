package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

// These fixtures are only unit-test ports. They are not production providers,
// caller authentication, calibration evidence, or a substitute for the E2E.
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

type testUpload struct {
	request api.BlobBeginRequest
	data    []byte
}

type testReceiptDomain struct {
	config         string
	kind           string
	principal      api.ID
	life           api.ID
	method         api.Method
	idempotencyKey api.ID
}

func testDomain(scope api.Scope, key api.RequestKey) testReceiptDomain {
	return testReceiptDomain{scope.Config, scope.Actor.Kind, scope.Actor.ID, scope.Actor.LifeID, key.Method, key.IdempotencyKey}
}

func testScopeKey(scope api.Scope) api.RequestKey {
	return api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
}

type testStore struct {
	api.StateStore
	policy          api.EffectivePolicy
	policyHistory   map[api.Generation]api.EffectivePolicy
	historyReads    []api.Generation
	historyErr      error
	advanceRequests []api.PolicyAdvanceRequest
	advanceErr      error
	alterAdvance    func(*api.PolicyAdvanceReceipt)
	policyEvents    []api.Event
	policyTx        api.Transaction
	lane            api.Lane
	launch          api.LaunchRecord
	grants          api.GrantSet
	org             api.OrgSnapshot
	orgRequests     []api.OrgSnapshotRequest
	turn            api.TurnSnapshot
	uploads         map[api.ID]*testUpload
	inputs          map[api.ID]*testUpload
	metadata        map[api.ID]api.ObjectMetadata
	receipts        map[testReceiptDomain]api.MutationReceipt
	proofs          map[api.ID]api.VerifiedHumanProof
	clock           *testClock
	lookups         int
	policyReads     int
	retentions      int
	lastRead        api.Scope
	targets         int
	proofUses       int
	lastTx          api.Transaction
	alterReceipt    func(*api.MutationReceipt)
	badTarget       bool
	events          []api.Event
	seq             api.Sequence
	transactErr     error
	policyErr       error
	retainErr       error
	sourceErr       error
	turnErr         error
	badRead         bool
	badMetadata     bool
	badReply        bool
	badTurn         bool
	badSource       bool
	onCommit        func()
	afterRetain     func()
	seenScopes      []api.Scope
}

func (s *testStore) Policy(_ context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	s.policyReads++
	s.lastRead = scope
	return copyPolicy(s.policy), s.policyErr
}

func (s *testStore) Lane(_ context.Context, _ api.Scope, target api.LifeRef) (api.Lane, error) {
	if target.LifeID != s.lane.LifeID || (target.Run != 0 && target.Run != s.lane.Run) {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound}
	}
	return s.lane, nil
}

func (s *testStore) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	if id != s.launch.ID {
		return api.LaunchRecord{}, &api.Error{Code: api.CodeNotFound}
	}
	return s.launch, nil
}

func (s *testStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	if id != s.grants.ID {
		return api.GrantSet{}, &api.Error{Code: api.CodeNotFound}
	}
	return s.grants, nil
}

func (s *testStore) Transact(_ context.Context, transaction api.Transaction) (api.Commit, error) {
	for _, guard := range transaction.Guards {
		if guard.Proof != nil {
			s.proofUses++
		}
	}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.Commit{}, err
	}
	domain := testDomain(transaction.Scope, testScopeKey(transaction.Scope))
	receipt, found := s.receipts[domain]
	if !found || !bytes.Equal(transaction.RawRequest, receipt.RawRequest) || transaction.Reply == nil {
		return api.Commit{}, integrity("fixture transaction lacks reserved exact request/reply")
	}
	if receipt.Reply != nil {
		return api.Commit{Reply: receipt.Reply, Operation: receipt.Operation,
			FirstSeq: receipt.FirstSeq, LastSeq: receipt.LastSeq, Replayed: true}, nil
	}
	if s.onCommit != nil {
		s.onCommit()
	}
	if s.transactErr != nil {
		return api.Commit{}, s.transactErr
	}
	for _, compare := range transaction.Compare {
		var want api.Generation
		switch compare.Kind {
		case api.CompareOrg:
			if compare.ID != s.org.Ref.OrgID {
				return api.Commit{}, integrity("fixture policy compare ID")
			}
			want = s.org.Ref.Generation
		case "lane":
			if compare.ID != s.lane.LifeID {
				return api.Commit{}, integrity("fixture life compare ID")
			}
			want = s.lane.Generation
		case "grants":
			if compare.ID != s.grants.ID {
				return api.Commit{}, integrity("fixture grant compare ID")
			}
			want = s.grants.Generation
		default:
			return api.Commit{}, invalid("fixture unknown compare kind")
		}
		if want != compare.Generation {
			return api.Commit{}, conflict("fixture generation changed")
		}
	}
	if len(transaction.Events) == 0 || len(transaction.Effects) != 0 {
		return api.Commit{}, invalid("fixture requires actual policy events")
	}
	if transaction.Scope.Actor.Kind == "human" {
		current, err := api.WithReadAuthority(context.Background(), transaction.Scope)
		if err != nil {
			return api.Commit{}, err
		}
		if transaction.Scope.ReadAuthority == nil || *current.ReadAuthority != *transaction.Scope.ReadAuthority || len(transaction.Guards) != 0 {
			return api.Commit{}, forbiddenTarget()
		}
	}
	first := s.seq + 1
	for _, event := range transaction.Events {
		if event.Kind != "policy.evaluated" || event.Actor != transaction.Scope.Actor || event.LifeID != s.lane.LifeID {
			return api.Commit{}, integrity("fixture event attribution mismatch")
		}
		var decision api.PolicyDecision
		if err := json.Unmarshal(event.Payload, &decision); err != nil || !decision.AuditComplete {
			return api.Commit{}, integrity("fixture event payload incomplete")
		}
		if !bytes.Equal(event.Payload, transaction.Reply.Result) || event.OperationID != receipt.Operation.ID {
			return api.Commit{}, integrity("fixture reply/event/operation mismatch")
		}
		if decision.PolicyGeneration != s.policy.Generation || decision.PolicyGeneration != transaction.Scope.PolicyGeneration {
			return api.Commit{}, conflict("fixture decision did not use current policy")
		}
		receipt.PolicyGeneration = decision.PolicyGeneration
		if _, found := s.uploads[decision.Input.ID]; !found {
			return api.Commit{}, integrity("fixture event refers to absent input")
		}
		s.seq++
		event.Seq = s.seq
		s.events = append(s.events, event)
	}
	receipt.Reply = &api.RPCReply{Result: append(json.RawMessage{}, transaction.Reply.Result...)}
	receipt.Operation.Status, receipt.Operation.FirstSeq, receipt.Operation.LastSeq = "succeeded", first, s.seq
	receipt.FirstSeq, receipt.LastSeq = first, s.seq
	s.receipts[domain] = receipt
	s.lastTx = transaction
	commit := api.Commit{Reply: receipt.Reply, Operation: receipt.Operation, FirstSeq: first, LastSeq: s.seq}
	if s.badReply {
		commit.Reply = nil
	}
	return commit, nil
}

func (s *testStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	s.lookups++
	if scope.Actor.Kind == "lane" && (s.launch.Revoked || s.grants.Revoked || scope.EndpointGeneration != s.launch.EndpointGeneration) {
		return api.MutationReceipt{}, forbiddenTarget()
	}
	receipt, found := s.receipts[testDomain(scope, key)]
	if !found {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound}
	}
	if receipt.Key != key || receipt.Actor != scope.Actor || receipt.Config != scope.Config {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeIdempotencyConflict}
	}
	if s.alterReceipt != nil {
		s.alterReceipt(&receipt)
	}
	return receipt, nil
}

func (s *testStore) AuthorizationTarget(_ context.Context, scope api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	s.targets++
	var body api.PolicyEvaluateRequest
	if request.Method != "policy.evaluate" || request.Config != scope.Config || api.DecodeObject(request.Params, &body) != nil ||
		body.Target.LifeID != s.lane.LifeID || body.Target.Run != s.lane.Run {
		return api.HumanChallengeRequest{}, forbiddenTarget()
	}
	target := api.HumanChallengeRequest{Method: request.Method, TargetID: s.lane.LifeID,
		RequestSHA256: request.RequestSHA256, BaseGeneration: s.lane.Generation}
	if s.badTarget {
		target.TargetID = "different-life"
	}
	return target, nil
}

func (s *testStore) OrgSnapshot(_ context.Context, scope api.Scope, request api.OrgSnapshotRequest) (api.OrgSnapshot, error) {
	s.orgRequests = append(s.orgRequests, request)
	if err := api.ValidateOrgSnapshotRequest(scope, request); err != nil {
		return api.OrgSnapshot{}, err
	}
	if request.Generation != s.org.Ref.Generation {
		return api.OrgSnapshot{}, conflict("fixture org snapshot changed")
	}
	// Deliberately return malformed projection facts to the consumer's existing
	// negative fixtures after enforcing the real request-selector contract.
	return s.org, nil
}

func (s *testStore) Source(_ context.Context, _ api.Scope, source api.SourceRef) (api.RetainedSource, error) {
	if s.sourceErr != nil {
		return api.RetainedSource{}, s.sourceErr
	}
	for _, file := range s.org.Sources {
		if file.Source == source {
			ref := file.Content
			if s.badSource {
				ref.ID = "other-source-object"
			}
			return api.RetainedSource{Source: source, Content: ref}, nil
		}
	}
	return api.RetainedSource{}, &api.Error{Code: api.CodeNotFound}
}

func (s *testStore) BriefingInput(_ context.Context, scope api.Scope, request api.BriefingInputRequest) (api.BriefingInput, error) {
	s.seenScopes = append(s.seenScopes, scope)
	s.lastRead = scope
	if s.policyErr != nil {
		return api.BriefingInput{}, s.policyErr
	}
	if request.LifeID == "" && request.Context == s.policy.Context {
		return api.BriefingInput{Policy: copyPolicy(s.policy)}, nil
	}
	if request.LifeID != s.lane.LifeID {
		return api.BriefingInput{}, &api.Error{Code: api.CodeNotFound}
	}
	lane := s.lane
	return api.BriefingInput{Lane: &lane, Policy: copyPolicy(s.policy)}, nil
}

func (s *testStore) Turn(_ context.Context, _ api.Scope, target api.LifeRef, turn api.ID) (api.TurnSnapshot, error) {
	if s.turnErr != nil {
		return api.TurnSnapshot{}, s.turnErr
	}
	if target != s.turn.Target || turn != s.turn.LogicalTurnID {
		return api.TurnSnapshot{}, &api.Error{Code: api.CodeNotFound}
	}
	result := s.turn
	if s.badTurn {
		result.Task.ID = "different-task"
	}
	return result, nil
}

func (s *testStore) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	upload, found := s.uploads[request.ObjectID]
	if !found {
		upload, found = s.inputs[request.ObjectID]
	}
	if !found || request.Offset < 0 || request.Offset > int64(len(upload.data)) || request.Limit <= 0 {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound}
	}
	end := min(int(request.Offset)+request.Limit, len(upload.data))
	data := append([]byte{}, upload.data[int(request.Offset):end]...)
	if s.badRead && len(data) > 0 {
		data[0] ^= 1
	}
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: digestBytes(data)}, nil
}

func (s *testStore) retain(_ context.Context, _ api.Scope, class string, data []byte) (api.BlobRef, error) {
	if len(data) == 0 || (class != "policy" && class != "judge_request") {
		return api.BlobRef{}, invalid("fixture invalid retained object")
	}
	id := api.ID(fmt.Sprintf("object-%d", len(s.uploads)+1))
	request := api.BlobBeginRequest{Class: class, Bytes: int64(len(data)), SHA256: digestBytes(data)}
	s.uploads[id] = &testUpload{request: request, data: append([]byte{}, data...)}
	return api.BlobRef{ID: id, SHA256: request.SHA256, Bytes: request.Bytes, Class: class}, nil
}

func (s *testStore) RetainObject(ctx context.Context, scope api.Scope, request api.RetainObjectRequest) (api.BlobRef, error) {
	s.retentions++
	if scope.Actor.Kind == "human" {
		verified, err := api.WithReadAuthority(ctx, scope)
		if err != nil {
			return api.BlobRef{}, err
		}
		if scope.ReadAuthority == nil || *scope.ReadAuthority != *verified.ReadAuthority {
			return api.BlobRef{}, forbiddenTarget()
		}
	}
	if s.retainErr != nil {
		return api.BlobRef{}, s.retainErr
	}
	intent, object := request.Intent, request.Object
	internalScope := scope
	internalScope.Request = api.Request{}
	if err := api.ValidateTransactionShape(api.Transaction{Scope: internalScope, Internal: &intent,
		Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
		return api.BlobRef{}, err
	}
	if intent.Kind != api.InternalObjectRetain || intent.Config != scope.Config || intent.RequestedBy != scope.Actor ||
		intent.Actor.Kind != "service" || intent.CauseRequestID != scope.Request.RequestID ||
		object.SHA256 != digestBytes(object.Bytes) || object.ACL.Config != scope.Config || object.ACL.Owner != scope.Actor {
		return api.BlobRef{}, integrity("fixture retention lost trusted intent or exact bytes")
	}
	if scope.Request.Method == "policy.evaluate" {
		receipt, found := s.receipts[testDomain(scope, testScopeKey(scope))]
		if !found || intent.CauseOperationID != receipt.Operation.ID || intent.Target != s.turn.Target || intent.LogicalTurnID != s.turn.LogicalTurnID {
			return api.BlobRef{}, integrity("fixture retention lost parent policy operation")
		}
	}
	if len(object.InputRefs) == 0 {
		return api.BlobRef{}, integrity("fixture retention lacks actual input references")
	}
	for _, ref := range object.InputRefs {
		input, found := s.inputs[ref.ID]
		if !found || ref.SHA256 != digestBytes(input.data) || ref.Bytes != int64(len(input.data)) || ref.Class != input.request.Class {
			return api.BlobRef{}, integrity("fixture retention refers to missing or changed input bytes")
		}
	}
	ref, err := s.retain(ctx, scope, object.Class, object.Bytes)
	if err != nil {
		return api.BlobRef{}, err
	}
	s.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, ACL: object.ACL, Origin: object.Origin, SourceOperationID: intent.CauseOperationID}
	if s.afterRetain != nil {
		s.afterRetain()
	}
	return ref, nil
}

func (s *testStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	metadata, found := s.metadata[id]
	if !found {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound}
	}
	if s.badMetadata {
		metadata.ACL.Config = "another-config"
	}
	return metadata, nil
}

func (s *testStore) installSources() {
	s.org.Sources = []api.ResourceFile{}
	for _, source := range s.policy.Sources {
		content := api.BlobRef{ID: api.ID("source-" + string(source.ID)), SHA256: source.SHA256, Bytes: int64(len(source.ID)), Class: "policy"}
		s.inputs[content.ID] = &testUpload{request: api.BlobBeginRequest{Class: content.Class,
			Bytes: content.Bytes, SHA256: content.SHA256}, data: []byte(source.ID)}
		s.org.Sources = append(s.org.Sources, api.ResourceFile{Source: source, Content: content,
			Mode: 0600, RevisionGeneration: source.Generation, Kind: "policy"})
	}
}

type testJudge struct {
	store       *testStore
	probability float64
	fitErr      error
	evalErr     error
	unproved    bool
	wait        bool
	alter       func(*api.JudgeReply)
	alterFit    func(*api.TokenFit)
	requests    []api.JudgeRequest
	fits        []api.JudgeRequest
	scopes      []api.Scope
}

func (j *testJudge) FitForScope(_ context.Context, scope api.Scope, request api.JudgeRequest) (api.TokenFit, error) {
	j.scopes = append(j.scopes, scope)
	if scope.Config != request.Context.Config {
		return api.TokenFit{}, forbiddenTarget()
	}
	if _, err := api.ResolveJudgeForScope(scope, request, j.store.policy); err != nil {
		return api.TokenFit{}, err
	}
	j.fits = append(j.fits, request)
	data, err := json.Marshal(request)
	if err != nil {
		return api.TokenFit{}, err
	}
	fit := api.TokenFit{Proved: !j.unproved, InputBytes: len(data), InputTokens: len(data),
		ContextTokens: request.Config.ContextTokens, TokenizerSHA256: request.Config.TokenizerSHA256}
	if j.alterFit != nil {
		j.alterFit(&fit)
	}
	return fit, j.fitErr
}

func (j *testJudge) EvaluateForScope(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.JudgeReply, error) {
	if scope.Config != request.Context.Config {
		return api.JudgeReply{}, forbiddenTarget()
	}
	if _, err := api.ResolveJudgeForScope(scope, request, j.store.policy); err != nil {
		return api.JudgeReply{}, err
	}
	j.requests = append(j.requests, request)
	if j.wait {
		<-ctx.Done()
		return api.JudgeReply{}, ctx.Err()
	}
	data, err := json.Marshal(request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	reply := api.JudgeReply{ID: request.ID, Status: "scored", Results: []api.Judgment{},
		SelectedModel: request.Config.Model, ReportedModel: request.Config.Model,
		DeploymentSHA256: request.Config.DeploymentSHA256, InputBytes: len(data), InputTokens: len(data), CostMicros: 1}
	for _, rule := range request.Rules {
		probability := j.probability
		reply.Results = append(reply.Results, api.Judgment{QuestionID: rule.ID, Status: "scored",
			Probability: &probability, Reason: "fixture membership proposition"})
	}
	if j.alter != nil {
		j.alter(&reply)
	}
	return reply, j.evalErr
}

type fixture struct {
	service *Service
	store   *testStore
	judge   *testJudge
	clock   *testClock
	scope   api.Scope
	request api.PolicyEvaluateRequest
}

func testSource(id string) api.SourceRef {
	return api.SourceRef{ID: api.ID(id), Path: "/org/" + id + ".toml", SHA256: digestBytes([]byte(id)), Generation: 1}
}

func testThreshold(match float64) api.Thresholds {
	return api.Thresholds{Match: match, UncertainLow: 0.4, UncertainHigh: 0.6, CalibrationID: "fixture-calibration"}
}

func sourceRule(id string) api.Rule {
	return api.Rule{ID: api.ID(id), Text: "Do not publish unreviewed output.", Instead: "Report to the publishing role.",
		Band: "refuse", Scope: api.RuleScope{Levels: []int{}, Roles: []string{}}}
}

func newFixture(t *testing.T, rules ...api.Rule) *fixture {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	role := api.RoleContext{Level: 3, Role: "executor", InstanceID: "instance-a"}
	policy, err := Resolve(1, role, []Layer{{Source: testSource("org"), Thresholds: testThreshold(0.85), Rules: rules}},
		DefaultJudgeConfig(digestBytes([]byte("deployment")), digestBytes([]byte("tokenizer")), 32768), 14*24*60*60)
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: "fixture", Actor: api.Actor{Kind: "lane", ID: "actor-a", LifeID: "life-a", Level: 3, Role: "executor"},
		LaunchID: "launch-a", EndpointGeneration: 1, PolicyGeneration: 1,
		Request: api.Request{RequestID: "request-a", IdempotencyKey: "key-a", Method: "policy.evaluate"}}
	lane := api.Lane{LifeID: "life-a", RootLifeID: "life-a", Name: "fixture", Level: 3, Role: "executor", Run: 1, State: "running", CancellationEpoch: 1,
		Task: api.BlobRef{ID: "task-a", SHA256: digestBytes([]byte("retained task")), Bytes: 13, Class: "brief"}, LaunchID: scope.LaunchID,
		LogicalTurnID: "turn-a", Generation: 1, GrantSetID: "grants-a", PolicyGeneration: 1,
		StarterChain: []api.ID{}, BudgetRemaining: api.Budget{SpendMicros: 10000}}
	store := &testStore{policy: policy, lane: lane, uploads: map[api.ID]*testUpload{}, inputs: map[api.ID]*testUpload{},
		policyHistory: map[api.Generation]api.EffectivePolicy{policy.Generation: copyPolicy(policy)},
		metadata:      map[api.ID]api.ObjectMetadata{}, receipts: map[testReceiptDomain]api.MutationReceipt{},
		proofs: map[api.ID]api.VerifiedHumanProof{}, clock: clock,
		org: api.OrgSnapshot{Config: scope.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(scope.Config), Generation: 1, ManifestSHA256: digestBytes([]byte("org-manifest"))},
			Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}},
		turn: api.TurnSnapshot{Target: api.LifeRef{LifeID: lane.LifeID, Run: 1}, LogicalTurnID: lane.LogicalTurnID, Task: lane.Task, Generation: 1},
		launch: api.LaunchRecord{ID: scope.LaunchID, Config: scope.Config, Target: api.LifeRef{LifeID: lane.LifeID, Run: 1},
			Actor: scope.Actor, GrantSetID: lane.GrantSetID, EndpointGeneration: 1, PolicyGeneration: 1},
		grants: api.GrantSet{ID: lane.GrantSetID, LifeID: lane.LifeID, Generation: 1, PolicyGeneration: 1, SHA256: digestBytes([]byte("grants")),
			ExpiresAt: api.Timestamp(clock.now.Add(time.Hour).Format(time.RFC3339Nano))}}
	judge := &testJudge{store: store}
	store.inputs[lane.Task.ID] = &testUpload{request: api.BlobBeginRequest{Class: lane.Task.Class,
		Bytes: lane.Task.Bytes, SHA256: lane.Task.SHA256}, data: []byte("retained task")}
	store.installSources()
	service, err := New(Dependencies{Store: store, Judge: judge, Clock: clock,
		MaxCostMicros: 10000,
		ValidateSources: func(_ context.Context, _ api.Scope, request api.OrgValidateRequest) (api.OrgValidation, error) {
			if request.Generation != store.org.Ref.Generation {
				return api.OrgValidation{}, conflict("fixture source generation changed")
			}
			if err := validatePolicy(store.policy); err != nil {
				return api.OrgValidation{Valid: false, Problems: []string{err.Error()}}, nil
			}
			return api.OrgValidation{Valid: true, Problems: []string{}}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	command := []byte("unfamiliar-public-reader --version")
	return &fixture{service: service, store: store, judge: judge, clock: clock, scope: scope,
		request: api.PolicyEvaluateRequest{Target: store.launch.Target, LogicalTurnID: lane.LogicalTurnID,
			Command: api.CommandData{Tool: "shell", Command: command, Argv: []string{}, DeclaredPaths: []string{},
				CWD: "/work/main", RawSHA256: digestBytes(command)}}}
}

func (f *fixture) evaluate(t *testing.T) api.PolicyDecision {
	t.Helper()
	result, err := f.evaluateOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.AuditComplete || result.ID == "" || result.Input.ID == "" {
		t.Fatalf("incomplete policy result: %+v", result)
	}
	return result
}

type testFrame []byte

func (f testFrame) Bytes() []byte { return append([]byte{}, f...) }
func (testFrame) Verify(context.Context, api.ConnectionContext) error {
	return api.NotImplemented("fixture", "real transport frame authentication")
}

func (f *fixture) prepare() error {
	params, err := json.Marshal(f.request)
	if err != nil {
		return err
	}
	key, err := client.NewRequestID()
	if err != nil {
		return err
	}
	// Each evaluateOnce models a new intended operation. Replay tests reuse
	// the retained envelope/key directly instead of entering this helper.
	request, err := client.PrepareRequest(api.Request{Config: f.scope.Config, Method: "policy.evaluate",
		IdempotencyKey: key, Params: append(append([]byte(" \n"), params...), '\n')})
	if err != nil {
		return err
	}
	f.scope.Request = request
	if f.scope.Actor.Kind == "human" {
		if f.scope.Connection == nil {
			connection, err := newReadConnection(f.scope, f.clock)
			if err != nil {
				return err
			}
			f.scope.Connection = connection
		}
		verified, err := api.WithReadAuthority(context.Background(), f.scope)
		if err != nil {
			return err
		}
		f.scope = verified
	}
	raw, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return err
	}
	f.scope.Request = request
	f.scope.Frame = testFrame(raw)
	f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))] = api.MutationReceipt{
		Config: f.scope.Config,
		Key:    api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256},
		Actor:  f.scope.Actor, Operation: api.Operation{ID: api.ID(fmt.Sprintf("operation-%d", len(f.store.receipts)+1)), Status: "running"},
		RawRequest: append([]byte{}, raw...)}
	return nil
}

func (f *fixture) evaluateOnce(ctx context.Context) (api.PolicyDecision, error) {
	if err := f.prepare(); err != nil {
		return api.PolicyDecision{}, err
	}
	return f.service.PolicyEvaluate(ctx, f.scope, f.request)
}

func (f *fixture) seal(t *testing.T) {
	t.Helper()
	var err error
	f.store.policy.SHA256, err = policyDigest(f.store.policy)
	if err != nil {
		t.Fatal(err)
	}
	f.store.installSources()
	if _, exists := f.store.policyHistory[f.store.policy.Generation]; !exists {
		f.store.policyHistory[f.store.policy.Generation] = copyPolicy(f.store.policy)
	}
}

func wantCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	typed, ok := err.(*api.Error)
	if !ok || typed.Code != code {
		t.Fatalf("want %s; got %v", code, err)
	}
}
