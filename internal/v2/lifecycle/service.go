// Package lifecycle implements the service-owned lane lifecycle.
package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const owner = "lb-v2-lifecycle"
const maxInteger = uint64(1<<53 - 1)

type Dependencies struct {
	Store              api.StateStore
	Identity           api.Authenticator
	Grants             api.GrantResolver
	Launcher           api.Launcher
	Sources            api.LaunchSourceResolver
	Capture            api.CaptureControl
	Delivery           api.MailDelivery
	Claudock           api.Runner
	Codex              api.Runner
	Credentials        api.CredentialBroker
	CredentialIdentity api.CredentialProjectionIdentity
	Guidance           api.GuidanceAPI
	Templates          api.TemplatesAPI
	Blobs              api.ServiceAPI
	Worker             api.DataWorker
	Review             api.ReviewVerifier
	ReviewControl      ReviewControl
	Archives           ArchiveControl
	Collector          OwnedCollector
	Input              InputControl
	Dispatch           MutationDispatch
	Clock              api.Clock
}

type lifeGate struct {
	token chan struct{}
	refs  int
}

type Service struct {
	deps           Dependencies
	mu             sync.Mutex
	gates          map[api.ID]*lifeGate
	changed        chan struct{}
	watchdog       api.Watchdog
	attachKey      [32]byte
	attachKeyReady bool
}

var _ api.LifecycleAPI = (*Service)(nil)
var _ api.Continuation = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func New(deps Dependencies) (*Service, error) {
	if absent(deps.Store) || absent(deps.Identity) || absent(deps.Clock) {
		return nil, problem(api.CodePrerequisite,
			"lifecycle requires store, identity and clock",
			"Wire the service-owned dependencies before registering lifecycle.")
	}
	if absent(deps.ReviewControl) {
		if control, ok := deps.Store.(ReviewControl); ok {
			deps.ReviewControl = control
		}
	}
	if absent(deps.CredentialIdentity) {
		deps.CredentialIdentity, _ = deps.Identity.(api.CredentialProjectionIdentity)
	}
	return &Service{deps: deps, gates: make(map[api.ID]*lifeGate),
		changed: make(chan struct{})}, nil
}

func absent(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func problem(code api.ErrorCode, message, instead string) *api.Error {
	result := &api.Error{Code: code, Message: message, Instead: instead, Owner: owner}
	if code == api.CodeUnauthenticated {
		return api.WithErrorComponent(result, "lifecycle_authorize")
	}
	return result
}

func invalid(message string) *api.Error {
	return problem(api.CodeInvalid, message, "Correct the retained request file.")
}

func integrity(message string) *api.Error {
	return problem(api.CodeIntegrity, message,
		"Preserve the evidence and repair the service dependency.")
}

func failure(err error) error {
	if err == nil {
		return nil
	}
	var typed *api.Error
	if errors.As(err, &typed) && typed != nil {
		return typed
	}
	if errors.Is(err, context.Canceled) {
		return problem(api.CodeCancelled, "lifecycle request cancelled",
			"Inspect the durable receipt before retrying the same request.")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return problem(api.CodeDeadline, "lifecycle deadline exceeded",
			"Resume from the last authorized cursor or inspect the operation.")
	}
	return integrity("lifecycle dependency failed")
}

func (s *Service) ready() error {
	if s == nil || absent(s.deps.Store) && absent(s.deps.Identity) && absent(s.deps.Clock) {
		return api.NotImplemented(owner, "initialized lifecycle service")
	}
	if absent(s.deps.Store) {
		return api.NotImplemented("lb-v2-service", "lifecycle state store")
	}
	if absent(s.deps.Identity) {
		return api.NotImplemented("lb-v2-identity", "lifecycle authenticator")
	}
	if absent(s.deps.Clock) {
		return problem(api.CodePrerequisite, "lifecycle clock is unavailable", "Supply the service clock.")
	}
	s.mu.Lock()
	if s.gates == nil {
		s.gates = make(map[api.ID]*lifeGate)
	}
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
	s.mu.Unlock()
	return nil
}

func contextReady(ctx context.Context) error {
	if absent(ctx) {
		return invalid("context required")
	}
	return failure(ctx.Err())
}

func validID(id api.ID) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validDigest(digest api.Digest) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	for _, c := range []byte(digest) {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func validTarget(target api.LifeRef) bool {
	return validID(target.LifeID) && target.Run > 0 &&
		uint64(target.Run) <= maxInteger
}

func validCounters(lane api.Lane) bool {
	return uint64(lane.CancellationEpoch) <= maxInteger &&
		lane.Counters.Failures <= maxInteger &&
		lane.Counters.Retries <= maxInteger
}

func validBlob(ref api.BlobRef) bool {
	return validID(ref.ID) && validDigest(ref.SHA256) &&
		ref.Bytes >= 0 && ref.Bytes <= api.MaxObjectBytes && ref.Class != ""
}

func newID() (api.ID, error) {
	var data [16]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		return "", integrity("service ID generation failed")
	}
	return api.ID(hex.EncodeToString(data[:])), nil
}

func validTime(value api.Timestamp) bool {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && strings.HasSuffix(string(value), "Z") &&
		parsed.Location() == time.UTC
}

func sameJSON(first, second []byte) bool {
	var a, b any
	left := json.NewDecoder(bytes.NewReader(first))
	left.UseNumber()
	right := json.NewDecoder(bytes.NewReader(second))
	right.UseNumber()
	return left.Decode(&a) == nil && right.Decode(&b) == nil &&
		reflect.DeepEqual(a, b)
}

// authorize retains dispatcher metadata, rather than rebuilding a request
// with a caller-selected actor, source, key or proof.
func (s *Service) authorize(ctx context.Context, scope api.Scope,
	method api.Method, params any) error {
	if err := s.ready(); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	request := scope.Request
	if scope.Config == "" || request.Config != scope.Config ||
		request.Method != method || request.Protocol != api.Protocol ||
		request.Schema != api.SchemaVersion || !validID(request.RequestID) ||
		len(request.RequestID) < 22 || !validID(request.IdempotencyKey) ||
		len(request.IdempotencyKey) < 22 || !validDigest(request.RequestSHA256) {
		return problem(api.CodeUnauthenticated, "missing authenticated request metadata",
			"Use the authenticated dispatcher with its original request envelope.")
	}
	if scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" &&
		scope.Actor.Kind != "scheduler" && scope.Actor.Kind != "watchdog" &&
		scope.Actor.Kind != "service" && scope.Actor.Kind != "worker" {
		return problem(api.CodeUnauthenticated, "unknown authenticated principal",
			"Use the installed service endpoint.")
	}
	if !validID(scope.Actor.ID) || scope.Actor.Kind == "lane" &&
		(!validID(scope.Actor.LifeID) || scope.Actor.Level < 3 || scope.Actor.Level > 6) {
		return problem(api.CodeUnauthenticated, "invalid authenticated principal",
			"Reauthenticate through the installed endpoint.")
	}
	shape := reflect.New(reflect.TypeOf(params)).Interface()
	if decode(request.Params, shape) != nil || !reflect.DeepEqual(reflect.ValueOf(shape).Elem().Interface(), params) {
		return integrity("request metadata does not match lifecycle input")
	}
	if err := validateInput(method, params); err != nil {
		return err
	}
	if request.Proof != nil && scope.Actor.Kind != "human" {
		return problem(api.CodeForbidden, "lane or worker requests cannot carry a human proof",
			"Use the authentic endpoint without borrowing human authority.")
	}
	if request.Proof != nil && (!validID(request.Proof.ID) || request.Proof.RequestSHA256 != request.RequestSHA256) {
		return invalid("operation proof is not bound to this lifecycle request")
	}
	if api.Methods[method].Mutation {
		digest, err := api.RequestDigest(request)
		if err != nil || digest != request.RequestSHA256 {
			return invalid("lifecycle mutation digest does not match its request")
		}
		if scope.Actor.Kind == "human" && api.Methods[method].Access != "spawn" && request.Proof == nil {
			return problem(api.CodeForbidden, "human lifecycle mutation needs its exact proof",
				"Confirm this operation and retain its request and idempotency key.")
		}
	}
	if err := s.deps.Identity.Authorize(ctx, scope, request); err != nil {
		return failure(err)
	}
	if api.Methods[method].Mutation {
		// Await another executor before taking a life gate. Otherwise a retry
		// arriving first could hold the gate needed by its original owner.
		if _, _, err := s.lookupReply(ctx, scope); err != nil {
			return err
		}
	}
	return nil
}

func treeVisible(scope api.Scope, lane api.Lane) bool {
	if scope.Actor.Kind == "human" || scope.Actor.Kind == "service" ||
		scope.Actor.Kind == "watchdog" ||
		scope.Actor.Kind == "scheduler" {
		// Internal principals still pass Authenticator and Store object ACLs.
		return true
	}
	if scope.Actor.Kind != "lane" && scope.Actor.Kind != "worker" {
		return false
	}
	if scope.Actor.LifeID == lane.LifeID {
		return true
	}
	for _, ancestor := range lane.StarterChain {
		if ancestor == scope.Actor.LifeID {
			return true
		}
	}
	return false
}

func (s *Service) lane(ctx context.Context, scope api.Scope,
	target api.LifeRef, current bool) (api.Lane, error) {
	if !validTarget(target) {
		return api.Lane{}, invalid("explicit life and run required")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, target)
	if err != nil {
		return api.Lane{}, failure(err)
	}
	if lane.LifeID != target.LifeID || !treeVisible(scope, lane) {
		return api.Lane{}, problem(api.CodeNotFound, "life is not visible",
			"Select your own life or an authentic starter descendant.")
	}
	if lane.Run < target.Run || current && lane.Run != target.Run {
		return api.Lane{}, problem(api.CodeConflict, "run is not current",
			"Read the authorized current life and retain its run and generation.")
	}
	if !validID(lane.RootLifeID) || lane.Generation == 0 || lane.Run == 0 ||
		uint64(lane.Generation) > maxInteger || uint64(lane.Run) > maxInteger ||
		lane.StarterChain == nil || !validAncestry(lane) || !validCounters(lane) {
		return api.Lane{}, integrity("invalid service lifecycle projection")
	}
	return lane, nil
}

func validAncestry(lane api.Lane) bool {
	if lane.ParentLifeID == "" {
		return lane.RootLifeID == lane.LifeID && len(lane.StarterChain) == 0 &&
			lane.StarterEventSeq == 0
	}
	chain := lane.StarterChain
	if len(chain) == 0 || chain[0] != lane.RootLifeID ||
		chain[len(chain)-1] != lane.ParentLifeID || lane.StarterEventSeq == 0 {
		return false
	}
	seen := make(map[api.ID]bool, len(chain))
	for _, id := range chain {
		if !validID(id) || id == lane.LifeID || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func (s *Service) lockLife(ctx context.Context, id api.ID) (func(), error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if err := s.ready(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	gate := s.gates[id]
	if gate == nil {
		gate = &lifeGate{token: make(chan struct{}, 1)}
		gate.token <- struct{}{}
		s.gates[id] = gate
	}
	gate.refs++
	s.mu.Unlock()
	drop := func() {
		s.mu.Lock()
		gate.refs--
		if gate.refs == 0 {
			delete(s.gates, id)
		}
		s.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		drop()
		return nil, failure(ctx.Err())
	case <-gate.token:
		return func() { gate.token <- struct{}{}; drop() }, nil
	}
}

// NotifyCommit is a service-internal wakeup hint, never an event submission.
// Readers always fetch and authorize the durable Store cursor after waking.
func (s *Service) NotifyCommit() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
	s.mu.Unlock()
}

func (s *Service) wakeup() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

func (s *Service) event(scope api.Scope, lane api.Lane, kind api.EventKind,
	payload any, actor api.Actor) (api.Event, error) {
	if kind == "lane.turn" && !validID(lane.LogicalTurnID) {
		return api.Event{}, integrity("turn event has no actual logical turn identity")
	}
	id, err := newID()
	if err != nil {
		return api.Event{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return api.Event{}, integrity("cannot encode lifecycle event")
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	chain := append([]api.ID{}, lane.StarterChain...)
	return api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config,
		Kind: kind, Actor: actor, RequestedBy: scope.Actor,
		RequestID: scope.Request.RequestID, LifeID: lane.LifeID, Run: lane.Run,
		LogicalTurnID: lane.LogicalTurnID, ParentLifeID: lane.ParentLifeID,
		RootLifeID: lane.RootLifeID, StarterChain: chain,
		StarterEventSeq: lane.StarterEventSeq, RecordedAt: now,
		RequestedAt: now, ObservedAt: now, Origin: "service", Payload: data}, nil
}

func (s *Service) transact(ctx context.Context, scope api.Scope,
	lane api.Lane, events []api.Event, effects []api.Effect, terminal ...api.StopResult) (api.Operation, error) {
	commit, err := s.commitLifecycleResult(ctx, scope, lane, events, effects, terminal)
	if err != nil {
		return api.Operation{}, err
	}
	var operation api.Operation
	if commit.Reply == nil || api.DecodeObject(commit.Reply.Result, &operation) != nil ||
		operation.ID != commit.Operation.ID || operation.LifeID != lane.LifeID || operation.Run != lane.Run {
		return api.Operation{}, integrity("durable operation reply differs from its lifecycle commit")
	}
	if len(terminal) == 1 && !reflect.DeepEqual(operation.Stop, &terminal[0]) {
		return api.Operation{}, integrity("terminal stop reply differs from its committed run end")
	}
	return operation, nil
}

func (s *Service) commitLifecycle(ctx context.Context, scope api.Scope,
	lane api.Lane, events []api.Event, effects []api.Effect, workers ...api.WorkerLease) (api.Commit, error) {
	return s.commitLifecycleResult(ctx, scope, lane, events, effects, nil, workers...)
}

func (s *Service) commitLifecycleResult(ctx context.Context, scope api.Scope,
	lane api.Lane, events []api.Event, effects []api.Effect, terminal []api.StopResult, workers ...api.WorkerLease) (api.Commit, error) {
	if scope.Request.Method != "" && !api.Methods[scope.Request.Method].Mutation {
		return api.Commit{}, integrity("lifecycle commit requires a mutation reservation or an internal intent")
	}
	operationID, err := newID()
	if err != nil {
		return api.Commit{}, err
	}
	if api.Methods[scope.Request.Method].Mutation {
		key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
		receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
		if notFound(err) {
			return api.Commit{}, integrity("mutation has no dispatcher reservation")
		}
		if err != nil {
			return api.Commit{}, failure(err)
		}
		if err == nil {
			if !receiptMatches(scope, key, receipt) || receipt.Reply != nil || !validID(receipt.Operation.ID) || receipt.Operation.Status != "pending" {
				return api.Commit{}, integrity("mutation lost its original pending operation")
			}
			owned, err := s.ownsMutation(ctx, scope, key, receipt)
			if err != nil {
				return api.Commit{}, err
			}
			if !owned {
				return api.Commit{}, integrity("mutation cannot complete another executor's reservation")
			}
			operationID = receipt.Operation.ID
		}
	}
	next := lane
	stateChanged, cancelled := false, false
	for i := range events {
		events[i].OperationID = operationID
		if events[i].Kind == "lane.ended" {
			var end api.RunEndEvent
			if decode(events[i].Payload, &end) != nil || validateObservation(end.Observation.Handle, end.Observation) != nil || requireQuiescence(end.Observation) != nil {
				return api.Commit{}, integrity("run end lost its measured quiescence")
			}
			next.Containment = "quiescent"
		}
		if events[i].Kind == "lane.loop" {
			var setting api.LoopRequest
			if decode(events[i].Payload, &setting) != nil || setting.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) ||
				setting.ExpectedGeneration != lane.Generation || lane.Generation >= api.Generation(maxInteger) {
				return api.Commit{}, integrity("invalid durable loop setting")
			}
			next.Generation, stateChanged = lane.Generation+1, true
		}
		if events[i].Kind == "lane.state" || events[i].Kind == "lane.stopping" {
			var state api.StateEvent
			if err := decode(events[i].Payload, &state); err != nil {
				return api.Commit{}, integrity("invalid lifecycle state intent")
			}
			next.State, next.Generation = state.To, state.Generation
			stateChanged = true
			cancelled = cancelled || state.To == "stopping" || state.To == "abandoned" || state.To == "merged"
		}
	}
	if cancelled {
		if uint64(lane.CancellationEpoch) >= maxInteger {
			return api.Commit{}, integrity("cancellation epoch exhausted")
		}
		next.CancellationEpoch++
	}
	for i := range effects {
		effects[i].OperationID = operationID
		intentID, err := newID()
		if err != nil {
			return api.Commit{}, err
		}
		effects[i].Context = &api.InternalIntent{ID: intentID, Kind: api.InternalLifecycleEffect,
			Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "lifecycle"},
			RequestedBy: scope.Actor, CauseOperationID: operationID,
			CauseRequestID: scope.Request.RequestID, EffectID: effects[i].ID,
			Target:        api.LifeRef{LifeID: lane.LifeID, Run: lane.Run},
			LogicalTurnID: lane.LogicalTurnID, CancellationEpoch: next.CancellationEpoch}
		if effects[i].HelperRelease != nil {
			effects[i].Context.Kind = api.InternalHelperRelease
			effects[i].HelperRelease.Cause = *effects[i].Context
		}
	}
	status := "succeeded"
	if len(effects) > 0 {
		status = "pending"
	}
	proposed := api.Operation{ID: operationID, Status: status, LifeID: lane.LifeID, Run: lane.Run}
	if len(terminal) != 0 {
		if len(terminal) != 1 || scope.Request.Method != "lane.stop" || len(events) != 0 || len(effects) != 0 {
			return api.Commit{}, integrity("terminal stop result cannot publish a transition")
		}
		proposed.Stop = &terminal[0]
	}
	result, err := json.Marshal(proposed)
	if err != nil {
		return api.Commit{}, integrity("cannot encode lifecycle operation")
	}
	if scope.Request.Method == "lane.check" {
		if len(events) == 0 || events[0].Kind != "run.observed" {
			return api.Commit{}, integrity("check reply has no correlated observation")
		}
		result = append([]byte{}, events[0].Payload...)
	}
	if scope.Request.Method == "lane.review" {
		if len(events) != 1 || events[0].Kind != "lane.reviewed" {
			return api.Commit{}, integrity("review reply has no verified receipt event")
		}
		result = append([]byte{}, events[0].Payload...)
	}
	reply := &api.RPCReply{Result: result}
	if scope.Request.Method == "lane.check" {
		var observed api.ProcessObservation
		if api.DecodeObject(result, &observed) != nil {
			return api.Commit{}, integrity("invalid observation reply")
		}
		if observed.State == "unknown" {
			reply = &api.RPCReply{Error: problem(api.CodeContainmentUnknown,
				"process observation has unknown containment",
				"Retain the run leases and reconcile; no end was recorded.")}
		}
	}
	transaction := api.Transaction{Scope: scope,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation}},
		Events:  events, Effects: effects, Reply: reply,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{
			LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}}}
	if reply.Error != nil {
		// Draft.4 final error receipts cannot publish state, events, effects
		// or consumed guards. Retain the actual unknown outcome in the exact
		// error receipt; no run end or observation event is fabricated.
		transaction = api.Transaction{Scope: scope, Reply: reply}
	}
	if stateChanged {
		transaction.Writes.Lanes = []api.Lane{next}
	}
	if len(workers) != 0 {
		if scope.Request.Method != "lane.input" || reply.Error != nil {
			return api.Commit{}, integrity("worker lease is outside its lifecycle input mutation")
		}
		transaction.Writes.WorkerLeases = append([]api.WorkerLease{}, workers...)
	}
	if scope.Frame != nil {
		transaction.RawRequest = append([]byte{}, scope.Frame.Bytes()...)
	}
	if scope.Actor.Kind == "human" && reply.Error == nil {
		if scope.Request.Proof == nil {
			return api.Commit{}, problem(api.CodeForbidden, "human lifecycle mutation needs its exact proof",
				"Confirm this operation and retain its request and idempotency key.")
		}
		target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
		if err != nil {
			return api.Commit{}, failure(err)
		}
		if target.Method != scope.Request.Method || target.TargetID != lane.LifeID ||
			target.RequestSHA256 != scope.Request.RequestSHA256 || target.BaseGeneration != lane.Generation {
			return api.Commit{}, integrity("human proof target differs from the lifecycle mutation")
		}
		transaction.Guards = append(transaction.Guards, api.TransactionGuard{
			Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}})
	}
	commit, err := s.deps.Store.Transact(ctx, transaction)
	if err != nil {
		return api.Commit{}, failure(err)
	}
	if !validID(commit.Operation.ID) || commit.Operation.Status == "" ||
		commit.LastSeq < commit.FirstSeq {
		return api.Commit{}, integrity("invalid lifecycle commit receipt")
	}
	switch commit.Operation.Status {
	case "pending", "running", "succeeded", "failed", "cancelled":
	default:
		return api.Commit{}, integrity("unknown lifecycle operation status")
	}
	if len(effects) > 0 && !commit.Replayed && commit.Operation.Status == "succeeded" {
		return api.Commit{}, integrity("external effect claimed completion during intent commit")
	}
	if commit.Reply == nil || (commit.Reply.Error == nil) == (len(commit.Reply.Result) == 0) {
		return api.Commit{}, integrity("lifecycle transaction omitted its durable reply")
	}
	if commit.Reply.Error != nil {
		s.NotifyCommit()
		return api.Commit{}, commit.Reply.Error
	}
	spec, exists := api.Methods[scope.Request.Method]
	if !exists || commit.Operation.Error != nil ||
		api.DecodeObject(commit.Reply.Result, reflect.New(spec.Response).Interface()) != nil {
		return api.Commit{}, integrity("lifecycle transaction returned an invalid typed reply")
	}
	s.NotifyCommit()
	// The committed epoch invalidates stale continuation claims. The stop
	// outbox still owns cancellation reconciliation and physical shutdown;
	// an unrecorded post-commit callback cannot replace that durable effect.
	return commit, nil
}
