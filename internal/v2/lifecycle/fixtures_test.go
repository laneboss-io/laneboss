package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

// These are dependency fixtures, not an isolation or authenticated-driver E2E.
// Unused interface methods are deliberately absent: calling one fails loudly.
type fixtureClock struct{}

func (fixtureClock) Now() time.Time {
	return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
}

type fixtureIdentity struct {
	api.Authenticator
	denied atomic.Bool
	mu     sync.Mutex
	actors []api.Actor
}

func (identity *fixtureIdentity) Authorize(_ context.Context, scope api.Scope,
	_ api.Request) error {
	identity.mu.Lock()
	identity.actors = append(identity.actors, scope.Actor)
	identity.mu.Unlock()
	if identity.denied.Load() {
		return &api.Error{Code: api.CodeForbidden, Message: "fixture revocation"}
	}
	return nil
}

type fixtureCursor struct {
	config string
	actor  api.Actor
	life   api.ID
	run    api.RunNumber
	until  api.EventKind
	seq    api.Sequence
}

type fixtureStore struct {
	api.StateStore
	mu              sync.Mutex
	lanes           map[api.ID]api.Lane
	launches        map[api.ID]api.LaunchRecord
	blobs           map[api.ID][]byte
	metadata        map[api.ID]api.ObjectMetadata
	grants          map[api.ID]api.GrantSet
	tickets         map[api.ID]api.Ticket
	ticketReads     int
	operations      map[api.ID]api.Operation
	operationReads  int
	continuations   map[api.ID]api.ContinuationIntent
	reviewWorkers   map[api.ID]api.WorkerLease
	reviewEffects   map[api.ID]api.EffectRecord
	reviewCaptures  map[api.ID]api.CaptureState
	events          []api.Event
	eventCalls      int
	transactions    []api.Transaction
	attempts        []api.Transaction
	receipts        map[string]api.MutationReceipt
	pendingFrames   map[string]api.FrameContext
	pendingDone     map[string]chan struct{}
	dispatchCalls   int
	receiptAwaited  chan struct{}
	lookupOverride  *api.MutationReceipt
	awaitOverride   *api.MutationReceipt
	lookupCalls     int
	awaitCalls      int
	cursors         map[string]fixtureCursor
	policy          api.EffectivePolicy
	policyHistory   map[api.Generation]api.EffectivePolicy
	policyRefreshes int
	read            chan struct{}
	readOnce        sync.Once
	laneErr         error
	laneReads       int
	pageOverride    *api.EventPage
	seq             api.Sequence
	readers         map[api.ID]bool
	readerCount     int
	readersReady    chan struct{}
	readersOnce     sync.Once
	transactErr     error
	effectDone      bool
	blobHook        func(api.BlobChunk) (api.BlobChunk, error)
	briefingHook    func(api.Scope, api.BriefingInput) api.BriefingInput
	targetHook      func(api.HumanChallengeRequest) api.HumanChallengeRequest
	reserveLaunch   func(context.Context, api.Scope, api.LaunchReservationRequest) (api.LaunchReservation, error)
}

func (store *fixtureStore) ReserveLaunch(ctx context.Context, scope api.Scope, request api.LaunchReservationRequest) (api.LaunchReservation, error) {
	if store.reserveLaunch == nil {
		return api.LaunchReservation{}, api.NotImplemented("lb-v2-service", "store.ReserveLaunch")
	}
	return store.reserveLaunch(ctx, scope, request)
}

func (store *fixtureStore) Lane(_ context.Context, _ api.Scope,
	target api.LifeRef) (api.Lane, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.laneReads++
	if store.laneErr != nil {
		return api.Lane{}, store.laneErr
	}
	lane, ok := store.lanes[target.LifeID]
	if !ok {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound, Message: "fixture life absent"}
	}
	return lane, nil
}

func (store *fixtureStore) Lanes(_ context.Context, _ api.Scope,
	_ api.ListRequest) (api.LanePage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	page := api.LanePage{Lanes: []api.Lane{}}
	for _, lane := range store.lanes {
		page.Lanes = append(page.Lanes, lane)
	}
	return page, nil
}

func (store *fixtureStore) Events(_ context.Context, scope api.Scope,
	request api.EventTailRequest) (api.EventPage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.eventCalls++
	store.readOnce.Do(func() { close(store.read) })
	if store.readerCount > 0 {
		store.readers[scope.Request.RequestID] = true
		if len(store.readers) >= store.readerCount {
			store.readersOnce.Do(func() { close(store.readersReady) })
		}
	}
	if store.pageOverride != nil {
		return *store.pageOverride, nil
	}
	since := request.Since
	if request.Cursor != "" {
		cursor, ok := store.cursors[request.Cursor]
		if !ok || cursor.config != scope.Config || cursor.actor != scope.Actor ||
			cursor.life != request.LifeID || cursor.run != request.Run || cursor.until != request.Until {
			return api.EventPage{}, &api.Error{Code: api.CodeCursorExpired, Message: "fixture cursor binding"}
		}
		since = cursor.seq
	}
	page := api.EventPage{Events: []api.Event{}, Complete: true}
	last := since
	// Deliberately return other lives/runs too, to exercise lifecycle's
	// independent selection before until. This fixture is not a Store proof.
	for _, event := range store.events {
		if event.Seq <= since {
			continue
		}
		if len(page.Events) == 200 {
			page.Complete = false
			break
		}
		page.Events = append(page.Events, event)
		last = event.Seq
	}
	page.Cursor = "page-" + strconv.Itoa(len(store.cursors)+1)
	store.cursors[page.Cursor] = fixtureCursor{config: scope.Config, actor: scope.Actor,
		life: request.LifeID, run: request.Run, until: request.Until, seq: last}
	return page, nil
}

func (store *fixtureStore) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.launches[id]
	if !ok {
		return api.LaunchRecord{}, &api.Error{Code: api.CodeNotFound, Message: "fixture launch absent"}
	}
	return record, nil
}

func (store *fixtureStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	grants, ok := store.grants[id]
	if !ok {
		return api.GrantSet{}, &api.Error{Code: api.CodeNotFound, Message: "fixture grants absent"}
	}
	return grants, nil
}

func (store *fixtureStore) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	return store.policy, nil
}

func (store *fixtureStore) BriefingInput(_ context.Context, scope api.Scope,
	request api.BriefingInputRequest) (api.BriefingInput, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	lane, ok := store.lanes[request.LifeID]
	if !ok {
		return api.BriefingInput{}, &api.Error{Code: api.CodeNotFound, Message: "fixture briefing life absent"}
	}
	if (scope.Actor.Kind == "lane" || scope.Actor.Kind == "worker") &&
		(scope.Actor.LifeID != lane.LifeID || request.GrantSetID != lane.GrantSetID ||
			request.Context.Level != lane.Level || request.Context.Role != lane.Role) {
		return api.BriefingInput{}, &api.Error{Code: api.CodeForbidden, Message: "fixture briefing is an own-life claim"}
	}
	policy := store.policy
	policy.Context = api.RoleContext{Level: lane.Level, Role: lane.Role}
	input := api.BriefingInput{Mode: "lane", Lane: &lane, Task: &lane.Task, Policy: policy}
	if store.briefingHook != nil {
		input = store.briefingHook(scope, input)
	}
	return input, nil
}

func (store *fixtureStore) Operation(_ context.Context, _ api.Scope, id api.ID) (api.Operation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.operationReads++
	operation, ok := store.operations[id]
	if !ok {
		return api.Operation{}, &api.Error{Code: api.CodeNotFound, Message: "fixture operation absent"}
	}
	return operation, nil
}

func (store *fixtureStore) ContinuationIntent(_ context.Context, _ api.Scope, id api.ID) (api.ContinuationIntent, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	intent, ok := store.continuations[id]
	if !ok {
		return api.ContinuationIntent{}, &api.Error{Code: api.CodeNotFound, Message: "fixture continuation absent"}
	}
	return intent, nil
}

func (store *fixtureStore) Ticket(_ context.Context, _ api.Scope, id api.ID) (api.Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ticketReads++
	ticket, ok := store.tickets[id]
	if !ok {
		return api.Ticket{}, &api.Error{Code: api.CodeNotFound, Message: "fixture ticket absent"}
	}
	return ticket, nil
}

func (store *fixtureStore) AuthorizationTarget(_ context.Context, _ api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	var id api.ID
	var generation api.Generation
	switch request.Method {
	case "lane.mark":
		var params api.MarkRequest
		if err := api.DecodeObject(request.Params, &params); err != nil {
			return api.HumanChallengeRequest{}, err
		}
		id, generation = params.Target.LifeID, params.ExpectedGeneration
	case "lane.stop":
		var params api.StopRequest
		if err := api.DecodeObject(request.Params, &params); err != nil {
			return api.HumanChallengeRequest{}, err
		}
		id, generation = params.Target.LifeID, params.ExpectedGeneration
	case "lane.resume":
		var params api.ResumeRequest
		if err := api.DecodeObject(request.Params, &params); err != nil {
			return api.HumanChallengeRequest{}, err
		}
		id, generation = params.Target.LifeID, params.ExpectedGeneration
	case "lane.turn":
		var params api.TurnRequest
		if err := api.DecodeObject(request.Params, &params); err != nil {
			return api.HumanChallengeRequest{}, err
		}
		id, generation = params.Target.LifeID, params.ExpectedGeneration
	case "lane.check":
		var params api.LifeRef
		if err := api.DecodeObject(request.Params, &params); err != nil {
			return api.HumanChallengeRequest{}, err
		}
		store.mu.Lock()
		id, generation = params.LifeID, store.lanes[params.LifeID].Generation
		store.mu.Unlock()
	default:
		return api.HumanChallengeRequest{}, api.NotImplemented(owner, "fixture authorization target")
	}
	target := api.HumanChallengeRequest{Method: request.Method, TargetID: id,
		BaseGeneration: generation, RequestSHA256: request.RequestSHA256}
	if store.targetHook != nil {
		target = store.targetHook(target)
	}
	return target, nil
}

func (store *fixtureStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	metadata, ok := store.metadata[id]
	if !ok {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound, Message: "fixture object absent"}
	}
	return metadata, nil
}

func (store *fixtureStore) LookupReceipt(_ context.Context, scope api.Scope, request api.RequestKey) (api.MutationReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.lookupCalls++
	if store.lookupOverride != nil {
		return *store.lookupOverride, nil
	}
	receipt, found := store.receipts[fixtureReceiptKey(scope, request)]
	if !found {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound, Message: "fixture receipt absent"}
	}
	if receipt.Key.RequestSHA256 != request.RequestSHA256 {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeIdempotencyConflict, Message: "fixture digest changed"}
	}
	return receipt, nil
}

func (store *fixtureStore) AwaitReceipt(ctx context.Context, scope api.Scope, request api.RequestKey) (api.MutationReceipt, error) {
	if absent(ctx) {
		return api.MutationReceipt{}, invalid("context required")
	}
	if err := ctx.Err(); err != nil {
		return api.MutationReceipt{}, err
	}
	store.mu.Lock()
	store.awaitCalls++
	override := store.awaitOverride
	domain := fixtureReceiptKey(scope, request)
	retained, exists := store.receipts[domain]
	done := store.pendingDone[domain]
	store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return api.MutationReceipt{}, err
	}
	if override != nil {
		return *override, nil
	}
	if store.receiptAwaited != nil {
		select {
		case store.receiptAwaited <- struct{}{}:
		default:
		}
	}
	if exists && retained.Reply == nil && done != nil {
		select {
		case <-ctx.Done():
			return api.MutationReceipt{}, ctx.Err()
		case <-done:
		}
	}
	if err := ctx.Err(); err != nil {
		return api.MutationReceipt{}, err
	}
	return store.LookupReceipt(ctx, scope, request)
}

func (store *fixtureStore) OwnsMutation(_ context.Context, scope api.Scope, key api.RequestKey, operation api.ID) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.dispatchCalls++
	domain := fixtureReceiptKey(scope, key)
	receipt, ok := store.receipts[domain]
	return ok && receiptMatches(scope, key, receipt) && receipt.Operation.ID == operation && receipt.Reply == nil &&
		scope.Frame != nil && store.pendingFrames[domain] == scope.Frame, nil
}

func (store *fixtureStore) ReserveRequest(_ context.Context, request api.RequestReservation) (api.MutationReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	scope := request.Scope
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	domain := fixtureReceiptKey(scope, key)
	if prior, ok := store.receipts[domain]; ok {
		if !receiptMatches(scope, key, prior) {
			return api.MutationReceipt{}, &api.Error{Code: api.CodeIdempotencyConflict, Message: "fixture digest changed"}
		}
		return prior, nil
	}
	var original api.Request
	if scope.Frame == nil || api.DecodeObject(request.RawRequest, &original) != nil || !reflect.DeepEqual(original, scope.Request) {
		return api.MutationReceipt{}, launchConflict()
	}
	op := api.Operation{ID: launchIDForTest(), Status: "pending"}
	receipt := api.MutationReceipt{Config: scope.Config, Key: key, Actor: scope.Actor, Operation: op,
		RawRequest: append([]byte{}, request.RawRequest...), PolicyGeneration: scope.PolicyGeneration}
	if store.pendingFrames == nil {
		store.pendingFrames = map[string]api.FrameContext{}
		store.pendingDone = map[string]chan struct{}{}
	}
	store.pendingFrames[domain], store.pendingDone[domain] = scope.Frame, make(chan struct{})
	store.receipts[domain], store.operations[op.ID] = receipt, op
	return receipt, nil
}

func fixtureReceiptKey(scope api.Scope, request api.RequestKey) string {
	return scope.Config + "\x00" + scope.Actor.Kind + "\x00" + string(scope.Actor.ID) + "\x00" +
		string(scope.Actor.LifeID) + "\x00" + string(request.Method) + "\x00" + string(request.IdempotencyKey)
}

func digestOf(data []byte) api.Digest {
	digest := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(digest[:]))
}

func (store *fixtureStore) Blob(_ context.Context, _ api.Scope,
	request api.BlobReadRequest) (api.BlobChunk, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	data, ok := store.blobs[request.ObjectID]
	if !ok || request.Offset < 0 || request.Offset > int64(len(data)) {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound, Message: "fixture blob absent"}
	}
	end := min(int64(len(data)), request.Offset+int64(request.Limit))
	part := append([]byte{}, data[request.Offset:end]...)
	chunk := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset,
		Data: part, SHA256: digestOf(part)}
	if store.blobHook != nil {
		return store.blobHook(chunk)
	}
	return chunk, nil
}

func (store *fixtureStore) Transact(_ context.Context, tx api.Transaction) (api.Commit, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.transactErr != nil {
		return api.Commit{}, store.transactErr
	}
	store.attempts = append(store.attempts, tx)
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	requestKey := api.RequestKey{Method: tx.Scope.Request.Method, IdempotencyKey: tx.Scope.Request.IdempotencyKey,
		RequestSHA256: tx.Scope.Request.RequestSHA256}
	key := fixtureReceiptKey(tx.Scope, requestKey)
	if prior, ok := store.receipts[key]; ok {
		if prior.Key.RequestSHA256 != tx.Scope.Request.RequestSHA256 {
			return api.Commit{}, &api.Error{Code: api.CodeIdempotencyConflict, Message: "fixture digest changed"}
		}
		if prior.Reply != nil {
			return api.Commit{Operation: prior.Operation, Reply: prior.Reply, FirstSeq: prior.FirstSeq,
				LastSeq: prior.LastSeq, Replayed: true}, nil
		}
	}
	for _, compare := range tx.Compare {
		if compare.Kind != "lane" || store.lanes[compare.ID].Generation != compare.Generation {
			return api.Commit{}, &api.Error{Code: api.CodeConflict, Message: "fixture generation changed"}
		}
	}
	for _, guard := range tx.Guards {
		if guard.Cancellation != nil && store.lanes[guard.Cancellation.LifeID].CancellationEpoch != guard.Cancellation.Epoch {
			return api.Commit{}, &api.Error{Code: api.CodeConflict, Message: "fixture epoch changed"}
		}
	}
	store.transactions = append(store.transactions, tx)
	first := store.seq + 1
	var operationID api.ID
	for _, event := range tx.Events {
		store.seq++
		event.Seq = store.seq
		operationID = event.OperationID
		store.events = append(store.events, event)
		lane := store.lanes[event.LifeID]
		if event.Kind == "lane.state" || event.Kind == "lane.stopping" {
			var state api.StateEvent
			if err := json.Unmarshal(event.Payload, &state); err != nil {
				return api.Commit{}, err
			}
			lane.State, lane.Generation = state.To, state.Generation
		}
		lane.LastSeq = event.Seq
		store.lanes[event.LifeID] = lane
	}
	if len(tx.Events) == 0 {
		first = 0
		if prior, ok := store.receipts[key]; ok {
			operationID = prior.Operation.ID
		} else {
			var err error
			operationID, err = newID()
			if err != nil {
				return api.Commit{}, err
			}
		}
	}
	for _, lane := range tx.Writes.Lanes {
		lane.LastSeq = store.seq
		store.lanes[lane.LifeID] = lane
	}
	status := "succeeded"
	if len(tx.Effects) > 0 && !store.effectDone {
		status = "pending"
	}
	if tx.Reply != nil && tx.Reply.Error != nil {
		status = "failed"
	}
	commit := api.Commit{FirstSeq: first, LastSeq: store.seq,
		Operation: api.Operation{ID: operationID, Status: status,
			FirstSeq: first, LastSeq: store.seq}}
	if len(tx.Events) > 0 {
		commit.Operation.LifeID, commit.Operation.Run = tx.Events[0].LifeID, tx.Events[0].Run
	} else if len(tx.Effects) > 0 && tx.Effects[0].Context != nil {
		commit.Operation.LifeID, commit.Operation.Run = tx.Effects[0].Context.Target.LifeID, tx.Effects[0].Context.Target.Run
	}
	commit.Reply = tx.Reply
	if commit.Reply != nil && commit.Reply.Error != nil {
		commit.Operation.Error = commit.Reply.Error
		if tx.Scope.Request.Method == "lane.check" {
			var target api.LifeRef
			if err := api.DecodeObject(tx.Scope.Request.Params, &target); err != nil {
				return api.Commit{}, err
			}
			commit.Operation.LifeID, commit.Operation.Run = target.LifeID, target.Run
		}
	}
	if tx.Scope.Request.Method == "lane.mark" || tx.Scope.Request.Method == "lane.stop" {
		if tx.Scope.Request.Method == "lane.stop" && len(tx.Events) == 0 && tx.Reply != nil && tx.Reply.Error == nil {
			var submitted api.Operation
			if err := api.DecodeObject(tx.Reply.Result, &submitted); err != nil {
				return api.Commit{}, err
			}
			commit.Operation.LifeID, commit.Operation.Run, commit.Operation.Stop = submitted.LifeID, submitted.Run, submitted.Stop
		}
		data, err := json.Marshal(commit.Operation)
		if err != nil {
			return api.Commit{}, err
		}
		commit.Reply = &api.RPCReply{Result: data}
	}
	store.receipts[key] = api.MutationReceipt{Config: tx.Scope.Config, Key: requestKey, Actor: tx.Scope.Actor, PolicyGeneration: tx.Scope.PolicyGeneration,
		Operation: commit.Operation, Reply: commit.Reply, RawRequest: append([]byte{}, tx.RawRequest...),
		FirstSeq: commit.FirstSeq, LastSeq: commit.LastSeq}
	store.operations[commit.Operation.ID] = commit.Operation
	if commit.Reply != nil {
		store.closePending(key)
	}
	return commit, nil
}

// Caller holds mu. Completion ends invocation ownership even when the public
// reply's operation still has a pending physical effect.
func (store *fixtureStore) closePending(domain string) {
	delete(store.pendingFrames, domain)
	if done := store.pendingDone[domain]; done != nil {
		select {
		case <-done:
		default:
			close(done)
		}
	}
}

type fixtureLauncher struct {
	api.Launcher
	observation api.ProcessObservation
	available   bool
	prepared    atomic.Int32
	launched    atomic.Int32
	stopped     atomic.Int32
	observed    atomic.Int32
}

func (launcher *fixtureLauncher) Observe(context.Context, api.ProcessHandle) (api.ProcessObservation, error) {
	launcher.observed.Add(1)
	return launcher.observation, nil
}

func (launcher *fixtureLauncher) Probe(context.Context) (api.IsolationCapabilities, error) {
	return api.IsolationCapabilities{Backend: "fixture", Available: launcher.available,
		Checks: []api.Capability{{Name: "fixture boundary", Available: launcher.available}}}, nil
}

func (launcher *fixtureLauncher) Prepare(context.Context, api.LaunchSpec) (api.PreparedLaunch, error) {
	launcher.prepared.Add(1)
	return api.PreparedLaunch{}, api.NotImplemented(owner, "fixture prepare")
}

func (launcher *fixtureLauncher) Launch(context.Context, api.PreparedLaunch,
	api.LaunchPermit) (api.ProcessHandle, error) {
	launcher.launched.Add(1)
	return api.ProcessHandle{}, api.NotImplemented(owner, "fixture launch")
}

func (launcher *fixtureLauncher) Stop(context.Context, api.ProcessHandle,
	string) (api.ProcessObservation, error) {
	launcher.stopped.Add(1)
	return api.ProcessObservation{}, api.NotImplemented(owner, "fixture stop")
}

type fixtureGrants struct{ api.GrantResolver }

func (fixtureGrants) Revalidate(_ context.Context, grants api.GrantSet) (api.GrantSet, error) {
	return grants, nil
}

func (fixtureGrants) Resolve(_ context.Context, _ api.Scope,
	_ api.GrantResolveRequest) (api.GrantSet, error) {
	return api.GrantSet{}, api.NotImplemented("lb-v2-grants", "fixture reserved grant resolution")
}

type fixtureRunner struct{ api.Runner }

type fixtureConnection struct {
	api.ConnectionContext
	binding api.InstalledBinding
}

func (connection *fixtureConnection) Binding() api.InstalledBinding { return connection.binding }

type fixtureCredentials struct {
	api.CredentialBroker
	eligibility api.ProfileEligibility
	room        api.Room
	acquired    atomic.Int32
}

func (broker *fixtureCredentials) Eligibility(_ context.Context, request api.ProfileEligibilityRequest) (api.ProfileEligibility, error) {
	if request != broker.eligibility.Request {
		return api.ProfileEligibility{}, &api.Error{Code: api.CodeForbidden, Message: "fixture eligibility context differs"}
	}
	return broker.eligibility, nil
}

func (broker *fixtureCredentials) Room(_ context.Context, grant api.ProfileGrant) (api.Room, error) {
	if grant.ProfileID != broker.room.ProfileID {
		return api.Room{}, &api.Error{Code: api.CodeForbidden, Message: "fixture room profile differs"}
	}
	return broker.room, nil
}

func (broker *fixtureCredentials) Acquire(context.Context, api.LifeRef, api.ProfileGrant) (api.CredentialSlot, error) {
	broker.acquired.Add(1)
	return api.CredentialSlot{}, api.NotImplemented(owner, "fixture slot acquisition")
}

type fixture struct {
	service  *Service
	store    *fixtureStore
	identity *fixtureIdentity
	launcher *fixtureLauncher
	child    api.Lane
	parent   api.Actor
	target   api.LifeRef
	budget   api.Budget
	t        *testing.T
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	budget := api.Budget{WallMS: 60000, CPUSeconds: 60, MemoryBytes: 1024,
		Processes: 16, DiskBytes: 4096, SpendMicros: 0, Currency: "USD"}
	child := api.Lane{LifeID: "child", Name: "child-name", ParentLifeID: "parent",
		LaunchID: "launch", Model: "fixture-model", Effort: "high",
		RootLifeID: "parent", StarterChain: []api.ID{"parent"}, StarterEventSeq: 1,
		Level: 3, Role: "executor", State: "verifying", Generation: 1, Run: 2,
		LogicalTurnID: "turn", Session: api.Session{ID: "session", Driver: api.DriverCodex,
			VendorID: "vendor-conversation", VendorVersion: "fixture", HomeID: "home", HistoryID: "history", LogicalCWD: "/work/main"},
		Workspace: api.Workspace{ID: "workspace", LogicalCWD: "/work/main"}, GrantSetID: "grants",
		ProfileGrantID: "profile-grant", PolicyGeneration: 1, BudgetRemaining: budget}
	target := api.LifeRef{LifeID: child.LifeID, Run: child.Run}
	handle := api.ProcessHandle{ID: "process", Target: target, ContainmentID: "containment", Generation: "generation"}
	zero, exit := uint64(0), 0
	launcher := &fixtureLauncher{available: true, observation: api.ProcessObservation{
		Handle: handle, State: "exited", Survivors: &zero, ExitCode: &exit,
		PromptStatus: "completed", ObservedAt: api.Timestamp(fixtureClock{}.Now().Format(time.RFC3339Nano))}}
	parentActor := api.Actor{Kind: "lane", ID: "parent-actor", LifeID: "parent", Level: 5, Role: "supervisor"}
	parentLane := api.Lane{LifeID: "parent", LaunchID: "parent-launch", RootLifeID: "parent", StarterChain: []api.ID{},
		Run: 1, Generation: 1, Level: 5, Role: "supervisor", State: "running", PolicyGeneration: 1}
	store := &fixtureStore{lanes: map[api.ID]api.Lane{"child": child, "parent": parentLane},
		launches: map[api.ID]api.LaunchRecord{}, blobs: map[api.ID][]byte{}, metadata: map[api.ID]api.ObjectMetadata{},
		grants: map[api.ID]api.GrantSet{}, receipts: map[string]api.MutationReceipt{},
		tickets: map[api.ID]api.Ticket{}, operations: map[api.ID]api.Operation{},
		continuations:  map[api.ID]api.ContinuationIntent{},
		reviewWorkers:  map[api.ID]api.WorkerLease{},
		reviewCaptures: map[api.ID]api.CaptureState{},
		cursors:        map[string]fixtureCursor{},
		read:           make(chan struct{}), policy: api.EffectivePolicy{Generation: 1,
			ProfileExclusions: []api.ID{}, Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{}},
		readers: map[api.ID]bool{}, readersReady: make(chan struct{})}
	store.policy.SHA256 = digestOf([]byte("approved policy generation one"))
	store.policyHistory = map[api.Generation]api.EffectivePolicy{1: store.policy}
	store.launches["launch"] = api.LaunchRecord{ID: "launch", Config: "example", Target: target,
		UIDLeaseID:   "helper-lease",
		ParentLifeID: child.ParentLifeID, RootLifeID: child.RootLifeID,
		StarterChain: child.StarterChain, StarterEventSeq: child.StarterEventSeq,
		ContainmentID: handle.ContainmentID, ProcessGeneration: handle.Generation}
	store.launches["parent-launch"] = api.LaunchRecord{ID: "parent-launch", Config: "example", Kind: "agent", Actor: parentActor,
		Target: api.LifeRef{LifeID: "parent", Run: 1}, EndpointGeneration: 1, RootLifeID: parentLane.RootLifeID, StarterChain: []api.ID{}}
	store.grants["grants"] = api.GrantSet{ID: "grants", LifeID: "child", ParentLifeID: "parent",
		SHA256: digestOf([]byte("fixture grants")), PolicyGeneration: 1, ExpiresAt: "2031-01-01T00:00:00Z"}
	identity := &fixtureIdentity{}
	service, err := New(Dependencies{Store: store, Identity: identity, Clock: fixtureClock{},
		Launcher: launcher, Grants: fixtureGrants{}, Codex: fixtureRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &fixture{service: service, store: store, identity: identity, launcher: launcher,
		child: child, target: target, budget: budget, t: t,
		parent: parentActor}
	fixture.child.Task = fixture.blob("retained-task", "task", []byte("original retained task\n"))
	store.lanes[child.LifeID] = fixture.child
	return fixture
}

func (fixture *fixture) prepareScope(method api.Method, request any, actor api.Actor) api.Scope {
	fixture.t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		fixture.t.Fatal(err)
	}
	id, err := newID()
	if err != nil {
		fixture.t.Fatal(err)
	}
	key, err := newID()
	if err != nil {
		fixture.t.Fatal(err)
	}
	prepared, err := client.PrepareRequest(api.Request{
		Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "example", Method: method,
		RequestID: id, IdempotencyKey: key, Params: data})
	if err != nil {
		fixture.t.Fatal(err)
	}
	class := api.EndpointLane
	if actor.Kind == "human" {
		class = api.EndpointHuman
	} else if actor.Kind == "worker" {
		class = api.EndpointWorker
	}
	connection := &fixtureConnection{binding: api.InstalledBinding{Config: "example", Class: class, EndpointGeneration: 1}}
	scope := api.Scope{Config: "example", Actor: actor, Source: "cli", LaunchID: "parent-launch",
		EndpointGeneration: 1, PolicyGeneration: fixture.store.policy.Generation, Request: prepared, Connection: connection}
	return scope
}

func (fixture *fixture) scope(method api.Method, request any, actor api.Actor) api.Scope {
	fixture.t.Helper()
	scope := fixture.prepareScope(method, request, actor)
	if api.Methods[method].Mutation {
		return fixture.reserveScope(scope)
	}
	return scope
}

func (fixture *fixture) reserveScope(scope api.Scope) api.Scope {
	fixture.t.Helper()
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		fixture.t.Fatal(err)
	}
	scope.Frame = &fixtureFrame{raw: raw}
	_, err = fixture.store.ReserveRequest(context.Background(), api.RequestReservation{Scope: scope, RawRequest: raw, Deadline: "2030-01-02T03:05:05Z"})
	if err != nil {
		fixture.t.Fatal(err)
	}
	return scope
}

func (fixture *fixture) add(kind api.EventKind, payload any, run api.RunNumber,
	origin string, actor api.Actor) api.Event {
	fixture.t.Helper()
	lane := fixture.child
	lane.Run = run
	return fixture.addTo(lane, kind, payload, origin, actor)
}

func (fixture *fixture) addTo(lane api.Lane, kind api.EventKind, payload any,
	origin string, actor api.Actor) api.Event {
	fixture.t.Helper()
	run := lane.Run
	scope := fixture.prepareScope("lane.check", api.LifeRef{LifeID: lane.LifeID, Run: run}, actor)
	event, err := fixture.service.event(scope, lane, kind, payload, actor)
	if err != nil {
		fixture.t.Fatal(err)
	}
	event.Origin = origin
	if receipt, ok := payload.(api.ReviewReceipt); ok && kind == "lane.reviewed" && receipt.Evidence != nil {
		event.OperationID = fixture.store.reviewWorkers[receipt.Evidence.VerifierLeaseID].OperationID
	}
	fixture.store.mu.Lock()
	fixture.store.seq++
	event.Seq = fixture.store.seq
	fixture.store.events = append(fixture.store.events, event)
	fixture.store.mu.Unlock()
	return event
}

func (fixture *fixture) ended() api.Event {
	return fixture.add("lane.ended", api.RunEndEvent{LaunchID: "launch", Reason: "exit",
		Observation: fixture.launcher.observation, BudgetRemaining: fixture.budget},
		fixture.target.Run, "service", fixture.parent)
}

func (fixture *fixture) blob(id api.ID, class string, data []byte) api.BlobRef {
	ref := api.BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: digestOf(data)}
	fixture.store.mu.Lock()
	fixture.store.blobs[id] = append([]byte{}, data...)
	fixture.store.metadata[id] = api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: "example"}}
	fixture.store.mu.Unlock()
	return ref
}

func fixtureContinuation(f *fixture) api.ContinuationRequest {
	f.t.Helper()
	f.ended()
	old := api.ProfileGrant{ID: f.child.ProfileGrantID, ProfileID: "old-profile",
		Driver: f.child.Session.Driver, Provider: "fixture-provider", ExpiresAt: "2031-01-01T00:00:00Z"}
	next := old
	next.ID, next.ProfileID = "replacement-grant", "new-profile"
	grants := f.store.grants[f.child.GrantSetID]
	grants.Profiles = []api.ProfileGrant{old, next}
	f.store.grants[grants.ID] = grants
	expected := api.ProfileEligibilityRequest{Target: f.target, GrantSetID: grants.ID,
		FromGrantID: old.ID, ToGrantID: next.ID, Driver: f.child.Session.Driver,
		Model: f.child.Model, Session: f.child.Session, HistoryID: f.child.Session.HistoryID}
	broker := &fixtureCredentials{
		eligibility: api.ProfileEligibility{ID: "eligibility", Request: expected, Compatible: true,
			Evidence:  f.blob("eligibility-evidence", "artifact", []byte("fixture eligible profile\n")),
			CheckedAt: "2030-01-02T03:04:05Z", ExpiresAt: "2031-01-01T00:00:00Z"},
		room: api.Room{ProfileID: next.ProfileID, Available: true,
			Evidence:  f.blob("room-evidence", "artifact", []byte("fixture room observation\n")),
			CheckedAt: "2030-01-02T03:04:05Z", ExpiresAt: "2031-01-01T00:00:00Z"}}
	f.service.deps.Credentials = broker
	swap := api.ProfileSwap{OperationID: "swap", CausingRun: f.target.Run, ContinuationRun: f.target.Run + 1,
		LogicalTurnID: f.child.LogicalTurnID, Limit: api.LimitSignal{Target: f.target, ProfileID: old.ProfileID},
		FromProfileID: old.ProfileID, ToProfileID: next.ProfileID, Room: broker.room,
		ProfileGrantID: next.ID, EligibilityID: broker.eligibility.ID, ExpectedGeneration: f.child.Generation,
		CancellationEpoch: f.child.CancellationEpoch}
	request := api.ContinuationRequest{IntentID: "intent", Swap: swap}
	f.store.operations[swap.OperationID] = api.Operation{ID: swap.OperationID,
		LifeID: f.target.LifeID, Run: f.target.Run, Status: "pending"}
	f.store.continuations[request.IntentID] = api.ContinuationIntent{ID: request.IntentID,
		OperationID: swap.OperationID, Target: f.target, LogicalTurnID: swap.LogicalTurnID,
		ExpectedGeneration: swap.ExpectedGeneration, Eligibility: broker.eligibility,
		Generation: 1, CancellationEpoch: swap.CancellationEpoch, Status: "pending", Swap: swap}
	return request
}

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	typed, ok := err.(*api.Error)
	if !ok || typed.Code != code {
		t.Fatalf("wanted %s; got %v", code, err)
	}
}
