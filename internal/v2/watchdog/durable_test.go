package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// journalStore models only the shared transaction boundary for component
// tests. It applies the comparisons/guards actually submitted, retains writes
// and stamps receipts. It does not model OS protection, slot claims or launch.
type journalStore struct {
	*readStore
	clock          *fixedClock
	intents        map[api.ID]api.ContinuationIntent
	operations     map[api.ID]api.Operation
	transactions   []api.Transaction
	before         func()
	after          func()
	fail           error
	lookupError    error
	operationErr   error
	omitWrite      bool
	replyOperation func(api.Operation) api.Operation
	onOperation    func()
}

func (m *journalStore) ContinuationIntent(_ context.Context, scope api.Scope, id api.ID) (api.ContinuationIntent, error) {
	m.check(scope)
	if m.lookupError != nil {
		return api.ContinuationIntent{}, m.lookupError
	}
	intent, exists := m.intents[id]
	if !exists {
		return api.ContinuationIntent{}, problem(api.CodeNotFound, "test intent is absent")
	}
	return intent, nil
}

func (m *journalStore) Operation(_ context.Context, scope api.Scope, id api.ID) (api.Operation, error) {
	m.check(scope)
	if m.onOperation != nil {
		m.onOperation()
	}
	if m.operationErr != nil {
		return api.Operation{}, m.operationErr
	}
	op, exists := m.operations[id]
	if !exists {
		return api.Operation{}, problem(api.CodeNotFound, "test operation is absent")
	}
	return op, nil
}

func (m *journalStore) Transact(_ context.Context, tx api.Transaction) (api.Commit, error) {
	m.check(tx.Scope)
	m.writeCalls++
	m.transactions = append(m.transactions, tx)
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	if m.before != nil {
		m.before()
	}
	if m.fail != nil {
		return api.Commit{}, m.fail
	}
	for _, compare := range tx.Compare {
		var actual api.Generation
		switch compare.Kind {
		case api.CompareLane:
			if compare.ID != m.lane.LifeID {
				m.t.Fatal("wrong life comparison")
			}
			actual = m.lane.Generation
		case api.CompareGrants:
			if compare.ID != m.grants.ID {
				m.t.Fatal("wrong grants comparison")
			}
			actual = m.grants.Generation
		case api.CompareContinuation:
			actual = m.intents[compare.ID].Generation
		default:
			m.t.Fatal("unexpected comparison kind")
		}
		if actual != compare.Generation {
			return api.Commit{}, problem(api.CodeConflict, "test transaction lost the CAS")
		}
	}
	for _, guard := range tx.Guards {
		if guard.Cancellation == nil || guard.Cancellation.LifeID != m.lane.LifeID {
			m.t.Fatal("unexpected guard")
		}
		if guard.Cancellation.Epoch != m.lane.CancellationEpoch {
			return api.Commit{}, problem(api.CodeCancelled, "test transaction lost the cancellation epoch")
		}
	}
	if tx.Internal == nil || len(tx.Writes.Continuations) != 1 ||
		len(tx.Effects) != 0 || tx.Reply != nil || len(tx.RawRequest) != 0 {
		m.t.Fatal("watchdog did not submit the narrow internal intent transaction")
	}
	if len(tx.Writes.Lanes) != 1 && !(tx.Internal.Kind == api.InternalProfileCancel && len(tx.Writes.Lanes) == 0) {
		m.t.Fatal("watchdog submitted an invalid life projection count")
	}
	op := api.Operation{ID: api.ID(fmt.Sprintf("journal-operation-%d", m.writeCalls)), Status: "succeeded",
		LifeID: m.lane.LifeID, Run: tx.Internal.Target.Run, FirstSeq: api.Sequence(len(m.events) + 1),
		LastSeq: api.Sequence(len(m.events) + max(1, len(tx.Events)))}
	if tx.Internal.Kind == api.InternalProfileContinue && tx.Writes.Continuations[0].Status == "pending" {
		op.Status = "pending"
	}
	if !m.omitWrite {
		if len(tx.Writes.Lanes) == 1 {
			m.lane = tx.Writes.Lanes[0]
		}
		for _, intent := range tx.Writes.Continuations {
			intent.OperationID, intent.Swap.OperationID = op.ID, op.ID
			m.intents[intent.ID] = intent
		}
		for _, event := range tx.Events {
			event.Seq = api.Sequence(len(m.events) + 1)
			event.OperationID = op.ID
			event.RecordedAt = api.Timestamp(m.clock.at.Format(time.RFC3339Nano))
			m.events = append(m.events, event)
		}
		if len(tx.Events) == 0 {
			// The shared writer retains its operation receipt even when a
			// selection update has no new domain event to announce.
			payload, err := json.Marshal(api.OperationEvent{Operation: op})
			if err != nil {
				m.t.Fatal(err)
			}
			kind := api.EventKind("operation.completed")
			if op.Status == "pending" {
				kind = "operation.accepted"
			}
			m.events = append(m.events, api.Event{Schema: api.SchemaVersion, Config: tx.Scope.Config,
				LifeID: m.lane.LifeID, Run: tx.Internal.Target.Run, Seq: op.FirstSeq,
				Kind: kind, Origin: "service", OperationID: op.ID, Payload: payload,
				Actor: api.Actor{Kind: "service", ID: "test-writer"}, RecordedAt: api.Timestamp(m.clock.at.Format(time.RFC3339Nano))})
		}
		m.operations[op.ID] = op
	}
	if m.after != nil {
		m.after()
	}
	if m.replyOperation != nil {
		op = m.replyOperation(op)
	}
	return api.Commit{Operation: op, FirstSeq: op.FirstSeq, LastSeq: op.LastSeq}, nil
}

// This probe observes the handoff only. Returning the retained test journal
// receipt does not simulate a process, a second run or a successful swap.
type continuationProbe struct {
	store    *journalStore
	requests []api.ContinuationRequest
	err      error
	before   func()
}

func (p *continuationProbe) Continue(_ context.Context, scope api.Scope, request api.ContinuationRequest) (api.Operation, error) {
	p.store.check(scope)
	p.requests = append(p.requests, request)
	if p.before != nil {
		p.before()
	}
	if p.err != nil {
		return api.Operation{}, p.err
	}
	intent, exists := p.store.intents[request.IntentID]
	if !exists || intent.Swap != request.Swap || intent.ExpectedGeneration != request.Swap.ExpectedGeneration ||
		intent.CancellationEpoch != request.Swap.CancellationEpoch || intent.Eligibility.ID != request.Swap.EligibilityID {
		return api.Operation{}, problem(api.CodeIntegrity, "test lifecycle received an unstored or different intent")
	}
	return p.store.operations[intent.OperationID], nil
}

func newJournal(t *testing.T) (*testRig, *journalStore, *continuationProbe) {
	t.Helper()
	r := newRig(t)
	store := &journalStore{readStore: r.store, clock: r.clock,
		intents: map[api.ID]api.ContinuationIntent{}, operations: map[api.ID]api.Operation{}}
	probe := &continuationProbe{store: store}
	r.s.deps.Store, r.s.deps.Lifecycle = store, probe
	return r, store, probe
}

func restartService(t *testing.T, r *testRig) {
	t.Helper()
	s, err := New(r.s.deps)
	if err != nil {
		t.Fatal(err)
	}
	r.s = s
}

func TestIntentHandoff(t *testing.T) {
	r, store, probe := newJournal(t)
	before := store.lane
	op, err := r.s.ObserveLimit(context.Background(), r.signal)
	if err != nil || len(probe.requests) != 1 || store.writeCalls != 1 || op.ID == "" {
		t.Fatal("validated limit did not commit before its internal handoff", err)
	}
	request := probe.requests[0]
	intent := store.intents[request.IntentID]
	if intent.Status != "pending" || intent.Slot != nil || request.Swap.ProfileGrantID != "grant-b" ||
		request.Swap.EligibilityID != r.broker.eligibility.ID || request.Swap.ExpectedGeneration != before.Generation+1 ||
		request.Swap.CancellationEpoch != before.CancellationEpoch || request.Swap.OperationID != op.ID ||
		intent.Eligibility != r.broker.eligibility || r.broker.acquireCalls != 0 || r.launcher.stopCalls != 0 {
		t.Fatal("handoff lost eligibility/epoch/CAS or acquired a loose credential slot")
	}
	after := store.lane
	after.Generation, after.State = before.Generation, before.State
	if !reflect.DeepEqual(after, before) {
		t.Fatal("intent preparation reset counters, budget, task, history, turn or workspace")
	}
	tx := store.transactions[0]
	if len(tx.Compare) != 3 || tx.Compare[0] != (api.Compare{Kind: api.CompareLane, ID: before.LifeID, Generation: before.Generation}) ||
		tx.Compare[1] != (api.Compare{Kind: api.CompareGrants, ID: store.grants.ID, Generation: store.grants.Generation}) ||
		tx.Compare[2] != (api.Compare{Kind: api.CompareContinuation, ID: intent.ID, Generation: 0}) ||
		len(tx.Guards) != 1 || tx.Guards[0].Cancellation == nil ||
		*tx.Guards[0].Cancellation != (api.CancellationCheck{LifeID: before.LifeID, Epoch: before.CancellationEpoch}) {
		t.Fatal("handoff omitted the shared life/grants/absent-intent comparisons or cancellation guard")
	}
	if tx.Internal.Actor != r.s.readScope().Actor || tx.Internal.RequestedBy != store.events[0].RequestedBy ||
		tx.Internal.CauseOperationID != store.events[0].OperationID || tx.Internal.CauseRequestID != store.events[0].RequestID {
		t.Fatal("handoff fabricated its actor or lost its original cause")
	}
	for _, event := range tx.Events {
		if event.Kind == "watchdog.swapped" || event.Kind == "mail.delivered" || event.Actor != r.s.readScope().Actor {
			t.Fatal("intent preparation invented an actual swap/mail completion or borrowed a sender")
		}
	}
}

func TestIntentReplay(t *testing.T) {
	r, store, probe := newJournal(t)
	_, err := r.s.ObserveLimit(context.Background(), r.signal)
	if err != nil {
		t.Fatal(err)
	}
	first := probe.requests[0]
	roomReads := len(r.broker.checked)
	r.clock.at = r.clock.at.Add(10 * time.Second)
	restartService(t, r)
	for _, call := range []func() (api.Operation, error){
		func() (api.Operation, error) { return r.s.ObserveLimit(context.Background(), r.signal) },
		func() (api.Operation, error) { return r.s.Reconcile(context.Background(), r.signal.Target) },
	} {
		if _, err := call(); err != nil {
			t.Fatal("restart did not recover the same stored intent", err)
		}
	}
	if store.writeCalls != 1 || len(r.broker.checked) != roomReads || len(probe.requests) != 3 {
		t.Fatal("replay reassessed/minted a second intent or lost the handoff")
	}
	for _, request := range probe.requests {
		if request != first {
			t.Fatal("recovery changed the claim identity or selected profile")
		}
	}
	changed := r.signal
	changed.CaptureID = "another-capture"
	_, err = r.s.ObserveLimit(context.Background(), changed)
	requireCode(t, err, api.CodeConflict)
}

func TestLostContinuationReply(t *testing.T) {
	r, store, probe := newJournal(t)
	wanted := problem(api.CodeDeadline, "test lifecycle reply was lost")
	probe.err = wanted
	_, err := r.s.ObserveLimit(context.Background(), r.signal)
	if err != wanted || store.writeCalls != 1 || len(probe.requests) != 1 {
		t.Fatal("lost continuation reply did not preserve its durable intent", err)
	}
	request := probe.requests[0]
	probe.err = nil
	restartService(t, r)
	if _, err := r.s.Reconcile(context.Background(), r.signal.Target); err != nil || len(probe.requests) != 2 ||
		probe.requests[1] != request || store.writeCalls != 1 || r.broker.acquireCalls != 0 {
		t.Fatal("lost-reply recovery minted another claim or slot", err)
	}
}

func TestWaitJournal(t *testing.T) {
	r, store, probe := newJournal(t)
	room := r.broker.rooms["profile-b"]
	room.Available = false
	r.broker.rooms["profile-b"] = room
	before := store.lane
	op, err := r.s.ObserveLimit(context.Background(), r.signal)
	if err != nil || op.ID == "" || store.lane.State != "profile_wait" || len(probe.requests) != 0 {
		t.Fatal("no-room did not create an actual durable wait", err)
	}
	wait := func(delay int64) {
		t.Helper()
		var payload api.WatchdogEvent
		last := store.events[len(store.events)-1]
		if err := json.Unmarshal(last.Payload, &payload); err != nil || last.Kind != "watchdog.waiting" ||
			payload.RetryAfterMS != delay || payload.Signal == nil || !reflect.DeepEqual(*payload.Signal, r.signal) {
			t.Fatal("wait did not retain its limit and exact bounded delay", err)
		}
	}
	wait(5000)
	reads := len(r.broker.checked)
	restartService(t, r)
	_, err = r.s.ObserveLimit(context.Background(), r.signal)
	requireCode(t, err, api.CodeUnavailable)
	if store.writeCalls != 1 || len(r.broker.checked) != reads {
		t.Fatal("repeated signal reset its delay or polled early")
	}
	r.clock.at = r.clock.at.Add(5 * time.Second)
	if _, err := r.s.Reconcile(context.Background(), r.signal.Target); err != nil {
		t.Fatal(err)
	}
	wait(10000)
	r.clock.at = r.clock.at.Add(10 * time.Second)
	room.Available = true
	r.broker.rooms["profile-b"] = room
	if _, err := r.s.Reconcile(context.Background(), r.signal.Target); err != nil || len(probe.requests) != 1 {
		t.Fatal("restored room did not hand off one persisted intent", err)
	}
	if store.writeCalls != 3 || store.lane.Run != before.Run || store.lane.Session != before.Session ||
		store.lane.Task != before.Task || store.lane.Counters != before.Counters || store.lane.BudgetRemaining != before.BudgetRemaining {
		t.Fatal("wait/restoration changed run/history/task/counters/budget before lifecycle")
	}
}

func TestCancelJournal(t *testing.T) {
	for _, phase := range []string{"waiting", "pending", "claimed"} {
		t.Run(phase, func(t *testing.T) {
			r, store, probe := newJournal(t)
			if phase == "waiting" {
				room := r.broker.rooms["profile-b"]
				room.Available = false
				r.broker.rooms["profile-b"] = room
			}
			if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
				t.Fatal(err)
			}
			if phase == "claimed" {
				id := r.s.intentID(r.signal.Target)
				intent := store.intents[id]
				intent.Status = phase
				store.intents[id] = intent
			}
			requests := len(probe.requests)
			before := store.lane
			if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil {
				t.Fatal(err)
			}
			written := store.transactions[len(store.transactions)-1].Writes.Continuations[0]
			if written.OperationID != "" || written.Swap.OperationID != "" ||
				written.ExpectedGeneration != written.Swap.ExpectedGeneration || written.CancellationEpoch != written.Swap.CancellationEpoch {
				t.Fatal("cancel copied/guessed operation IDs or submitted stale Swap fences")
			}
			if store.lane.CancellationEpoch != before.CancellationEpoch+1 || store.lane.Generation != before.Generation+1 ||
				store.lane.Counters != before.Counters || store.lane.BudgetRemaining != before.BudgetRemaining || store.lane.State != "verifying" {
				t.Fatal("cancel did not durably advance the epoch without resetting task accounting")
			}
			restartService(t, r)
			_, err := r.s.Reconcile(context.Background(), r.signal.Target)
			requireCode(t, err, api.CodeCancelled)
			_, err = r.s.ObserveLimit(context.Background(), r.signal)
			requireCode(t, err, api.CodeCancelled)
			writes := store.writeCalls
			if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil || store.writeCalls != writes ||
				len(probe.requests) != requests || r.broker.acquireCalls != 0 {
				t.Fatal("cancel replay mutated again or restarted continuation", err)
			}
		})
	}
}

func TestWaitEpoch(t *testing.T) {
	r, store, probe := newJournal(t)
	room := r.broker.rooms["profile-b"]
	room.Available = false
	r.broker.rooms["profile-b"] = room
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	store.lane.CancellationEpoch++ // Independent manual-control commit.
	r.clock.at = r.clock.at.Add(5 * time.Second)
	room.Available = true
	r.broker.rooms["profile-b"] = room
	_, err := r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeCancelled)
	if store.writeCalls != 1 || len(probe.requests) != 0 {
		t.Fatal("wait was reauthorized under a later cancellation epoch")
	}
}

func TestCommitCAS(t *testing.T) {
	for _, name := range []string{"life", "epoch", "intent", "grants"} {
		t.Run(name, func(t *testing.T) {
			r, store, probe := newJournal(t)
			store.before = func() {
				switch name {
				case "life":
					store.lane.Generation++
				case "epoch":
					store.lane.CancellationEpoch++
				case "grants":
					store.grants.Generation++
				case "intent":
					id := r.s.intentID(r.signal.Target)
					store.intents[id] = api.ContinuationIntent{ID: id, Generation: 1}
				}
			}
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			code := api.CodeConflict
			if name == "epoch" {
				code = api.CodeCancelled
			}
			requireCode(t, err, code)
			if len(probe.requests) != 0 || r.broker.acquireCalls != 0 {
				t.Fatal("lost shared CAS/epoch proceeded to continuation")
			}
		})
	}
}

func TestJournalFailures(t *testing.T) {
	for _, name := range []string{"lookup", "commit", "missing-write"} {
		t.Run(name, func(t *testing.T) {
			r, store, probe := newJournal(t)
			wanted := api.NotImplemented("dependency", name)
			switch name {
			case "lookup":
				store.lookupError = wanted
			case "commit":
				store.fail = wanted
			default:
				store.omitWrite = true
			}
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			if name == "missing-write" {
				requireCode(t, err, api.CodeIntegrity)
			} else if err != wanted {
				t.Fatal("journal error was swallowed or converted to a successful operation", err)
			}
			if len(probe.requests) != 0 || r.broker.acquireCalls != 0 {
				t.Fatal("failed journal launched or leased a replacement")
			}
		})
	}
}

func TestClaimRecovery(t *testing.T) {
	r, store, probe := newJournal(t)
	probe.err = problem(api.CodeDeadline, "test claim reply interrupted")
	_, err := r.s.ObserveLimit(context.Background(), r.signal)
	requireCode(t, err, api.CodeDeadline)
	request := probe.requests[0]
	intent := store.intents[request.IntentID]
	intent.Status = "claimed"
	intent.Slot = &api.CredentialSlot{ID: "slot-owned", LeaseID: "lease-owned", ProfileGrantID: "grant-b", ProfileID: "profile-b"}
	store.intents[intent.ID] = intent
	store.lane.Run++
	store.lane.Generation++
	store.lane.ProfileGrantID = "grant-b"
	reads := len(r.broker.checked)
	r.clock.at = r.clock.at.Add(2 * time.Hour)
	restartService(t, r)
	probe.err = nil
	if _, err := r.s.Reconcile(context.Background(), r.signal.Target); err != nil || len(probe.requests) != 2 ||
		probe.requests[1] != request || store.intents[intent.ID].Slot != intent.Slot ||
		len(r.broker.checked) != reads || r.broker.acquireCalls != 0 || store.writeCalls != 1 {
		t.Fatal("claimed-slot recovery changed the claim, reacquired or reassessed", err)
	}
	store.lane.CancellationEpoch++
	_, err = r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeCancelled)
	if len(probe.requests) != 2 {
		t.Fatal("revoked claim was sent back to lifecycle")
	}
}

func TestCompletedReplay(t *testing.T) {
	r, store, probe := newJournal(t)
	operation, err := r.s.ObserveLimit(context.Background(), r.signal)
	if err != nil {
		t.Fatal(err)
	}
	id := probe.requests[0].IntentID
	intent := store.intents[id]
	intent.Status = "completed"
	store.intents[id] = intent
	operation.Status = "succeeded"
	store.operations[operation.ID] = operation
	restartService(t, r)
	replay, err := r.s.Reconcile(context.Background(), r.signal.Target)
	if err != nil || replay != operation || len(probe.requests) != 1 || store.writeCalls != 1 {
		t.Fatal("completed intent did not return its retained operation without another continuation", err)
	}
	unfinished := operation
	unfinished.Status = "pending"
	store.operations[operation.ID] = unfinished
	_, err = r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeInvalid)
	wanted := problem(api.CodeUnavailable, "test operation unavailable")
	store.operationErr = wanted
	if _, err := r.s.Reconcile(context.Background(), r.signal.Target); err != wanted {
		t.Fatal("completed replay fabricated a receipt during a store outage", err)
	}
}

func TestCommitRecovery(t *testing.T) {
	for _, phase := range []string{"claimed", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			r, store, probe := newJournal(t)
			store.after = func() {
				id := r.s.intentID(r.signal.Target)
				intent := store.intents[id]
				intent.Generation++
				intent.Status = phase
				store.lane.Generation++
				if phase == "claimed" {
					intent.Slot = &api.CredentialSlot{ID: "slot-claimed", LeaseID: "lease-claimed"}
					store.lane.Run++
					store.lane.ProfileGrantID = "grant-b"
				} else {
					store.lane.CancellationEpoch++
					intent.CancellationEpoch = store.lane.CancellationEpoch
					intent.ExpectedGeneration = store.lane.Generation
				}
				store.intents[id] = intent
			}
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			if phase == "claimed" {
				if err != nil || len(probe.requests) != 1 {
					t.Fatal("a newer legitimate claim was mistaken for a missing commit", err)
				}
			} else {
				requireCode(t, err, api.CodeCancelled)
				if len(probe.requests) != 0 {
					t.Fatal("a cancellation between commit and read-back was bypassed")
				}
			}
			if store.writeCalls != 1 || r.broker.acquireCalls != 0 {
				t.Fatal("read-back race overwrote the newer intent or acquired another slot")
			}
		})
	}
}

func TestOperationBinding(t *testing.T) {
	r, store, probe := newJournal(t)
	probe.before = func() {
		for id, operation := range store.operations {
			operation.ID = "another-operation"
			store.operations[id] = operation
		}
	}
	_, err := r.s.ObserveLimit(context.Background(), r.signal)
	requireCode(t, err, api.CodeInvalid)
	if len(probe.requests) != 1 || r.broker.acquireCalls != 0 {
		t.Fatal("bad operation receipt did not reach the single internal handoff")
	}
}

func TestEligibilityReceipts(t *testing.T) {
	for _, name := range []string{"excluded", "model", "history", "grant", "expired", "missing-proof"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			switch name {
			case "excluded":
				r.broker.eligibility.Compatible = false
			case "model":
				r.broker.eligibility.Request.Model = "claude-opus-4-6"
			case "history":
				r.broker.eligibility.Request.HistoryID = "another-history"
			case "grant":
				r.broker.eligibility.Request.ToGrantID = "ungranted"
			case "expired":
				r.broker.eligibility.ExpiresAt = r.signal.ObservedAt
			case "missing-proof":
				r.broker.eligibility.Evidence = api.BlobRef{}
			}
			plan, err := r.s.assess(context.Background(), r.signal)
			if name == "excluded" {
				if err != nil || plan.Swap != nil || r.broker.eligibilityCalls != 1 {
					t.Fatal("excluded model/profile was selected or misrepresented as a worker outage", err)
				}
			} else {
				requireCode(t, err, api.CodeIntegrity)
			}
			r.noEffects()
		})
	}
}

func TestTurnSnapshot(t *testing.T) {
	t.Run("task", func(t *testing.T) {
		r := newRig(t)
		r.store.turn.Task.SHA256 = digest([]byte("another task"))
		_, err := r.s.assess(context.Background(), r.signal)
		requireCode(t, err, api.CodeIntegrity)
		r.noEffects()
	})
	t.Run("status", func(t *testing.T) {
		for _, status := range []string{"completed", "failed", "cancelled", "", "unknown"} {
			t.Run(status, func(t *testing.T) {
				r := newRig(t)
				r.store.turn.Status = status
				_, err := r.s.assess(context.Background(), r.signal)
				requireCode(t, err, api.CodeConflict)
				r.noEffects()
			})
		}
	})
}
