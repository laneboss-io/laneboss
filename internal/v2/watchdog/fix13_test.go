package watchdog

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Authored before changing production code: a policy publish inside the
// original no-room backoff must not strand the retained waiting intent.
func TestWaitingPolicyBackoff(t *testing.T) {
	r, store, probe := newJournal(t)
	room := r.broker.rooms["profile-b"]
	room.Available = false
	r.broker.rooms["profile-b"] = room
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	id := r.s.intentID(r.signal.Target)
	before, life := store.intents[id], store.lane
	if before.Status != "waiting" || before.ExpectedGeneration != life.Generation || store.writeCalls != 1 {
		t.Fatal("no-room fixture did not retain its original wait and life fence")
	}
	reads := len(r.broker.checked)
	r.advancePolicy()
	r.clock.at = r.clock.at.Add(time.Second)
	for _, early := range []func() (api.Operation, error){
		func() (api.Operation, error) { return r.s.ObserveLimit(context.Background(), r.signal) },
		func() (api.Operation, error) { return r.s.Reconcile(context.Background(), r.signal.Target) },
	} {
		_, err := early()
		requireCode(t, err, api.CodeUnavailable)
		if !reflect.DeepEqual(store.lane, life) || !reflect.DeepEqual(store.intents[id], before) ||
			len(store.policyRefreshes) != 0 || store.writeCalls != 1 || len(r.broker.checked) != reads || len(probe.requests) != 0 {
			t.Fatal("backoff retry advanced policy or stranded the waiting intent's life fence")
		}
	}
	r.clock.at = r.clock.at.Add(4 * time.Second)
	operation, err := r.s.Reconcile(context.Background(), r.signal.Target)
	if err != nil {
		t.Fatal("wait could not progress after policy publish and its original deadline", err)
	}
	current := store.intents[id]
	if store.writeCalls != 2 || len(store.policyRefreshes) != 1 || store.lane.PolicyGeneration != store.policy.Generation ||
		current.Status != "waiting" || current.Generation != before.Generation+1 || current.ExpectedGeneration != store.lane.Generation ||
		current.Swap.ExpectedGeneration != store.lane.Generation || current.OperationID != operation.ID || operation.ID == before.OperationID ||
		store.transactions[1].Compare[0].Generation != life.Generation+1 || store.transactions[1].Compare[2].Generation != before.Generation ||
		len(probe.requests) != 0 || r.broker.acquireCalls != 0 {
		t.Fatal("expired wait did not refresh once and commit consistent current fences")
	}
}

func TestRefusedLimitPolicyStable(t *testing.T) {
	for _, fault := range []string{"capture", "usage", "room"} {
		t.Run(fault, func(t *testing.T) {
			r := newRig(t)
			before := r.store.lane
			r.advancePolicy()
			code := api.CodeIntegrity
			switch fault {
			case "capture":
				r.runner.none = true
			case "usage":
				evidence, provenance := r.usageFixture("refused-usage")
				evidence.ProducerGeneration = "foreign-producer"
				ref := r.retainUsage(evidence, provenance)
				r.signal.UsageEvidence = &ref
				code = api.CodeInvalid
			case "room":
				room := r.broker.rooms["profile-a"]
				room.Available = true
				r.broker.rooms["profile-a"] = room
				code = api.CodeConflict
			}
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			requireCode(t, err, code)
			if !reflect.DeepEqual(r.store.lane, before) || len(r.store.policyRefreshes) != 0 {
				t.Fatal("refused limit advanced the live policy projection")
			}
			r.noEffects()
		})
	}
}

func TestPendingUsageAge(t *testing.T) {
	for _, age := range []time.Duration{30 * time.Second, 50 * time.Second} {
		t.Run(map[bool]string{false: "fresh-boundary", true: "expired"}[age > 30*time.Second], func(t *testing.T) {
			r, store, probe := newJournal(t)
			for id, room := range r.broker.rooms {
				room.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Minute).Format(time.RFC3339Nano))
				r.broker.rooms[id] = room
			}
			r.broker.eligibility.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Minute).Format(time.RFC3339Nano))
			probe.err = problem(api.CodeDeadline, "pending reply interrupted")
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			requireCode(t, err, api.CodeDeadline)
			original := probe.requests[0]
			oldRef := *original.Swap.Limit.UsageEvidence
			oldBytes := append([]byte{}, store.blobs[oldRef.ID]...)
			r.clock.at = r.clock.at.Add(age)
			usageReads := r.freshSelectionReceipts()
			maximumWrites := 1
			if age > 30*time.Second {
				maximumWrites = 2
			}
			// Assert the write bound during the call too: an incorrect age
			// boundary can recursively reassess without returning to the
			// final assertions below while this injected clock stays fixed.
			store.before = func() {
				if store.writeCalls > maximumWrites {
					t.Fatalf("pending usage age %s exceeded its journal write bound: got %d, want at most %d", age, store.writeCalls, maximumWrites)
				}
			}
			probe.err = nil
			_, err = r.s.Reconcile(context.Background(), r.signal.Target)
			if err != nil || len(probe.requests) != 2 || r.broker.acquireCalls != 0 {
				t.Fatal("pending usage age did not retain a safe continuation path", err)
			}
			if age > 30*time.Second {
				if *usageReads != 1 || store.writeCalls != 2 || probe.requests[1] == original ||
					*probe.requests[1].Swap.Limit.UsageEvidence == oldRef {
					t.Fatal("stale pending usage was dispatched instead of remeasured under CAS")
				}
			} else if *usageReads != 0 || store.writeCalls != 1 || probe.requests[1] != original {
				t.Fatal("thirty-second usage boundary unnecessarily replaced the retained intent")
			}
			if !bytes.Equal(oldBytes, store.blobs[oldRef.ID]) || digest(store.blobs[oldRef.ID]) != oldRef.SHA256 {
				t.Fatal("usage refresh rewrote or relabelled the stale immutable envelope")
			}
		})
	}
}

func TestPendingPolicyRefusalStable(t *testing.T) {
	r, store, probe := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	life := store.lane
	before := store.intents[probe.requests[0].IntentID]
	r.advancePolicy()
	r.runner.none = true
	_, err := r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeIntegrity)
	if !reflect.DeepEqual(store.lane, life) || !reflect.DeepEqual(store.intents[before.ID], before) ||
		len(store.policyRefreshes) != 0 || store.writeCalls != 1 || len(probe.requests) != 1 || r.broker.acquireCalls != 0 {
		t.Fatal("pending policy drift wrote a life fence before validating its fresh plan")
	}
}

func TestPendingUsageEnvelope(t *testing.T) {
	for _, fault := range []string{"future", "target"} {
		t.Run(fault, func(t *testing.T) {
			r, store, probe := newJournal(t)
			if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
				t.Fatal(err)
			}
			evidence, provenance := r.usageFixture("pending-envelope")
			if fault == "future" {
				evidence.ObservedAt = api.Timestamp(r.clock.at.Add(time.Second).Format(time.RFC3339Nano))
			} else {
				evidence.Target.Run++
			}
			ref := r.retainUsage(evidence, provenance)
			id := probe.requests[0].IntentID
			intent := store.intents[id]
			intent.Swap.Limit.UsageEvidence = &ref
			store.intents[id] = intent
			reads := len(r.broker.checked)
			_, err := r.s.Reconcile(context.Background(), r.signal.Target)
			requireCode(t, err, api.CodeIntegrity)
			if store.writeCalls != 1 || len(probe.requests) != 1 || len(r.broker.checked) != reads || r.broker.acquireCalls != 0 {
				t.Fatal("invalid retained usage envelope was dispatched or treated as renewable age")
			}
		})
	}
}
