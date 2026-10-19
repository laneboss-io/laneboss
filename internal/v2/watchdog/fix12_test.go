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

// helper_open may commit lane.resumed then the run's own lane.turn. A later
// mail_deliver turn announcement has the same identity and must also survive.
// This test was authored before changing the sequence-only control guard.
func TestOwnTurnAfterLaunch(t *testing.T) {
	r, store, probe := newJournal(t)
	store.events[0].Kind = "lane.resumed"
	r.addEvent("lane.turn", api.TurnEvent{Task: store.lane.Task, Status: "running"})
	last := len(store.events) - 1
	turn := store.events[last]
	turn.LogicalTurnID = store.lane.LogicalTurnID
	store.events = append(store.events[:1], append([]api.Event{turn}, store.events[1:last]...)...)
	for i := range store.events {
		store.events[i].Seq = api.Sequence(i + 1)
	}
	store.captureState.LastSeq = store.events[len(store.events)-1].Seq
	if store.events[1].Run != r.signal.Target.Run || store.events[1].LogicalTurnID != store.lane.LogicalTurnID ||
		store.events[1].Seq <= store.events[0].Seq {
		t.Fatal("normal-path fixture lost its same-run same-turn launch ordering")
	}
	operation, err := r.s.ObserveLimit(context.Background(), r.signal)
	if err != nil || operation.ID == "" || store.writeCalls != 1 || len(probe.requests) != 1 {
		t.Fatal("own turn after launch incorrectly cancelled its continuation", err)
	}
	if probe.requests[0].Swap.LogicalTurnID != turn.LogicalTurnID || r.broker.acquireCalls != 0 {
		t.Fatal("own turn continuation changed its identity or acquired a loose slot")
	}
}

func (r *testRig) freshSelectionReceipts() *int {
	r.t.Helper()
	r.broker.onRoom = func(grant api.ProfileGrant) {
		room := r.broker.rooms[grant.ProfileID]
		room.CheckedAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
		room.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Minute).Format(time.RFC3339Nano))
		data, err := json.Marshal(room)
		if err != nil {
			r.t.Fatal(err)
		}
		room.Evidence = r.addClassBlob(api.ID(fmt.Sprintf("fresh-room-%d", len(r.broker.checked))), data, "artifact")
		r.broker.rooms[grant.ProfileID] = room
	}
	r.broker.onEligibility = func() {
		r.broker.eligibility.ID = "fresh-eligibility"
		r.broker.eligibility.CheckedAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
		r.broker.eligibility.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Minute).Format(time.RFC3339Nano))
	}
	calls := 0
	r.broker.usageRead = func(_ context.Context, scope api.Scope, request api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
		r.store.check(scope)
		original := r.store.usage[r.signal.UsageEvidence.ID]
		if request.Target != r.signal.Target || request.LaunchID != r.store.launch.ID || request.OperationID != r.store.events[0].OperationID ||
			request.ProfileGrantID != r.store.lane.ProfileGrantID || request.ProfileID != r.signal.ProfileID || request.Provider != r.signal.Provider ||
			request.RunEndedAt != r.launcher.observation.ObservedAt || request.Executable != original.Executable || request.RuntimeManifest != original.RuntimeManifest {
			r.t.Fatal("usage refresh lost its actual causing run, profile, exit or enrollment pins")
		}
		calls++
		evidence, provenance := r.usageFixture(api.ID(fmt.Sprintf("fresh-usage-%d", calls)))
		r.retainUsage(evidence, provenance)
		return evidence, nil
	}
	return &calls
}

func TestPendingReassessment(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		t.Run(map[bool]string{false: "progress", true: "claim-wins"}[claimed], func(t *testing.T) {
			r, store, probe := newJournal(t)
			probe.err = problem(api.CodeDeadline, "pending reply interrupted")
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			requireCode(t, err, api.CodeDeadline)
			original := probe.requests[0]
			before := store.intents[original.IntentID]
			turnBefore := store.turn
			r.clock.at = r.clock.at.Add(31 * time.Second)
			usageReads := r.freshSelectionReceipts()
			probe.err = nil
			if claimed {
				store.before = func() {
					intent := store.intents[before.ID]
					intent.Status, intent.Generation = "claimed", intent.Generation+1
					intent.Slot = &api.CredentialSlot{ID: "claimed-slot", LeaseID: "claimed-lease"}
					store.intents[intent.ID] = intent
				}
			}
			operation, err := r.s.Reconcile(context.Background(), r.signal.Target)
			if claimed {
				requireCode(t, err, api.CodeConflict)
				if len(probe.requests) != 1 || store.intents[before.ID].Status != "claimed" || store.intents[before.ID].Slot == nil {
					t.Fatal("reassessment overwrote the winning continuation claim")
				}
			} else {
				if err != nil || len(probe.requests) != 2 || probe.requests[1] == original || operation.ID == before.OperationID ||
					store.intents[before.ID].Generation != before.Generation+1 || probe.requests[1].Swap.Limit.UsageEvidence == nil ||
					*probe.requests[1].Swap.Limit.UsageEvidence == *original.Swap.Limit.UsageEvidence {
					t.Fatal("expired pending intent did not progress with newly measured receipts", err)
				}
				if !sameLimitCause(original.Swap.Limit, probe.requests[1].Swap.Limit) {
					t.Fatal("fresh usage evidence changed the original causing limit")
				}
			}
			if store.writeCalls != 2 || *usageReads != 1 || r.broker.acquireCalls != 0 ||
				store.transactions[1].Compare[2].Generation != before.Generation || !reflect.DeepEqual(store.turn, turnBefore) {
				t.Fatal("reassessment lost continuation CAS, measured refresh or slot ownership")
			}
		})
	}
}

func TestTurnRunScope(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-run", true: "same-turn-next-run"}[newer], func(t *testing.T) {
			r := newRig(t)
			r.addEvent("lane.turn", api.TurnEvent{Task: r.store.lane.Task, Status: "running"})
			last := len(r.store.events) - 1
			r.store.events[last].LogicalTurnID = "historical-turn"
			r.store.events[last].Run--
			if newer {
				r.store.events[last].LogicalTurnID = r.store.lane.LogicalTurnID
				r.store.events[last].Run = r.signal.Target.Run + 1
			}
			if _, err := runEvidence(r.store.events, r.signal, r.store.lane.LogicalTurnID); err != nil {
				t.Fatal("historical run or continued same turn superseded the causing turn", err)
			}
			r.noEffects()
		})
	}
}

func TestPendingMalformed(t *testing.T) {
	for _, fault := range []string{"profile", "future"} {
		t.Run(fault, func(t *testing.T) {
			r, store, probe := newJournal(t)
			if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
				t.Fatal(err)
			}
			id := probe.requests[0].IntentID
			intent := store.intents[id]
			if fault == "profile" {
				intent.Swap.Room.ProfileID = "foreign-profile"
			} else {
				intent.Swap.Room.CheckedAt = api.Timestamp(r.clock.at.Add(time.Second).Format(time.RFC3339Nano))
			}
			store.intents[id] = intent
			reads := len(r.broker.checked)
			_, err := r.s.Reconcile(context.Background(), r.signal.Target)
			requireCode(t, err, api.CodeIntegrity)
			if len(r.broker.checked) != reads || store.writeCalls != 1 || len(probe.requests) != 1 {
				t.Fatal("malformed pending receipt was treated as renewable expiry")
			}
		})
	}
}
