package watchdog

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPendingFreshness(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func(*testRig, *journalStore)
		code api.ErrorCode
	}{
		{"room", func(r *testRig, store *journalStore) {
			id := r.s.intentID(r.signal.Target)
			intent := store.intents[id]
			intent.Eligibility.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Minute).Format(time.RFC3339Nano))
			intent.Swap.Room.ExpiresAt = api.Timestamp(r.clock.at.Add(5 * time.Second).Format(time.RFC3339Nano))
			store.intents[id] = intent
			room := r.broker.rooms["profile-a"]
			room.ExpiresAt = intent.Swap.Room.ExpiresAt
			r.broker.rooms["profile-a"] = room
			r.clock.at = r.clock.at.Add(6 * time.Second)
		}, api.CodeIntegrity},
		{"eligibility", func(r *testRig, store *journalStore) {
			id := r.s.intentID(r.signal.Target)
			intent := store.intents[id]
			intent.Swap.Room.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Minute).Format(time.RFC3339Nano))
			intent.Eligibility.ExpiresAt = api.Timestamp(r.clock.at.Add(5 * time.Second).Format(time.RFC3339Nano))
			store.intents[id] = intent
			room := r.broker.rooms["profile-a"]
			room.ExpiresAt = intent.Eligibility.ExpiresAt
			r.broker.rooms["profile-a"] = room
			r.clock.at = r.clock.at.Add(6 * time.Second)
		}, api.CodeIntegrity},
		{"outage", func(r *testRig, store *journalStore) {
			expires := api.Timestamp(r.clock.at.Add(3 * time.Hour).Format(time.RFC3339Nano))
			store.grants.ExpiresAt = expires
			for i := range store.grants.Profiles {
				store.grants.Profiles[i].ExpiresAt = expires
			}
			r.grants.grants = store.grants
			r.broker.grants = store.grants.Profiles
			r.clock.at = r.clock.at.Add(2 * time.Hour)
		}, api.CodeIntegrity},
		{"clock-during-read", func(r *testRig, store *journalStore) {
			id := r.s.intentID(r.signal.Target)
			intent := store.intents[id]
			intent.Swap.Room.ExpiresAt = api.Timestamp(r.clock.at.Add(5 * time.Second).Format(time.RFC3339Nano))
			store.intents[id] = intent
			room := r.broker.rooms["profile-a"]
			room.ExpiresAt = intent.Swap.Room.ExpiresAt
			r.broker.rooms["profile-a"] = room
			lastRead := store.laneReads + 2
			store.onLane = func(reads int) {
				if reads == lastRead {
					r.clock.at = r.clock.at.Add(6 * time.Second)
				}
			}
		}, api.CodeIntegrity},
		{"grant-set", func(r *testRig, store *journalStore) {
			store.grants.ExpiresAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
			r.grants.grants = store.grants
		}, api.CodeForbidden},
		{"from-grant", func(r *testRig, store *journalStore) {
			store.grants.Profiles[0].ExpiresAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
			r.grants.grants = store.grants
		}, api.CodeForbidden},
		{"to-grant", func(r *testRig, store *journalStore) {
			store.grants.Profiles[1].ExpiresAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
			r.grants.grants = store.grants
		}, api.CodeForbidden},
		{"revalidation", func(r *testRig, _ *journalStore) { r.grants.change = true }, api.CodeConflict},
		{"policy", func(_ *testRig, store *journalStore) { store.policy.ProfileExclusions = []api.ID{"profile-b"} }, api.CodeForbidden},
	} {
		t.Run(row.name, func(t *testing.T) {
			r, store, probe := newJournal(t)
			probe.err = problem(api.CodeDeadline, "selection committed but no claim reply")
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			requireCode(t, err, api.CodeDeadline)
			if len(probe.requests) != 1 {
				t.Fatal("control did not reach the initial lifecycle handoff")
			}
			row.edit(r, store)
			before := store.intents[r.s.intentID(r.signal.Target)]
			reads := len(r.broker.checked)
			probe.err = nil
			restartService(t, r)
			_, err = r.s.Reconcile(context.Background(), r.signal.Target)
			requireCode(t, err, row.code)
			newChecks := 0
			if row.code == api.CodeIntegrity {
				newChecks = 1
			}
			if len(probe.requests) != 1 || store.writeCalls != 1 || len(r.broker.checked) != reads+newChecks ||
				r.broker.acquireCalls != 0 || !reflect.DeepEqual(store.intents[before.ID], before) {
				t.Fatal("expired pending receipt did not reassess once or resubmitted its old Swap")
			}
		})
	}
}

func TestCancelWithoutLiveIntent(t *testing.T) {
	for _, phase := range []string{"absent", "completed", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			r, store, probe := newJournal(t)
			if phase != "absent" {
				if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
					t.Fatal(err)
				}
				id := r.s.intentID(r.signal.Target)
				intent := store.intents[id]
				intent.Status = phase
				store.intents[id] = intent
			}
			before, writes, requests := store.lane, store.writeCalls, len(probe.requests)
			intent := store.intents[r.s.intentID(r.signal.Target)]
			if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(store.lane, before) || store.writeCalls != writes || len(probe.requests) != requests ||
				!reflect.DeepEqual(store.intents[r.s.intentID(r.signal.Target)], intent) {
				t.Fatal("cancel rewrote a life or an absent/terminal intent")
			}
		})
	}
}

func TestCancelledIntentPriority(t *testing.T) {
	r, store, probe := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil {
		t.Fatal(err)
	}
	// The durable terminal intent is sufficient to refuse even when current
	// lane/event reads are unavailable. No projection or marker is erased.
	store.readError = problem(api.CodeUnavailable, "current life read interrupted")
	_, err := r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeCancelled)
	if store.writeCalls != 2 || len(probe.requests) != 1 || r.broker.acquireCalls != 0 {
		t.Fatal("terminal replay depended on another read/write or continued again")
	}
}

func TestCancelClaimedNextRun(t *testing.T) {
	r, store, probe := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	id := r.s.intentID(r.signal.Target)
	intent := store.intents[id]
	intent.Status = "claimed"
	intent.Slot = &api.CredentialSlot{ID: "owned-slot", LeaseID: "owned-lease"}
	store.intents[id] = intent
	store.lane.Run++
	store.lane.Generation++
	store.lane.State = "running"
	store.lane.ProfileGrantID = "grant-b"
	before := store.lane
	if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil {
		t.Fatal(err)
	}
	cancelled := store.intents[id]
	if cancelled.Status != "cancelled" || cancelled.Slot != intent.Slot || store.lane.Run != before.Run ||
		!reflect.DeepEqual(store.lane, before) || len(store.transactions[1].Writes.Lanes) != 0 ||
		cancelled.Swap.ExpectedGeneration != store.lane.Generation || cancelled.Swap.CancellationEpoch != store.lane.CancellationEpoch ||
		cancelled.OperationID != cancelled.Swap.OperationID || cancelled.OperationID == intent.OperationID ||
		len(probe.requests) != 1 || r.launcher.stopCalls != 0 || r.broker.acquireCalls != 0 {
		t.Fatal("claimed next-run cancel lost its fences, slot or actual running process state")
	}
	if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil || store.writeCalls != 2 {
		t.Fatal("replayed old-run cancellation rewrote its terminal intent", err)
	}
}

func TestCancelAdvancedEpoch(t *testing.T) {
	r, store, _ := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	store.lane.Generation++
	store.lane.CancellationEpoch++
	store.lane.State = "stopping"
	before := store.lane
	if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, store.lane) || len(store.transactions[1].Writes.Lanes) != 0 ||
		store.intents[r.s.intentID(r.signal.Target)].Status != "cancelled" {
		t.Fatal("cancel double-bumped a manual control's already committed life fence")
	}
}

func TestCancelUnsettledControl(t *testing.T) {
	r, store, _ := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	store.lane.Generation++
	store.lane.CancellationEpoch++
	before := store.lane
	err := r.s.Cancel(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeConflict)
	if !reflect.DeepEqual(before, store.lane) || store.writeCalls != 1 ||
		store.intents[r.s.intentID(r.signal.Target)].Status != "pending" {
		t.Fatal("incomplete manual control was reported as a successful cancelled wait or double-bumped")
	}
}

func TestPendingControl(t *testing.T) {
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
			requests, reads := len(probe.requests), len(r.broker.checked)
			r.addEvent("watchdog.cancelled", api.WatchdogEvent{Reason: "manual control"})
			last := len(store.events) - 1
			store.events[last].Actor = api.Actor{Kind: "human", ID: "controller"}
			store.events[last].Run = 0
			_, err := r.s.Reconcile(context.Background(), r.signal.Target)
			requireCode(t, err, api.CodeCancelled)
			if len(probe.requests) != requests || len(r.broker.checked) != reads || store.writeCalls != 1 {
				t.Fatal("durable recovery ignored life-scoped manual cancellation")
			}
		})
	}
}

func TestControlActorsAndScope(t *testing.T) {
	for _, kind := range []api.EventKind{"watchdog.cancelled", "grants.revoked", "lane.stopping", "lane.cleaned", "lane.lost", "lane.state", "lane.turn"} {
		for _, actor := range []string{"human", "lane", "service", "worker", "scheduler", "watchdog"} {
			for _, runZero := range []bool{false, true} {
				t.Run(string(kind)+"/"+actor+"/"+map[bool]string{true: "life", false: "run"}[runZero], func(t *testing.T) {
					r := newRig(t)
					r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: 5000})
					var payload any = api.WatchdogEvent{Reason: "manual control"}
					switch kind {
					case "lane.state":
						payload = api.StateEvent{From: "profile_wait", To: "accepted"}
					case "lane.stopping":
						payload = api.StateEvent{From: "profile_wait", To: "stopping"}
					case "lane.turn":
						payload = api.TurnEvent{Task: r.store.lane.Task, Status: "running"}
					case "lane.cleaned":
						payload = api.CleanEvent{Quiescence: r.launcher.observation}
					case "lane.lost":
						payload = api.RunEndEvent{LaunchID: r.store.lane.LaunchID, Reason: "lost", Observation: r.launcher.observation}
					case "grants.revoked":
						grants := r.store.grants
						grants.Revoked = true
						payload = api.GrantEvent{GrantSet: grants}
					}
					r.addEvent(kind, payload)
					last := len(r.store.events) - 1
					r.store.events[last].Actor = api.Actor{Kind: actor, ID: "controller"}
					if kind == "lane.turn" {
						r.store.events[last].LogicalTurnID = "later-turn"
					}
					if runZero {
						r.store.events[last].Run = 0
					}
					_, err := runEvidence(r.store.events, r.signal, r.store.lane.LogicalTurnID)
					requireCode(t, err, api.CodeCancelled)
					_, err = r.s.Reconcile(context.Background(), r.signal.Target)
					requireCode(t, err, api.CodeCancelled)
					if len(r.broker.checked) != 0 {
						t.Fatal("control was considered only after room polling/backoff")
					}
					r.noEffects()
				})
			}
		}
	}
}

func TestWaitingHistory(t *testing.T) {
	for _, name := range []string{"missing", "shrinking", "early-record", "orphan-current"} {
		t.Run(name, func(t *testing.T) {
			r, store, probe := newJournal(t)
			room := r.broker.rooms["profile-b"]
			room.Available = false
			r.broker.rooms["profile-b"] = room
			if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
				t.Fatal(err)
			}
			if name == "missing" {
				store.events = store.events[:len(store.events)-1]
			} else if name == "orphan-current" {
				id := r.s.intentID(r.signal.Target)
				intent := store.intents[id]
				intent.Generation++
				intent.OperationID, intent.Swap.OperationID = "orphan-operation", "orphan-operation"
				store.intents[id] = intent
			} else {
				r.clock.at = r.clock.at.Add(10 * time.Second)
				r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: 10000})
				store.events[len(store.events)-1].OperationID = store.intents[r.s.intentID(r.signal.Target)].OperationID
				r.clock.at = r.clock.at.Add(10 * time.Second)
				delay := int64(10000)
				if name == "shrinking" {
					delay = 5000
				} else {
					r.clock.at = r.clock.at.Add(-time.Second)
				}
				r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: delay})
				store.events[len(store.events)-1].OperationID = store.intents[r.s.intentID(r.signal.Target)].OperationID
			}
			r.clock.at = r.clock.at.Add(time.Minute)
			// Keep unrelated outside receipts fresh. Removing a history guard
			// must expose the forbidden new journal attempt, not be hidden by
			// an independent stale-room refusal later in assessment.
			for id, room := range r.broker.rooms {
				room.CheckedAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
				room.ExpiresAt = api.Timestamp(r.clock.at.Add(30 * time.Second).Format(time.RFC3339Nano))
				data, err := json.Marshal(map[string]any{"profile_id": room.ProfileID, "available": room.Available, "checked_at": room.CheckedAt})
				if err != nil {
					t.Fatal(err)
				}
				room.Evidence = r.addBlob(room.Evidence.ID, data)
				r.broker.rooms[id] = room
			}
			r.freshSelectionReceipts()
			reads := len(r.broker.checked)
			_, err := r.s.Reconcile(context.Background(), r.signal.Target)
			requireCode(t, err, api.CodeIntegrity)
			if store.writeCalls != 1 || len(r.broker.checked) != reads || len(probe.requests) != 0 {
				t.Fatal("missing/corrupt wait history reset or bypassed durable backoff")
			}
		})
	}
}

func TestSelectedCandidateOnly(t *testing.T) {
	r := newRig(t)
	// B is live when read, but incompatible with this retained model/session.
	// Its short grant/room expires while C's independent check is in flight.
	r.store.grants.Profiles[1].ExpiresAt = api.Timestamp(r.clock.at.Add(2 * time.Second).Format(time.RFC3339Nano))
	profileC := r.store.grants.Profiles[0]
	profileC.ID, profileC.ProfileID = "grant-c", "profile-c"
	r.store.grants.Profiles = append(r.store.grants.Profiles, profileC)
	r.grants.grants = r.store.grants
	r.broker.grants = r.store.grants.Profiles
	roomB := r.broker.rooms["profile-b"]
	roomB.ExpiresAt = r.store.grants.Profiles[1].ExpiresAt
	r.broker.rooms["profile-b"] = roomB
	roomC := roomB
	roomC.ProfileID, roomC.ExpiresAt = profileC.ProfileID, api.Timestamp(r.clock.at.Add(30*time.Second).Format(time.RFC3339Nano))
	roomBytes, err := json.Marshal(map[string]any{"profile_id": profileC.ProfileID, "available": true, "checked_at": roomC.CheckedAt})
	if err != nil {
		t.Fatal(err)
	}
	roomC.Evidence = r.addBlob("room-grant-c", roomBytes)
	r.broker.rooms[profileC.ProfileID] = roomC
	eligibleB := r.broker.eligibility
	eligibleB.Compatible = false
	eligibleC := r.broker.eligibility
	eligibleC.ID, eligibleC.Request.ToGrantID = "eligibility-c", profileC.ID
	r.broker.eligibilities = map[api.ID]api.ProfileEligibility{"grant-b": eligibleB, "grant-c": eligibleC}
	r.broker.onRoom = func(grant api.ProfileGrant) {
		if grant.ID == profileC.ID {
			r.clock.at = r.clock.at.Add(3 * time.Second)
		}
	}
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap == nil || plan.Swap.ToProfileID != profileC.ProfileID || r.broker.eligibilityCalls != 2 {
		t.Fatal("expired unselected B aborted a healthy selected C", err)
	}
	r.noEffects()
}

func TestPolicyExclusion(t *testing.T) {
	r := newRig(t)
	r.store.policy.ProfileExclusions = []api.ID{"profile-b"}
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap != nil || !reflect.DeepEqual(r.broker.checked, []api.ID{"profile-a"}) || r.broker.eligibilityCalls != 0 {
		t.Fatal("policy-excluded profile reached broker selection", err)
	}
	r.noEffects()
}

func TestOneLimitEvent(t *testing.T) {
	r, store, _ := newJournal(t)
	room := r.broker.rooms["profile-b"]
	room.Available = false
	r.broker.rooms["profile-b"] = room
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	r.clock.at = r.clock.at.Add(5 * time.Second)
	if _, err := r.s.Reconcile(context.Background(), r.signal.Target); err != nil {
		t.Fatal(err)
	}
	limits := 0
	for _, event := range store.events {
		if event.Kind != "watchdog.limit" {
			continue
		}
		limits++
		var payload api.WatchdogEvent
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Swap != nil {
			t.Fatal("usage diagnostic constructed a self-swap")
		}
	}
	if limits != 1 {
		t.Fatal("backoff retries invented repeated provider limit observations")
	}
}

func TestSchedulerLaunch(t *testing.T) {
	r := newRig(t)
	r.store.events[0].Actor = api.Actor{Kind: "scheduler", ID: "scheduler"}
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap == nil {
		t.Fatal("service-origin scheduler launch was rejected", err)
	}
	r.noEffects()
}

func TestTurnControlSequence(t *testing.T) {
	for _, later := range []bool{false, true} {
		t.Run(map[bool]string{true: "new-run", false: "before-launch"}[later], func(t *testing.T) {
			r := newRig(t)
			r.addEvent("lane.turn", api.TurnEvent{Task: r.store.lane.Task, Status: "running"})
			last := len(r.store.events) - 1
			if later {
				r.store.events[last].Run++
				r.store.events[last].LogicalTurnID = "later-turn"
				r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: 5000})
				_, err := r.s.Reconcile(context.Background(), r.signal.Target)
				requireCode(t, err, api.CodeCancelled)
				_, err = runEvidence(r.store.events, r.signal, r.store.lane.LogicalTurnID)
				requireCode(t, err, api.CodeCancelled)
			} else {
				turn := r.store.events[last]
				r.store.events = append([]api.Event{turn}, r.store.events[:last]...)
				for i := range r.store.events {
					r.store.events[i].Seq = api.Sequence(i + 1)
				}
				plan, err := r.s.assess(context.Background(), r.signal)
				if err != nil || plan.Swap == nil {
					t.Fatal("initial turn before launch incorrectly cancelled its own run", err)
				}
			}
			r.noEffects()
		})
	}
}
