package watchdog

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestClockReceipts(t *testing.T) {
	t.Run("exit", func(t *testing.T) {
		r := newRig(t)
		// The outside usage result is issued after the newly observed exit.
		// Its future timestamp is not read until onObserve advances the clock.
		evidence, provenance := r.usageFixture("usage-after-exit")
		evidence.ObservedAt = api.Timestamp(r.clock.at.Add(time.Second).Format(time.RFC3339Nano))
		ref := r.retainUsage(evidence, provenance)
		for _, id := range []api.ID{ref.ID, evidence.Raw.ID} {
			metadata := r.store.metadata[id]
			metadata.CommittedAt = evidence.ObservedAt
			r.store.metadata[id] = metadata
		}
		r.signal.UsageEvidence, r.runner.usageEvidence = &ref, &ref
		r.launcher.onObserve = func() {
			r.clock.at = r.clock.at.Add(time.Second)
			r.launcher.observation.ObservedAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
		}
		plan, err := r.s.assess(context.Background(), r.signal)
		if err != nil || plan.Swap == nil {
			t.Fatal("fresh exit receipt produced during observation was rejected", err)
		}
		r.noEffects()
	})
	t.Run("room", func(t *testing.T) {
		r := newRig(t)
		r.broker.onRoom = func(grant api.ProfileGrant) {
			r.clock.at = r.clock.at.Add(time.Second)
			room := r.broker.rooms[grant.ProfileID]
			room.CheckedAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
			data, err := json.Marshal(map[string]any{
				"profile_id": room.ProfileID, "available": room.Available, "checked_at": room.CheckedAt,
			})
			if err != nil {
				t.Fatal(err)
			}
			room.Evidence = r.addBlob(room.Evidence.ID, data)
			r.broker.rooms[grant.ProfileID] = room
		}
		plan, err := r.s.assess(context.Background(), r.signal)
		if err != nil || plan.Swap == nil {
			t.Fatal("fresh room issued during broker call was rejected", err)
		}
		r.noEffects()
	})
	t.Run("final-room", func(t *testing.T) {
		r := newRig(t)
		// Eligibility and outside usage stay live so removing the final room
		// check cannot be masked by either independent expiry requirement.
		r.broker.eligibility.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Minute).Format(time.RFC3339Nano))
		room := r.broker.rooms["profile-b"]
		room.ExpiresAt = api.Timestamp(r.clock.at.Add(5 * time.Second).Format(time.RFC3339Nano))
		r.broker.rooms["profile-b"] = room
		r.store.onLane = func(reads int) {
			if reads == 2 {
				r.clock.at = r.clock.at.Add(6 * time.Second)
			}
		}
		_, err := r.s.assess(context.Background(), r.signal)
		requireCode(t, err, api.CodeIntegrity)
		r.noEffects()
	})
	t.Run("final-grant", func(t *testing.T) {
		r := newRig(t)
		r.store.grants.ExpiresAt = api.Timestamp(r.clock.at.Add(time.Second).Format(time.RFC3339Nano))
		r.grants.grants = r.store.grants
		r.store.onLane = func(reads int) {
			if reads == 2 {
				r.clock.at = r.clock.at.Add(2 * time.Second)
			}
		}
		_, err := r.s.assess(context.Background(), r.signal)
		requireCode(t, err, api.CodeForbidden)
		r.noEffects()
	})
}

func TestQuotaValidation(t *testing.T) {
	for _, row := range []struct {
		name string
		text string
	}{
		{"quote", `{"type":"assistant","message":{"content":[{"type":"text","text":"Usage limit reached"}]}}`},
		{"auth", `{"type":"result","is_error":true,"result":{"code":"token_expired"}}`},
		{"candidate", `{"type":"result","is_error":true,"result":{"code":"usage_limit_reached"}}`},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t)
			r.capture(func(capture *api.CaptureRecord) {
				capture.Data = r.addBlob(capture.Data.ID, []byte(row.text+"\n"))
				r.signal.CaptureSHA256 = capture.Data.SHA256
			})
			_, err := r.s.assess(context.Background(), r.signal)
			requireCode(t, err, api.CodeIntegrity)
			r.noEffects()
		})
	}
}

func TestRecordedControl(t *testing.T) {
	for _, kind := range []api.EventKind{"lane.stopping", "lane.cleaned", "grants.revoked", "watchdog.cancelled"} {
		t.Run(string(kind), func(t *testing.T) {
			r := newRig(t)
			var payload any
			switch kind {
			case "lane.stopping":
				payload = api.StateEvent{From: "running", To: "stopping", Generation: r.store.lane.Generation + 1}
			case "lane.cleaned":
				payload = api.CleanEvent{Quiescence: r.launcher.observation}
			case "grants.revoked":
				grants := r.store.grants
				grants.Revoked = true
				payload = api.GrantEvent{GrantSet: grants}
			default:
				payload = api.WatchdogEvent{Reason: "control"}
			}
			r.addEvent(kind, payload)
			_, err := runEvidence(r.store.events, r.signal, r.store.lane.LogicalTurnID)
			requireCode(t, err, api.CodeCancelled)
		})
	}
}

func TestLaneGates(t *testing.T) {
	for _, name := range []string{"stale-run", "cleaned", "budget"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			target := r.signal.Target
			code := api.CodeConflict
			switch name {
			case "stale-run":
				target.Run--
			case "cleaned":
				r.store.lane.Cleaned = true
				code = api.CodeCancelled
			case "budget":
				r.store.lane.BudgetRemaining.WallMS = 0
				code = api.CodeBudget
			}
			requireCode(t, eligibleLane(r.store.lane, target), code)
		})
	}
}

func TestGrantValidity(t *testing.T) {
	for _, name := range []string{"revoked", "expired"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			grants := r.store.grants
			if name == "revoked" {
				grants.Revoked = true
			} else {
				grants.ExpiresAt = api.Timestamp(r.clock.at.Format(time.RFC3339Nano))
			}
			requireCode(t, currentGrants(grants, r.store.lane, r.store.launch, r.clock.at), api.CodeForbidden)
		})
	}
}

func TestRecoveryGates(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		r := newRig(t)
		r.addEvent("watchdog.cancelled", api.WatchdogEvent{Reason: "control"})
		_, err := r.s.Reconcile(context.Background(), r.signal.Target)
		requireCode(t, err, api.CodeCancelled)
		r.noEffects()
	})
	t.Run("early", func(t *testing.T) {
		r := newRig(t)
		r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: 5000})
		_, err := r.s.Reconcile(context.Background(), r.signal.Target)
		requireCode(t, err, api.CodeUnavailable)
		if len(r.broker.checked) != 0 {
			t.Fatal("room was polled before durable backoff elapsed")
		}
		r.noEffects()
	})
	t.Run("forged", func(t *testing.T) {
		r := newRig(t)
		r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: 5000})
		last := len(r.store.events) - 1
		r.store.events[last].Actor = api.Actor{Kind: "lane", ID: "forged", LifeID: r.signal.Target.LifeID}
		_, err := r.s.Reconcile(context.Background(), r.signal.Target)
		requireCode(t, err, api.CodeNotFound)
		r.noEffects()
	})
}

func TestPlanInvariants(t *testing.T) {
	t.Run("no-room", func(t *testing.T) {
		r := newRig(t)
		room := r.broker.rooms["profile-b"]
		room.Available = false
		r.broker.rooms["profile-b"] = room
		plan, err := r.s.assess(context.Background(), r.signal)
		if err != nil || plan.Swap != nil || len(plan.Rooms) != 2 {
			t.Fatal("no-room did not preserve exhausted delegated profile evidence", err)
		}
		r.noEffects()
	})
}
