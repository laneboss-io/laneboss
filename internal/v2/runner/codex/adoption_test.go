package codex

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestTurnPlan(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.service.Start(ctx, f.request); err != nil {
		t.Fatal(err)
	}
	key := f.service.deps.Planning.Lease.Record.Effect.ID
	current := fixtureCopy(f.store.effects[key])
	current.Effect.Context.LogicalTurnID = "foreign_turn"
	f.store.effects[key] = current
	f.service.deps.Planning.Lease.Record = fixtureCopy(current)
	plan, err := f.service.Start(ctx, f.request)
	wantCode(t, err, api.CodeIntegrity)
	if !reflect.DeepEqual(plan, api.RunnerPlan{}) {
		t.Fatal("foreign logical turn returned a runner plan")
	}
}

func TestTurnEvent(t *testing.T) {
	for _, fault := range []string{"missing", "invalid"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.store.event(f.request.Target, "lane.turn", api.TurnEvent{Task: f.request.Prompt, Prompt: f.request.Prompt, Status: "ready", MailIDs: []api.ID{}})
			ctx := context.Background()
			if _, err := f.service.events(ctx, f.request.Target); err != nil {
				t.Fatal("valid logical turn event refused", err)
			}
			f.store.events[0].LogicalTurnID = ""
			if fault == "invalid" {
				f.store.events[0].LogicalTurnID = "invalid turn"
			}
			_, err := f.service.events(ctx, f.request.Target)
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestPolicyOwner(t *testing.T) {
	f := newFixture(t)
	r := f.currentPlan().Reservation
	ctx := context.Background()
	if err := f.service.launchAuthority(ctx, r, f.store.grants); err != nil {
		t.Fatal(err)
	}
	f.store.policy.Generation++
	err := f.service.launchAuthority(ctx, r, f.store.grants)
	wantCode(t, err, api.CodeConflict)
	expected := api.ValidateLaunchPolicyCurrent(r, f.store.grants, f.store.policy)
	var actual *api.Error
	if !errors.As(err, &actual) || !reflect.DeepEqual(actual, expected) {
		t.Fatal("new launch policy lost its owning recovery route", err)
	}
}

func TestPolicyHead(t *testing.T) {
	f := newFixture(t)
	r := f.currentPlan().Reservation
	ctx := context.Background()
	if err := f.service.launchAuthority(ctx, r, f.store.grants); err != nil {
		t.Fatal(err)
	}
	head := fixtureCopy(f.store.policy)
	head.Generation++
	f.store.approvedPolicy = &head
	// The bound scope and its historical Policy read deliberately stay old.
	err := f.service.launchAuthority(ctx, r, f.store.grants)
	wantCode(t, err, api.CodeConflict)
}

func TestUsageClaimTime(t *testing.T) {
	f := newFixture(t)
	f.quotaProof()
	record, exit := f.endCapture([]byte("{\"type\":\"turn.failed\",\"error\":{\"code\":\"synthetic_quota\"}}\n"), 1)
	ctx := context.Background()
	if signal, err := f.service.LimitFromCapture(ctx, record, exit); err != nil || signal == nil {
		t.Fatal("valid usage claim control failed", err)
	}
	refs := f.store.usage[record.Target]
	var producer api.WorkerPrincipal
	if err := f.store.retainedInternal(refs.Principal, &producer); err != nil {
		t.Fatal(err)
	}
	producer.Claim.ExpiresAt = api.Timestamp(f.clock.Now().Add(time.Second).Format(time.RFC3339Nano))
	producer.Claim.Record.ClaimExpiresAt = producer.Claim.ExpiresAt
	refs.Principal = f.keepJSON(producer, "record")
	f.store.usage[record.Target] = refs
	profile := f.service.deps.UsageProfile
	f.service.deps.UsageProfile = func(ctx context.Context, grant api.ProfileGrant) (string, error) {
		result, err := profile(ctx, grant)
		f.clock.now = f.clock.Now().Add(2 * time.Second)
		f.service.deps.Clock = f.clock
		return result, err
	}
	signal, err := f.service.LimitFromCapture(ctx, record, exit)
	wantCode(t, err, api.CodeInvalid)
	if signal != nil {
		t.Fatal("expired producing claim authorized a usage limit")
	}
}

func TestDataEffectState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.service.Start(ctx, f.request); err != nil {
		t.Fatal("completed materialization was refused", err)
	}
	r := f.currentPlan().Reservation
	stage, err := f.store.LaunchDataStage(ctx, f.service.deps.ReadScope, api.LaunchDataRequest{ReservationID: r.ID,
		GrantSetID: r.GrantSetID, LeaseID: f.store.effects[f.service.deps.AllocationEffectID].Outcome.HelperLease.ID})
	if err != nil {
		t.Fatal(err)
	}
	child := f.store.effects[stage.Worker.EffectID]
	child.State = "succeeded"
	f.store.effects[stage.Worker.EffectID] = child
	_, err = f.service.Start(ctx, f.request)
	wantCode(t, err, api.CodeConflict)
}
