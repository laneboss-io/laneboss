package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestOpenedWithdraw(t *testing.T) {
	for _, mode := range []string{"held", "withdrawing", "withdrawn", "reserved", "handoff", "prepared"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			if _, err := f.store.Transact(context.Background(), openFixtureTransaction(t, f)); err != nil {
				t.Fatal(err)
			}
			var id api.ID
			for key := range f.store.projections {
				id = key
			}
			projection := launchClone(t, f.store.projections[id])
			projection.State = mode
			if mode == "handoff" || mode == "prepared" {
				projection.State = "held"
			}
			projection.Receipt.GateClosed = false
			if mode == "withdrawing" || mode == "withdrawn" {
				projection.State = "held"
				cause := projection.Authority.Request.Cause
				cause.Kind, cause.ID, cause.EffectID = api.InternalHelperStop, launchIDForTest(), launchIDForTest()
				fence := api.CredentialWithdrawalRequest{ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Cause: cause, Reason: "cancelled"}
				if err := api.ValidateCredentialWithdrawalRequest(projection, fence); err != nil {
					t.Fatal(err)
				}
				projection.Fence, projection.Generation, projection.State = &fence, projection.Generation+1, mode
				if mode == "withdrawn" {
					projection.Generation++
				}
			}
			claim := &projection.Authority.Request.Claim
			claim.ExpiresAt, claim.Record.ClaimExpiresAt = "2029-01-01T00:00:00Z", "2029-01-01T00:00:00Z"
			f.store.effects[claim.Record.Effect.ID] = claim.Record
			if mode == "handoff" {
				projection.Authority.Request.Handoff.Original.ID = "foreign-handoff"
			}
			if mode == "prepared" {
				projection.Authority.Request.Prepared.ID = "foreign-gate"
			}
			f.store.projections[id] = projection
			f.ports.failStage, f.ports.failure = "credential-check", api.NotImplemented("identity-owner", "fresh opening is forbidden during replay")
			before := f.ports.calls["acquire"]
			got, err := f.service.PlanLaunch(context.Background(), scope, request)
			if mode == "held" || mode == "withdrawing" || mode == "withdrawn" {
				if err != nil || !reflect.DeepEqual(got, plan) || f.ports.calls["credential-check"] != 0 || f.ports.calls["acquire"] != before {
					t.Fatalf("opened reconciliation lost its original permit: %v", err)
				}
			} else if err == nil || f.ports.calls["acquire"] != before {
				t.Fatalf("opened reconciliation accepted a foreign projection: %v", err)
			}
		})
	}
}

func TestPartialBind(t *testing.T) {
	f, scope, request, plan := preparedFixture(t)
	record := f.store.plans[plan.Reservation.ID]
	record.Phase = "spec_retained"
	f.store.plans[plan.Reservation.ID] = record
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || typed.Message != "unbound launch plan has a partial launch binding" || f.ports.calls["acquire"] != 1 {
		t.Fatalf("unbound recovery accepted a partial identity commit: %v", err)
	}
}

func TestProjectionEffect(t *testing.T) {
	f, scope, request, _ := preparedFixture(t)
	for _, projection := range f.store.projections {
		delete(f.store.effects, projection.Authority.Request.Claim.Record.Effect.ID)
	}
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err == nil || f.ports.calls["acquire"] != 1 {
		t.Fatalf("bound recovery skipped its actual prepare effect: %v", err)
	}
}

func TestBoundRecovery(t *testing.T) {
	for _, mode := range []string{"turn", "snapshot"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			if mode == "snapshot" {
				delete(f.store.turns, request.Lease.Record.Effect.Context.LogicalTurnID)
			} else {
				lane := f.store.lanes[plan.Reservation.Target.LifeID]
				lane.LogicalTurnID = "foreign-turn"
				f.store.lanes[lane.LifeID] = lane
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || f.ports.calls["acquire"] != 1 {
				t.Fatalf("bound recovery skipped its actual turn snapshot: %v", err)
			}
		})
	}
}

func TestWriterBind(t *testing.T) {
	for _, mode := range []string{"duplicate", "reservation"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, plan := preparedFixture(t)
			tx := f.store.transactions[len(f.store.transactions)-1]
			binding := f.store.bindings[plan.Reservation.LaunchID]
			// Model a partial write: keep the committed identity, but return
			// the plan/lane CAS to their pre-bind state. The new duplicate
			// guard must decide before a second identity can overwrite it.
			previous := f.store.plans[plan.Reservation.ID]
			previous.Phase, previous.Generation = "spec_retained", previous.Generation-1
			delete(f.store.lanes, plan.Reservation.Target.LifeID)
			if mode == "reservation" {
				delete(f.store.bindings, plan.Reservation.LaunchID)
				delete(f.store.launches, plan.Reservation.LaunchID)
				previous.Reservation.RequestSHA256 = digestOf([]byte("different reserved request"))
			}
			f.store.plans[plan.Reservation.ID] = previous
			before := len(f.store.transactions)
			_, err := f.store.Transact(context.Background(), tx)
			if err == nil || len(f.store.transactions) != before || !reflect.DeepEqual(f.store.plans[plan.Reservation.ID], previous) ||
				mode == "duplicate" && !reflect.DeepEqual(f.store.bindings[plan.Reservation.LaunchID], binding) {
				t.Fatalf("fixture writer replaced a committed binding or reservation: %v", err)
			}
		})
	}
}

func TestPrepareEffect(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "actor", "claimant", "claim", "input", "pending", "failed", "generation", "complete"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			var projection api.CredentialProjectionRecord
			for _, p := range f.store.projections {
				projection = launchClone(t, p)
			}
			p := projection.Authority.Request
			effect := launchClone(t, f.store.effects[p.Claim.Record.Effect.ID])
			switch mode {
			case "missing":
				delete(f.store.effects, effect.Effect.ID)
			case "actor":
				p.Cause.Actor.ID = "foreign-service"
			case "claimant":
				p.Claim.Record.ClaimantID = "foreign-service"
			case "claim":
				effect.ClaimID = "foreign-claim"
			case "input":
				effect.Effect.HelperPrepare.LeaseID = "foreign-lease"
			case "pending":
				effect.State, effect.Generation = api.EffectPending, 1
				effect.ClaimID, effect.ClaimantID, effect.ClaimExpiresAt = "", "", ""
			case "failed":
				effect.State, effect.Generation = api.EffectFailed, effect.Generation+1
				effect.Outcome = &api.EffectOutcome{EffectID: effect.Effect.ID, ClaimID: effect.ClaimID, ExpectedGeneration: p.Claim.Record.Generation,
					Status: "failed", Error: api.NotImplemented("helper-owner", "prepare failed")}
			case "generation":
				effect.Generation = 1
			case "complete":
				if _, err := f.store.CompleteEffect(context.Background(), scope, api.EffectOutcome{EffectID: effect.Effect.ID, ClaimID: effect.ClaimID,
					ExpectedGeneration: effect.Generation, Status: "succeeded", Prepared: &p.Prepared}); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "missing" && mode != "complete" {
				f.store.effects[effect.Effect.ID] = effect
			}
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[plan.Reservation.ID]}
			err := execution.prepareEffect(context.Background(), p)
			if mode == "valid" || mode == "complete" {
				if err != nil {
					t.Fatalf("prepare recovery rejected its original claimed effect: %v", err)
				}
			} else if err == nil {
				t.Fatal("credential recovery trusted an unretained prepare claim")
			}
		})
	}
}

func TestBoundTurn(t *testing.T) {
	for _, mode := range []string{"valid", "turn", "grants", "policy", "workspace", "snapshot", "task", "prompt", "snap-policy"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			turnID := request.Lease.Record.Effect.Context.LogicalTurnID
			lane, turn := f.store.lanes[plan.Reservation.Target.LifeID], launchClone(t, f.store.turns[turnID])
			switch mode {
			case "turn":
				lane.LogicalTurnID = "foreign-turn"
			case "grants":
				lane.GrantSetID = "foreign-grants"
			case "policy":
				lane.PolicyGeneration++
			case "workspace":
				lane.Workspace.ID = "foreign-workspace"
			case "snapshot":
				turn.LogicalTurnID = "foreign-turn"
			case "task":
				turn.Task.ID = "foreign-task"
			case "prompt":
				turn.Prompt.ID = "foreign-prompt"
			case "snap-policy":
				turn.PolicyGeneration++
			}
			f.store.lanes[lane.LifeID], f.store.turns[turnID] = lane, turn
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease,
				record: f.store.plans[plan.Reservation.ID], input: launchInput{turn: turnID}}
			err := execution.boundTurn(context.Background(), plan)
			if mode == "valid" {
				if err != nil {
					t.Fatalf("bound recovery rejected its committed turn: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("bound recovery accepted a replaced turn snapshot: %v", err)
			}
		})
	}
}

func TestOpenedResources(t *testing.T) {
	for _, mode := range []string{"allocation", "data", "capture", "turn"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			if _, err := f.store.Transact(context.Background(), openFixtureTransaction(t, f)); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "allocation":
				delete(f.store.effects, launchObjectID(plan.Reservation.ID, "allocate-effect"))
			case "data":
				delete(f.store.dataStages, plan.Reservation.ID)
			case "capture":
				f.ports.reconcileHook = func(c *api.CaptureBinding) { c.ProducerID = "foreign-producer" }
			case "turn":
				delete(f.store.turns, request.Lease.Record.Effect.Context.LogicalTurnID)
			}
			before := launchClone(t, f.ports.calls)
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || f.ports.calls["acquire"] != before["acquire"] || f.ports.calls["allocate"] != before["allocate"] ||
				f.ports.calls["materialize-entry"] != before["materialize-entry"] || len(f.store.failedWrites) != 0 {
				t.Fatalf("opened recovery trusted missing retained resources: %v", err)
			}
		})
	}
}
