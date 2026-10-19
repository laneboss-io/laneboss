package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReservationAuthorityHandoff(t *testing.T) {
	f := newLaunchFixture(t)
	f.request.RootTicketID = "root-ticket"
	human := api.Actor{Kind: "human", ID: "root-human"}
	ticket := api.Ticket{ID: f.request.RootTicketID, PrincipalID: human.ID, Config: "example", EndpointGeneration: 1,
		Level: f.request.Level, Role: f.request.Role, GrantSetID: "root-authority-grants", ExpiresAt: "2031-01-01T00:00:00Z"}
	f.store.tickets[ticket.ID] = ticket
	rootGrants := f.ports.delegated
	rootGrants.ID = ticket.GrantSetID
	f.store.grants[ticket.GrantSetID] = rootGrants
	f.scope = f.fixture.scope("lane.start", f.request, human)
	operation, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if err != nil || operation.ID == "" || len(f.store.reservationRequests) != 1 {
		t.Fatalf("root launch omitted its atomic ticket handoff: %v", err)
	}
	selector := f.store.reservationRequests[0]
	want := api.TransactionGuard{Ticket: &api.TicketUse{TicketID: ticket.ID, PrincipalID: ticket.PrincipalID,
		Config: ticket.Config, EndpointGeneration: ticket.EndpointGeneration, Level: ticket.Level, Role: ticket.Role, GrantSetID: ticket.GrantSetID}}
	if selector.OperationID != operation.ID || !reflect.DeepEqual(selector.Guards, []api.TransactionGuard{want}) || !f.store.tickets[ticket.ID].Redeemed {
		t.Fatal("root launch omitted its atomic ticket handoff")
	}
	replayed, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if err != nil || replayed != operation || f.store.reservationCalls != 1 {
		t.Fatalf("root retry consumed a replacement ticket: %v", err)
	}
	for _, record := range f.store.plans {
		if record.Reservation.Authority != (api.LaunchAuthority{Kind: "ticket", ID: ticket.ID}) {
			t.Fatal("root reservation lost its consumed authority")
		}
	}
}

func TestReservationLaneAuthority(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	selector := f.store.reservationRequests[0]
	if len(selector.Guards) != 0 || record.Reservation.Authority != (api.LaunchAuthority{Kind: "starter", ID: f.scope.LaunchID}) {
		t.Fatal("lane reservation borrowed proof or lost its authentic starter")
	}
	scope := f.scope
	scope.Request.Proof = &api.ProofRef{ID: "borrowed-proof", RequestSHA256: scope.Request.RequestSHA256}
	_, _, err := f.service.launchAuthority(context.Background(), scope, api.Lane{})
	if err == nil {
		t.Fatal("lane reservation accepted a human proof")
	}
}

func TestReservationRetainedProof(t *testing.T) {
	f := newFixture(t)
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: f.child.Generation,
		Message: f.blob("resume-input", "task", []byte("retained operation input")), Budget: f.budget}
	scope := f.prepareScope("lane.resume", request, api.Actor{Kind: "human", ID: "retained-controller"})
	scope.Request.Proof = &api.ProofRef{ID: "retained-proof", RequestSHA256: scope.Request.RequestSHA256}
	guards, authority, err := f.service.launchAuthority(context.Background(), scope, f.child)
	if err != nil || len(guards) != 2 || guards[0].Cancellation == nil || guards[1].Proof == nil ||
		*guards[0].Cancellation != (api.CancellationCheck{LifeID: f.child.LifeID, Epoch: f.child.CancellationEpoch}) ||
		guards[1].Proof.Proof != *scope.Request.Proof || guards[1].Proof.Target.BaseGeneration != f.child.Generation ||
		authority != (api.LaunchAuthority{Kind: "proof", ID: scope.Request.Proof.ID}) {
		t.Fatalf("retained launch lost exact proof and cancellation authority: %v", err)
	}
	if err := api.ValidateLaunchReservationRequest(scope, api.LaunchReservationRequest{OperationID: "retained-operation", Guards: guards}); err != nil {
		t.Fatal(err)
	}
}

func TestReservationReturnedPins(t *testing.T) {
	for _, field := range []string{"authority", "level", "role", "driver"} {
		t.Run(field, func(t *testing.T) {
			f := newLaunchFixture(t)
			f.store.reservationHook = func(r *api.LaunchReservation) {
				switch field {
				case "authority":
					r.Authority.ID = "foreign-starter"
				case "level":
					r.Level = 4
				case "role":
					r.Role = "reviewer"
				case "driver":
					r.Driver = api.DriverClaudock
				}
			}
			_, err := f.service.LaneStart(context.Background(), f.scope, f.request)
			if err == nil {
				t.Fatalf("launch accepted changed reserved authority or pins: %s", field)
			}
		})
	}
}

func TestPreparedTransactionRequiresPlan(t *testing.T) {
	for _, field := range []string{"identity-no-plan", "lane-no-plan", "legacy-kind", "worker-kind", "level", "role", "driver", "life-cas"} {
		t.Run(field, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			f.bindPrepared(t, scope, request, plan)
			// Keep the API-private policy fence issued by the real fixture
			// writer. JSON-cloning the whole transaction drops that authority.
			tx := f.store.transactions[len(f.store.transactions)-1]
			tx.Writes = launchClone(t, tx.Writes)
			tx.Events = append([]api.Event{}, tx.Events...)
			tx.Compare = append([]api.Compare{}, tx.Compare...)
			if tx.Internal == nil || tx.Internal.Kind != api.InternalHelperPrepare || api.ValidateTransactionShape(tx) != nil {
				t.Fatal("prepared fixture lost its valid complete transaction")
			}
			switch field {
			case "identity-no-plan":
				tx.Writes.LaunchPlans = nil
				tx.Writes.Lanes = nil
				tx.Writes.Turns = nil
				tx.Events = tx.Events[:1]
			case "lane-no-plan":
				tx.Writes.LaunchPlans = nil
				tx.Writes.IdentityBindings = nil
				tx.Writes.Turns = nil
				tx.Events = nil
			case "legacy-kind":
				tx.Writes.IdentityBindings[0].Record.Kind = ""
			case "worker-kind":
				tx.Writes.IdentityBindings[0].Record.Kind = "worker"
			case "level":
				tx.Writes.Lanes[0].Level++
			case "role":
				tx.Writes.Lanes[0].Role = "reviewer"
			case "driver":
				tx.Writes.Lanes[0].Session.Driver = api.DriverClaudock
			case "life-cas":
				tx.Compare = tx.Compare[:1]
			}
			if api.ValidateTransactionShape(tx) == nil {
				t.Fatalf("prepared binding escaped its same-transaction plan and pins: %s", field)
			}
		})
	}
}

func TestCaptureD6(t *testing.T) {
	for _, field := range []string{"disabled", "approval", "generation", "release-disabled", "recovery-disabled"} {
		t.Run(field, func(t *testing.T) {
			f := newLaunchFixture(t)
			f.ports.refuseCapture = true
			f.allowCaptureRefusal()
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			if field == "disabled" {
				f.store.policy.AllowCaptureRefusal = false
			}
			if field == "approval" {
				f.ports.captureHook = func(b *api.CaptureBinding) { b.RefusalPolicy.ApprovalID = "foreign-approval" }
			}
			if field == "generation" {
				f.ports.captureHook = func(b *api.CaptureBinding) { b.RefusalPolicy.PolicyGeneration++ }
			}
			if field == "release-disabled" {
				f.ports.onStage = func(stage string) {
					if stage == "storage" && f.ports.calls["capture"] > 0 {
						f.store.policy.AllowCaptureRefusal = false
					}
				}
			}
			if field == "recovery-disabled" {
				if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
					t.Fatal(err)
				}
				f.store.policy.AllowCaptureRefusal = false
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || f.launcher.launched.Load() != 0 {
				t.Fatalf("refused capture ignored current D6 policy: %s: %v", field, err)
			}
		})
	}
}

func TestContinuationOneOperation(t *testing.T) {
	f := newLaunchFixture(t)
	_, lane := f.endedPlan(t)
	scope, request, _ := f.continuation(t, lane)
	selected := f.store.operations[request.Swap.OperationID]
	operation, err := f.service.Continue(context.Background(), scope, request)
	if err != nil || operation.ID != selected.ID || operation.Status != "pending" {
		t.Fatalf("continuation replaced its store-stamped operation: %v", err)
	}
	operation.Status = "running"
	f.store.operations[operation.ID] = operation
	before := f.store.reservationCalls
	replay, err := f.service.Continue(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replay, operation) || f.store.reservationCalls != before+1 {
		t.Fatalf("running continuation replaced its retained operation: %v", err)
	}
	var record api.LaunchPlanRecord
	for _, candidate := range f.store.plans {
		if candidate.Reservation.OperationID == operation.ID {
			record = candidate
		}
	}
	internal, planRequest := f.claim(t, record)
	plan, err := f.service.PlanLaunch(context.Background(), internal, planRequest)
	if err != nil {
		t.Fatal(err)
	}
	f.bindPrepared(t, internal, planRequest, plan)
	before = f.store.reservationCalls
	replay, err = f.service.Continue(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replay, operation) || f.store.reservationCalls != before+1 {
		t.Fatalf("running continuation replaced its retained operation: %v", err)
	}
	intent := f.store.continuations[request.IntentID]
	intent.Status = "completed"
	f.store.continuations[intent.ID] = intent
	operation.Status = "succeeded"
	f.store.operations[operation.ID] = operation
	before = f.store.reservationCalls
	acquired := f.ports.calls["acquire"]
	replay, err = f.service.Continue(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replay, operation) || f.store.reservationCalls != before || f.ports.calls["acquire"] != acquired {
		t.Fatalf("completed continuation launched instead of returning its operation: %v", err)
	}
}

func TestContinueOpRefuses(t *testing.T) {
	for _, field := range []string{"swap-operation", "operation-result", "waiting", "cancelled", "pending-succeeded", "public-method", "capture-refused"} {
		t.Run(field, func(t *testing.T) {
			f := newLaunchFixture(t)
			if field == "capture-refused" {
				f.ports.refuseCapture = true
				f.allowCaptureRefusal()
			}
			_, lane := f.endedPlan(t)
			scope, request, _ := f.continuation(t, lane)
			intent := f.store.continuations[request.IntentID]
			operation := f.store.operations[request.Swap.OperationID]
			switch field {
			case "swap-operation":
				intent.Swap.OperationID = "different-operation"
			case "operation-result":
				operation.ID = "different-operation"
			case "waiting":
				intent.Status = "waiting"
			case "cancelled":
				intent.Status = "cancelled"
			case "pending-succeeded":
				operation.Status = "succeeded"
			case "public-method":
				scope.Request.Method = "lane.check"
			}
			f.store.continuations[request.IntentID] = intent
			f.store.operations[request.Swap.OperationID] = operation
			before := f.store.reservationCalls
			acquired := f.ports.calls["acquire"]
			_, err := f.service.Continue(context.Background(), scope, request)
			if err == nil || f.store.reservationCalls != before || f.ports.calls["acquire"] != acquired {
				t.Fatalf("invalid continuation operation reached reservation or credential acquisition: %s: %v", field, err)
			}
		})
	}
}
