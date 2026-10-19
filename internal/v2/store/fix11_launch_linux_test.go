//go:build linux

package store_test

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestReservationAuthority(t *testing.T) {
	for _, fault := range []string{"missing_ticket", "foreign_grant_set", "issued_target", "wrong_role", "proof_on_root"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.New(t)
			request := f.ReservationRequest(t)
			scope := f.Human
			switch fault {
			case "missing_ticket":
				request.Guards = nil
			case "foreign_grant_set":
				request.Guards[0].Ticket.GrantSetID = fx.ID(t)
			case "issued_target":
				request.Guards[0].Ticket.Target = api.LifeRef{LifeID: fx.ID(t), Run: 1}
			case "wrong_role":
				request.Guards[0].Ticket.Role = "executor"
			case "proof_on_root":
				scope.Request.Proof = &api.ProofRef{ID: fx.ID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: fx.Expiry()}
			}
			if _, err := f.State.ReserveLaunch(context.Background(), scope, request); err == nil {
				t.Fatal("reservation accepted authority " + fault)
			}
			f.Reserve(t)
			if f.Reservation.Authority.Kind != "ticket" || f.Reservation.Authority.ID != f.Start.RootTicketID || f.Reservation.Level != f.Start.Level || f.Reservation.Role != f.Start.Role || f.Reservation.Driver != f.Start.Driver {
				t.Fatal("reservation lost its actual consumed authority or child pins")
			}
		})
	}
}

func publishFixturePolicy(t *testing.T, f *fx.Fixture) api.EffectivePolicy {
	t.Helper()
	policy, err := f.State.Policy(context.Background(), f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	policy.Generation++
	policy.SHA256 = fx.Digest([]byte("approved policy fixture " + string(fx.ID(t))))
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalOrgBootstrap, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor}
	// This fixture installs an approved protected policy generation. It does
	// not claim an administrator/D6 ceremony or enable capture refusal.
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Policy: &policy}}); err != nil {
		t.Fatal("approved policy fixture transition failed", err)
	}
	return policy
}

func TestPolicyHistoryAndAdvance(t *testing.T) {
	f := fx.Ready(t, true)
	f.Opened(t)
	ctx := context.Background()
	historical, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	oldBinding := f.Binding
	oldGrants, err := f.State.Grants(ctx, f.Reservation.GrantSetID)
	if err != nil {
		t.Fatal(err)
	}
	current := publishFixturePolicy(t, f)
	read, err := f.State.PolicyAt(ctx, f.Execution, historical.Generation)
	if err != nil || !reflect.DeepEqual(read, historical) {
		t.Fatal("policy history rewrote an approved snapshot", err)
	}
	request := api.PolicyAdvanceRequest{Target: f.Reservation.Target, ExpectedLaneGeneration: f.Lane.Generation, FromGeneration: historical.Generation, ToGeneration: current.Generation, CancellationEpoch: f.Lane.CancellationEpoch}
	advanced, err := f.State.RefreshLanePolicy(ctx, f.Execution, request)
	if err != nil || !advanced.Changed || advanced.Lane.Generation != f.Lane.Generation+1 || advanced.EventID == "" || advanced.CommittedSeq == 0 {
		t.Fatal("current policy did not advance the actual lane once", err)
	}
	if err := api.ValidatePolicyAdvance(f.Lane, request, current, advanced); err != nil {
		t.Fatal(err)
	}
	request.ExpectedLaneGeneration, request.FromGeneration = advanced.Lane.Generation, current.Generation
	replay, err := f.State.RefreshLanePolicy(ctx, f.Execution, request)
	if err != nil || replay.Changed || replay.EventID != "" {
		t.Fatal("already-current policy appended another event", err)
	}
	binding, err := f.State.LaunchBinding(ctx, f.Reservation.LaunchID)
	if err != nil || !reflect.DeepEqual(binding, oldBinding) {
		t.Fatal("policy refresh rewrote the historical launch binding", err)
	}
	grants, err := f.State.Grants(ctx, f.Reservation.GrantSetID)
	if err != nil || !reflect.DeepEqual(grants, oldGrants) {
		t.Fatal("policy refresh silently rewrote issued grants", err)
	}
	if _, err := f.State.PolicyAt(ctx, f.Execution, current.Generation+1); err == nil {
		t.Fatal("policy history accepted an unapproved future generation")
	}
}

func TestPolicyAdvanceGuards(t *testing.T) {
	for _, fault := range []string{"foreign_run", "stale_cas", "old_epoch", "future_policy", "old_policy", "foreign_actor"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.Ready(t, true)
			f.Opened(t)
			current := publishFixturePolicy(t, f)
			request := api.PolicyAdvanceRequest{Target: f.Reservation.Target, ExpectedLaneGeneration: f.Lane.Generation, FromGeneration: f.Lane.PolicyGeneration, ToGeneration: current.Generation, CancellationEpoch: f.Lane.CancellationEpoch}
			scope := f.Execution
			switch fault {
			case "foreign_run":
				request.Target.Run++
			case "stale_cas":
				request.ExpectedLaneGeneration++
			case "old_epoch":
				request.CancellationEpoch++
			case "future_policy":
				request.ToGeneration++
			case "old_policy":
				request.FromGeneration++
			case "foreign_actor":
				scope.Actor = f.Human.Actor
				scope.Connection = f.Human.Connection
				scope.EndpointGeneration = f.Human.EndpointGeneration
			}
			if _, err := f.State.RefreshLanePolicy(context.Background(), scope, request); err == nil {
				t.Fatal("policy refresh accepted " + fault)
			}
		})
	}
}

func TestNaturalCompletionCommit(t *testing.T) {
	for _, fault := range []string{"valid", "missing_epoch", "missing_cas", "foreign_observation", "changed_budget", "changed_end_budget", "running_observation", "missing_state"} {
		t.Run(fault, func(t *testing.T) {
			f := fx.ControlledChild(t)
			f.Opened(t)
			ctx := context.Background()
			measured := f.Observation(t, "exited")
			exit := 0
			measured.Observation.ExitCode = &exit
			if fault != "running_observation" {
				if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, measured); err != nil {
					t.Fatal(err)
				}
			}
			next := f.Lane
			next.Generation++
			next.State, next.Containment = "verifying", "quiescent"
			end := api.RunEndEvent{LaunchID: f.Reservation.LaunchID, Reason: "exit", Observation: measured.Observation, BudgetRemaining: next.BudgetRemaining}
			if fault == "foreign_observation" {
				end.Observation.Handle.ID = fx.ID(t)
			}
			if fault == "changed_budget" {
				next.BudgetRemaining.WallMS++
				end.BudgetRemaining = next.BudgetRemaining
			}
			if fault == "changed_end_budget" {
				end.BudgetRemaining.WallMS++
			}
			f.Admit(t, "lane.check", f.Reservation.Target)
			events := []api.Event{f.Event(t, "lane.ended", end), f.Event(t, "lane.state", api.StateEvent{From: f.Lane.State, To: next.State, Generation: next.Generation})}
			input := api.Transaction{Scope: f.Human, RawRequest: f.Raw, Writes: api.StateWrites{Lanes: []api.Lane{next}}, Events: events, Compare: []api.Compare{{Kind: api.CompareLane, ID: next.LifeID, Generation: f.Lane.Generation}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: next.LifeID, Epoch: next.CancellationEpoch}}}, Reply: &api.RPCReply{Result: fx.JSON(t, measured.Observation)}}
			for i := range input.Events {
				input.Events[i].OperationID = ""
				input.Events[i].RequestID = ""
				input.Events[i].RequestedBy = f.Human.Actor
			}
			switch fault {
			case "missing_epoch":
				input.Guards = nil
			case "missing_cas":
				input.Compare = nil
			case "missing_state":
				input.Events = input.Events[:1]
			}
			commit, err := f.State.Transact(ctx, input)
			if fault == "valid" {
				if err != nil {
					t.Fatal("measured lane.check natural completion failed", err)
				}
				lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
				if err != nil || lane.LastSeq != commit.LastSeq {
					t.Fatal("natural completion lost its actual committed journal head", err)
				}
				return
			}
			if err == nil {
				t.Fatal("natural completion accepted " + fault)
			}
		})
	}
}
