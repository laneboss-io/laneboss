//go:build linux

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Corrupt actual retained fixture records after real admission. Change both
// ticket copies for provenance cases, so agreement between the copies alone
// cannot satisfy the independent original reservation/receipt binding.
func TestLaunchTicketRetainedAuthority(t *testing.T) {
	for _, mutation := range []string{"another_human", "different_config", "changed_endpoint_generation", "unredeemed", "expired", "other_operation", "other_ticket", "other_role", "other_grants"} {
		t.Run(mutation, func(t *testing.T) {
			f, reservation, _ := scopePlanningFixture(t)
			ctx := context.Background()
			ticket, err := f.State.Ticket(ctx, f.Human, f.Start.RootTicketID)
			if err != nil {
				t.Fatal("could not read actual consumed fixture ticket", err)
			}
			redeemedBy := reservation.OperationID
			switch mutation {
			case "another_human":
				ticket.PrincipalID = fx.ID(t)
			case "different_config":
				ticket.Config = "other-ticket-config"
			case "changed_endpoint_generation":
				ticket.EndpointGeneration++
			case "unredeemed":
				ticket.Redeemed = false
			case "expired":
				ticket.ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
			case "other_operation":
				redeemedBy = fx.ID(t)
			case "other_ticket":
				ticket.ID = fx.ID(t)
			case "other_role":
				ticket.Role = "other-role"
			case "other_grants":
				ticket.GrantSetID = fx.ID(t)
			}
			f.Replace(t, "ticket", f.Start.RootTicketID, 1, struct {
				RedeemedBy         api.ID
				PrincipalID        api.ID
				Config             string
				EndpointGeneration api.Generation
				Ticket             api.Ticket
			}{RedeemedBy: redeemedBy, PrincipalID: ticket.PrincipalID, Config: ticket.Config, EndpointGeneration: ticket.EndpointGeneration, Ticket: ticket})
			selected, err := f.State.LaunchTicket(ctx, f.Execution, api.LaunchTicketRequest{ReservationID: reservation.ID})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "launch ticket differs from its retained reservation authority" || selected != (api.Ticket{}) {
				t.Fatal("protected ticket read accepted altered retained authority", err)
			}
			state := &planningPolicyStore{Service: f.State}
			resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: state, Worker: &dataworker.Service{}, Clock: fx.Clock{}})
			if err != nil {
				t.Fatal(err)
			}
			set, err := resolver.Resolve(ctx, f.Execution, api.GrantResolveRequest{ReservationID: reservation.ID})
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "launch ticket differs from its retained reservation authority" || set.ID != "" ||
				len(state.tickets) != 1 || state.tickets[0].ReservationID != reservation.ID || len(state.ticketScopes) != 1 || state.ticketScopes[0].Actor != f.Execution.Actor || state.ticketScopes[0].ReadView == nil {
				t.Fatal("real grant resolver did not preserve the protected ticket refusal", err)
			}
		})
	}
}

func TestLaunchTicketScopeBoundary(t *testing.T) {
	f, reservation, _ := scopePlanningFixture(t)
	ctx := context.Background()
	request := api.LaunchTicketRequest{ReservationID: reservation.ID}
	public, err := f.State.Ticket(ctx, f.Human, f.Start.RootTicketID)
	if err != nil || !public.Redeemed {
		t.Fatal("public owner ticket read lost its retained consumed ticket", err)
	}
	// A fresh installed service reader is allowed: the durable planner claim
	// is authenticated by PlanLaunch, not borrowed as another component's ID.
	scope := f.Execution
	scope.Actor.ID = fx.ID(t)
	view, err := f.State.BeginRead(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	scope.ReadView = view
	private, err := f.State.LaunchTicket(ctx, scope, request)
	if err != nil || !reflect.DeepEqual(private, public) || scope.Actor.Kind != "service" || scope.Actor.ID == public.PrincipalID || scope.EndpointGeneration == public.EndpointGeneration {
		t.Fatal("private ticket read did not preserve its authentic service view", err)
	}
	for _, mutation := range []string{"borrowed_view", "different_config", "request_envelope", "frame_envelope"} {
		t.Run(mutation, func(t *testing.T) {
			foreign := scope
			want := api.CodeUnauthenticated
			switch mutation {
			case "borrowed_view":
				foreign.Actor.ID = fx.ID(t)
			case "different_config":
				foreign.Config = "foreign-config"
			case "request_envelope":
				foreign.Request, want = f.Human.Request, api.CodeForbidden
			case "frame_envelope":
				foreign.Frame, want = f.Human.Frame, api.CodeForbidden
			}
			selected, refusal := f.State.LaunchTicket(ctx, foreign, request)
			codeIs(t, refusal, want)
			if selected != (api.Ticket{}) {
				t.Fatal("foreign service scope returned private ticket bytes")
			}
		})
	}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = f.State.LaunchTicket(ctx, scope, request)
	codeIs(t, err, api.CodeUnauthenticated)
	for _, caller := range []api.Scope{f.Execution, func() api.Scope {
		foreign := f.Human
		foreign.Actor.ID = fx.ID(t)
		return foreign
	}()} {
		selected, refusal := f.State.Ticket(ctx, caller, public.ID)
		var typed *api.Error
		if !errors.As(refusal, &typed) || typed.Code != api.CodeNotFound || typed.Message != "ticket provenance differs from caller" || selected != (api.Ticket{}) {
			t.Fatal("public ticket provenance guard was relaxed", refusal)
		}
	}
}
