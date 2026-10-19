package grants_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDirectStarterLifecycle(t *testing.T) {
	for _, state := range []string{"preparing", "running", "stopping", "verifying", "idle", "profile_wait", "lost", "accepted", "merged", "abandoned", "unknown"} {
		t.Run(state, func(t *testing.T) {
			g := newLaunchGraph(t)
			r := g.parentReservation()
			lane := g.lanes[r.Reservation.ParentLifeID]
			lane.State = state
			g.lanes[lane.LifeID] = lane
			result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			switch state {
			case "lost", "accepted", "merged", "abandoned":
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Owner != "lb-v2-grants" || result.ID != "" {
					t.Fatal("post-exit direct starter delegated without a sealed lease", err)
				}
			case "unknown":
				launchError(t, err, api.CodeIntegrity)
			default:
				if err != nil || result.ParentLifeID != lane.LifeID {
					t.Fatal("live direct starter could not delegate", err)
				}
			}
		})
	}
}

func TestRetainedStarterAuthority(t *testing.T) {
	for _, mode := range []string{"resume", "turn"} {
		for _, fault := range []string{"sibling", "self", "kind", "revoked", "actor", "run", "policy", "level", "role"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				g := newLaunchGraph(t)
				g.parentReservation()
				r := g.retained(mode)
				before := launchCopy(t, g.sets[r.Reservation.GrantSetID])
				if result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID}); err != nil || !reflect.DeepEqual(result, before) {
					t.Fatal("retained ancestor positive control failed", err)
				}
				starter := g.launches[r.Reservation.Authority.ID]
				switch fault {
				case "sibling":
					r.Reservation.RequestedBy.LifeID = "sibling-life"
				case "self":
					r.Reservation.RequestedBy.LifeID = r.Reservation.Target.LifeID
				case "kind":
					starter.Kind = "worker"
				case "revoked":
					starter.Revoked = true
				case "actor":
					starter.Actor.ID = "other-principal"
				case "run":
					starter.Target.Run++
				case "policy":
					starter.PolicyGeneration++
				case "level":
					r.Reservation.RequestedBy.Level = r.Reservation.Level
				case "role":
					r.Reservation.RequestedBy.Role = "other-role"
				}
				g.launches[starter.ID] = starter
				g.plans[r.Reservation.ID] = r
				result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || result.ID != "" {
					t.Fatal("retained starter authority was not rechecked", err)
				}
			})
		}
	}
}

func TestRetainedBudgetBoundary(t *testing.T) {
	for _, mode := range []string{"resume", "turn"} {
		for _, fault := range []string{"invalid", "disk"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				g := newLaunchGraph(t)
				r := g.retained(mode)
				budget := g.selection.Budget
				code := api.CodeInvalid
				if fault == "invalid" {
					budget.Processes = 0
				} else {
					budget.DiskBytes = 1
					code = api.CodeBudget
				}
				var frame api.Request
				if err := api.DecodeObject(g.blobs[r.Reservation.OriginalRequest.ID], &frame); err != nil {
					t.Fatal(err)
				}
				if mode == "resume" {
					var request api.ResumeRequest
					if err := json.Unmarshal(frame.Params, &request); err != nil {
						t.Fatal(err)
					}
					request.Budget = budget
					g.request(request, "lane.resume", &r.Reservation)
				} else {
					var request api.TurnRequest
					if err := json.Unmarshal(frame.Params, &request); err != nil {
						t.Fatal(err)
					}
					request.Budget = budget
					g.request(request, "lane.turn", &r.Reservation)
				}
				g.plans[r.Reservation.ID] = r
				result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != code || result.ID != "" {
					t.Fatal("retained launch ignored its validated budget", err)
				}
			})
		}
	}
}
