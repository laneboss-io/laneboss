package grants_test

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestLaunchReservationPins(t *testing.T) {
	for _, mode := range []string{"start", "adopt"} {
		for _, pin := range []string{"level", "role", "driver", "ticket"} {
			t.Run(mode+"/"+pin, func(t *testing.T) {
				g := newLaunchGraph(t)
				r := g.plans["reservation-one"]
				body := g.selection
				switch pin {
				case "level":
					body.Level = 3
				case "role":
					body.Role = "executor"
				case "driver":
					body.Driver = api.DriverClaudock
				case "ticket":
					body.RootTicketID = "another-ticket"
				}
				if mode == "start" {
					g.request(body, "lane.start", &r.Reservation)
				} else {
					r.Reservation.Mode = "adopt"
					g.request(api.AdoptRequest{Lane: body.Lane, Level: body.Level, Role: body.Role, Task: body.Task,
						Grants: body.Grants, Budget: body.Budget, Driver: body.Driver, RootTicketID: body.RootTicketID,
						ProfileGrantID: body.ProfileGrantID, Model: body.Model, Effort: body.Effort,
						ExpectedPolicyGeneration: body.ExpectedPolicyGeneration, ImportManifest: g.metadata["source-object"].Ref}, "lane.adopt", &r.Reservation)
				}
				g.plans[r.Reservation.ID] = r
				// The record is valid; only the retained request disagrees with it.
				if err := api.ValidateLaunchPlanRecord(r); err != nil {
					t.Fatal(err)
				}
				result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
				launchError(t, err, api.CodeForbidden)
				if result.ID != "" || len(g.policyScopes) != 0 {
					t.Fatal("request pins reached policy or grant selection")
				}
			})
		}
	}
}

func TestLaunchStoredPolicyPins(t *testing.T) {
	g := newLaunchGraph(t)
	r := g.plans["reservation-one"].Reservation
	if _, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.ID}); err != nil {
		t.Fatal(err)
	}
	if len(g.policyScopes) == 0 {
		t.Fatal("stored policy pins were never read")
	}
	if len(g.policyRequests) != len(g.policyScopes) {
		t.Fatal("policy read lost its separate target selection")
	}
	for i, scope := range g.policyScopes {
		selection := g.policyRequests[i]
		if scope.Actor != g.scope.Actor || selection.Context.Level != r.Level || selection.Context.Role != r.Role || selection.Target != r.Target || selection.GrantSetID != r.GrantSetID || selection.PolicyGeneration != r.PolicyGeneration || selection.ReservationID != r.ID {
			t.Fatal("launch policy lost its stored reservation pins")
		}
	}
}

func TestLaunchConsumedProof(t *testing.T) {
	for _, fault := range []string{"missing", "foreign", "root", "lane"} {
		t.Run(fault, func(t *testing.T) {
			g := newLaunchGraph(t)
			r := g.plans["reservation-one"]
			if fault == "missing" || fault == "foreign" {
				r = g.retained("resume")
			} else if fault == "lane" {
				r = g.parentReservation()
			}
			var frame api.Request
			if err := api.DecodeObject(g.blobs[r.Reservation.OriginalRequest.ID], &frame); err != nil {
				t.Fatal(err)
			}
			frame.Proof = &api.ProofRef{ID: "foreign-proof", RequestSHA256: r.Reservation.RequestSHA256}
			if fault == "missing" {
				frame.Proof = nil
			}
			r.Reservation.OriginalRequest = g.encoded(r.Reservation.OriginalRequest.ID, "launch_request", frame, r.Reservation.OperationID)
			g.plans[r.Reservation.ID] = r
			_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			launchError(t, err, api.CodeForbidden)
		})
	}
}

func TestLaunchStarterAuthority(t *testing.T) {
	for _, fault := range []string{"id", "kind", "revoked", "actor", "run"} {
		t.Run(fault, func(t *testing.T) {
			g := newLaunchGraph(t)
			r := g.parentReservation()
			starter := g.launches[r.Reservation.Authority.ID]
			switch fault {
			case "id":
				starter.ID, r.Reservation.Authority.ID = "foreign-starter", "foreign-starter"
			case "kind":
				starter.Kind = "worker"
			case "revoked":
				starter.Revoked = true
			case "actor":
				starter.Actor.ID = "foreign-principal"
			case "run":
				starter.Target.Run++
			}
			g.launches[starter.ID], g.plans[r.Reservation.ID] = starter, r
			_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			launchError(t, err, api.CodeForbidden)
		})
	}
}

func TestRetainedReservationPins(t *testing.T) {
	for _, pin := range []string{"level", "role", "driver"} {
		t.Run(pin, func(t *testing.T) {
			g := newLaunchGraph(t)
			r := g.retained("resume")
			switch pin {
			case "level":
				r.Reservation.Level = 4
			case "role":
				r.Reservation.Role = "executor"
			case "driver":
				r.Reservation.Driver = api.DriverClaudock
			}
			g.plans[r.Reservation.ID] = r
			if err := api.ValidateLaunchPlanRecord(r); err != nil {
				t.Fatal(err)
			}
			_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			launchError(t, err, api.CodeConflict)
		})
	}
}

func TestRetainedPreparedBinding(t *testing.T) {
	for _, fault := range []string{"worker-kind", "legacy-kind", "role"} {
		t.Run(fault, func(t *testing.T) {
			g := newLaunchGraph(t)
			r := g.retained("resume")
			binding := g.bindings[r.Reservation.PreviousLaunchID]
			switch fault {
			case "worker-kind":
				binding.Record.Kind = "worker"
			case "legacy-kind":
				binding.Record.Kind = ""
			case "role":
				binding.Record.Actor.Role = "executor"
			}
			var err error
			binding.Identity.RecordSHA256, err = manifest.HashValue(binding.Record)
			if err != nil {
				t.Fatal(err)
			}
			g.bindings[binding.Record.ID] = binding
			_, err = g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			launchError(t, err, api.CodeInvalid)
		})
	}
}

func TestRetainedCaptureRequired(t *testing.T) {
	for _, mode := range []string{"resume", "turn", "continue"} {
		t.Run(mode, func(t *testing.T) {
			g := newLaunchGraph(t)
			g.capturePolicy, g.captureRefused = true, true
			r := g.retained(mode)
			_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			launchError(t, err, api.CodeForbidden)
		})
	}
}

func TestLaunchCaptureCurrentPolicy(t *testing.T) {
	for _, fault := range []string{"allowed", "disabled", "changed-during-read"} {
		t.Run(fault, func(t *testing.T) {
			g := newLaunchGraph(t)
			g.capturePolicy, g.captureRefused = true, true
			r := g.completed()
			if fault == "disabled" {
				g.capturePolicy = false
			} else if fault == "changed-during-read" {
				g.onBlob = func(id api.ID) {
					if id == "workspace-snapshot" {
						g.capturePolicy, g.onBlob = false, nil
					}
				}
			}
			result, err := g.worker.MaterializeLaunch(context.Background(), launchRequestFor(r))
			if fault == "allowed" {
				if err != nil || result.ReservationID != r.Reservation.ID {
					t.Fatal("approved capture refusal failed retained-data verification", err)
				}
			} else {
				launchError(t, err, api.CodeInvalid)
				if result.ReservationID != "" {
					t.Fatal("stale capture exception returned retained launch data")
				}
			}
		})
	}
}

func TestLaunchSourceDriverPin(t *testing.T) {
	g := newLaunchGraph(t)
	r := g.completed()
	r.Plan, r.Phase, r.Generation = nil, "sourced", 2
	r.Inputs.Sources.Runtime.Driver = api.DriverClaudock
	g.plans[r.Reservation.ID] = r
	g.helper.onSources = func(sources *api.LaunchSources) { sources.Runtime.Driver = api.DriverClaudock }
	if err := api.ValidateLaunchPlanRecord(r); err != nil {
		t.Fatal(err)
	}
	_, err := g.worker.MaterializeLaunch(context.Background(), launchRequestFor(r))
	launchError(t, err, api.CodeConflict)
}

func TestLaunchContinuationOperation(t *testing.T) {
	for _, fault := range []string{"intent-id", "pending-success"} {
		t.Run(fault, func(t *testing.T) {
			g := newLaunchGraph(t)
			r := g.retained("continue")
			operation := g.operations[r.Reservation.OperationID]
			code := api.CodeIntegrity
			if fault == "intent-id" {
				operation.ID = "continuation-one"
			} else {
				operation.Status, code = "succeeded", api.CodeConflict
			}
			g.operations[r.Reservation.OperationID] = operation
			_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			launchError(t, err, code)
		})
	}
}
