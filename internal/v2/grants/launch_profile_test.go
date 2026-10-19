package grants_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Retained request/store facts are unit wiring fixtures, not an authenticated
// native lane. No profile slot, credential, model request or write is supplied.
func profileReservation(t *testing.T, mode string, driver api.Driver) (*launchGraph, api.LaunchPlanRecord) {
	t.Helper()
	g := newLaunchGraph(t)
	record := g.plans["reservation-one"]
	if mode == "child" {
		record = g.parentReservation()
	}
	var frame api.Request
	if err := api.DecodeObject(g.blobs[record.Reservation.OriginalRequest.ID], &frame); err != nil {
		t.Fatal(err)
	}
	var body api.StartRequest
	if err := api.DecodeObject(frame.Params, &body); err != nil {
		t.Fatal(err)
	}
	body.Driver, record.Reservation.Driver = driver, driver
	templateID := g.tickets["root-ticket"].GrantSetID
	if mode == "child" {
		templateID = g.lanes[record.Reservation.ParentLifeID].GrantSetID
	}
	template := g.sets[templateID]
	template.Profiles[0].Driver = driver
	launchSeal(t, &template)
	g.sets[templateID] = template
	if mode == "child" {
		launch := g.launches[record.Reservation.Authority.ID]
		launch.GrantsSHA256 = template.SHA256
		g.launches[launch.ID] = launch
	}
	if mode == "adopt" {
		record.Reservation.Mode = "adopt"
		adopt := api.AdoptRequest{Lane: body.Lane, Level: body.Level, Role: body.Role,
			Task: body.Task, RootTicketID: body.RootTicketID, Grants: body.Grants, Driver: body.Driver,
			ProfileGrantID: body.ProfileGrantID, Model: body.Model, Effort: body.Effort, Budget: body.Budget,
			ExpectedPolicyGeneration: body.ExpectedPolicyGeneration, ImportManifest: g.metadata["source-object"].Ref}
		g.request(adopt, "lane.adopt", &record.Reservation)
	} else {
		g.request(body, "lane.start", &record.Reservation)
	}
	g.validReservation(record.Reservation)
	g.plans[record.Reservation.ID] = record
	return g, record
}

func closedProfileViews(t *testing.T, g *launchGraph) {
	t.Helper()
	for _, view := range g.views {
		if !view.closed {
			t.Fatal("profile resolution leaked its authority view")
		}
	}
}

func TestLaunchProfilePick(t *testing.T) {
	for _, mode := range []string{"root", "adopt", "child"} {
		for _, driver := range []struct {
			name string
			id   api.Driver
		}{{"codex", api.DriverCodex}, {"cli", api.DriverClaudock}} {
			t.Run(mode+"-"+driver.name, func(t *testing.T) {
				g, record := profileReservation(t, mode, driver.id)
				request := api.GrantResolveRequest{ReservationID: record.Reservation.ID}
				set, err := g.resolver.Resolve(context.Background(), g.scope, request)
				if err != nil {
					t.Fatal("profile control could not resolve its real grant set", err)
				}
				before := launchCopy(t, g.plans)
				first, err := g.resolver.ResolveProfile(context.Background(), g.scope, request)
				if err != nil || len(set.Profiles) != 1 || !reflect.DeepEqual(first, set.Profiles[0]) || first.ID == "profile-cap" {
					t.Fatal("approved selector did not resolve its issued member", err)
				}
				g.sets[set.ID] = set
				again, err := g.resolver.ResolveProfile(context.Background(), g.scope, request)
				if err != nil || !reflect.DeepEqual(first, again) || !reflect.DeepEqual(before, g.plans) {
					t.Fatal("profile replay changed its issued member or wrote a plan", err)
				}
				if mode == "child" && first.ParentGrantID != "profile-cap" || mode != "child" && first.ParentGrantID != "" {
					t.Fatal("profile resolution invented or lost a parent edge")
				}
				closedProfileViews(t, g)
			})
		}
	}
}

func TestLaunchProfileChoice(t *testing.T) {
	g, record := profileReservation(t, "root", api.DriverCodex)
	template := g.sets["root-template"]
	selected := template.Profiles[0]
	selected.ID, selected.ProfileID = "selected-cap", "profile-two"
	template.Profiles = append(template.Profiles, selected)
	launchSeal(t, &template)
	g.sets[template.ID] = template
	body := g.selection
	body.ProfileGrantID = selected.ID
	body.Grants.Profiles = append(body.Grants.Profiles, api.ProfileDelegation{ParentGrantID: selected.ID, ProfileID: selected.ProfileID,
		ExpiresAt: "2030-01-01T02:00:00Z"})
	g.request(body, "lane.start", &record.Reservation)
	g.validReservation(record.Reservation)
	g.plans[record.Reservation.ID] = record
	request := api.GrantResolveRequest{ReservationID: record.Reservation.ID}
	set, err := g.resolver.Resolve(context.Background(), g.scope, request)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := g.resolver.ResolveProfile(context.Background(), g.scope, request)
	if err != nil || len(set.Profiles) != 2 || !reflect.DeepEqual(profile, set.Profiles[1]) || profile.ID == selected.ID {
		t.Fatal("profile resolution chose another approved selector", err)
	}
	closedProfileViews(t, g)
}

func TestLaunchProfileSpend(t *testing.T) {
	for _, name := range []string{"free", "paid-ok", "paid-none"} {
		t.Run(name, func(t *testing.T) {
			g, record := profileReservation(t, "root", api.DriverCodex)
			body := g.selection
			template := g.sets["root-template"]
			template.Profiles[0].Paid = name != "free"
			launchSeal(t, &template)
			g.sets[template.ID] = template
			if name == "paid-ok" {
				body.Budget.SpendMicros = 100
			}
			g.request(body, "lane.start", &record.Reservation)
			g.validReservation(record.Reservation)
			g.plans[record.Reservation.ID] = record
			profile, err := g.resolver.ResolveProfile(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			if name == "paid-none" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || profile.ID != "" {
					t.Fatal("profile resolution exceeded retained spend", err)
				}
			} else if err != nil || profile.ID == "" || profile.Paid != template.Profiles[0].Paid {
				t.Fatal("profile resolution rejected authorized spend", err)
			}
			closedProfileViews(t, g)
		})
	}
}

func TestProfileRetainedRefused(t *testing.T) {
	g := newLaunchGraph(t)
	record := g.retained("resume")
	profile, err := g.resolver.ResolveProfile(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || profile.ID != "" {
		t.Fatal("retained profile was remapped as a new launch", err)
	}
	closedProfileViews(t, g)
}

func TestLaunchProfileGuards(t *testing.T) {
	for _, name := range []string{"selector", "ambiguous", "driver", "profile", "expiry", "expired", "delegation", "foreign", "lane-scope", "policy", "revoked", "stored", "input", "paid", "excluded", "changed-profile"} {
		t.Run(name, func(t *testing.T) {
			g, record := profileReservation(t, "root", api.DriverCodex)
			body := g.selection
			code := api.CodeForbidden
			template := g.sets["root-template"]
			switch name {
			case "selector":
				body.ProfileGrantID = "unknown-cap"
			case "ambiguous":
				body.Grants.Profiles = append(body.Grants.Profiles, body.Grants.Profiles[0])
				code = api.CodeInvalid // Duplicate declarations fail input validation before authority resolution.
			case "driver":
				template.Profiles[0].Driver = api.DriverClaudock
			case "profile":
				body.Grants.Profiles[0].ProfileID = "foreign-profile"
			case "expiry":
				body.Grants.Profiles[0].ExpiresAt = "2030-01-01T05:00:00Z"
			case "expired":
				template.Profiles[0].ExpiresAt = "2029-01-01T00:00:00Z"
			case "delegation":
				body.Grants.Profiles[0].Delegate = true
			case "foreign":
				g.scope.Config = "foreign-config"
			case "lane-scope":
				g.scope.Actor.Kind = "lane"
			case "policy":
				g.policy++
				code = api.CodeConflict
			case "revoked":
				template.Revoked = true
			case "stored":
				set, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
				if err != nil {
					t.Fatal(err)
				}
				set.Profiles[0].Provider = "other-provider"
				launchSeal(t, &set)
				g.sets[set.ID] = set
				code = api.CodeConflict
			case "input":
				code = api.CodeIntegrity
			case "paid":
				template.Profiles[0].Paid = true
			case "excluded":
				g.profileExclusions = []api.ID{template.Profiles[0].ProfileID}
			case "changed-profile":
				code = api.CodeConflict
				g.onBlob = func(id api.ID) {
					if id != "source-object" {
						return
					}
					g.onBlob = nil
					current := g.sets["root-template"]
					current.Profiles[0].Provider = "other-provider"
					launchSeal(t, &current)
					g.sets[current.ID] = current
				}
			}
			launchSeal(t, &template)
			g.sets[template.ID] = template
			g.request(body, "lane.start", &record.Reservation)
			g.plans[record.Reservation.ID] = record
			if name == "input" {
				g.blobs[record.Reservation.OriginalRequest.ID] = append(g.blobs[record.Reservation.OriginalRequest.ID], ' ')
			}
			profile, err := g.resolver.ResolveProfile(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || profile.ID != "" {
				t.Fatal("launch profile escaped its reservation guard", name, err)
			}
			if name == "changed-profile" && g.onBlob != nil {
				t.Fatal("profile freshness control missed its source read")
			}
			closedProfileViews(t, g)
		})
	}
}
