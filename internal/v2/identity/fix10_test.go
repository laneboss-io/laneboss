package identity

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReservedPinsFixture(t *testing.T) {
	for _, rule := range []string{"level", "role", "driver", "authority", "human-starter", "lane-proof"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			if rule == "lane-proof" {
				store.record.ParentLifeID, store.record.RootLifeID = "parent-life", "parent-life"
				store.record.StarterChain, store.record.StarterEventSeq = []api.ID{"parent-life"}, 3
				store.lane.ParentLifeID, store.lane.RootLifeID = "parent-life", "parent-life"
				store.lane.StarterChain, store.lane.StarterEventSeq = []api.ID{"parent-life"}, 3
			}
			request := fixtureLaunchBinding(t, store.record)
			retainFixturePlan(t, store, request)
			if _, _, err := s.retainedLaunchPlan(context.Background(), *store.binding); err != nil {
				t.Fatalf("fixture setup: original reserved authority is invalid: %v", err)
			}
			switch rule {
			case "level", "role":
				if rule == "level" {
					store.binding.Record.Actor.Level = 3
				} else {
					store.binding.Record.Actor.Role = "executor"
				}
				// Keep the altered record correctly hashed. The immutable store
				// reservation, not the caller's role claim, must decide.
				store.binding.Identity.RecordSHA256 = launchBlob(t, "record", "manifest", store.binding.Record).SHA256
			case "driver":
				store.plan.Reservation.Driver = api.DriverClaudock
				store.plan.Plan.Reservation.Driver = api.DriverClaudock
			case "authority":
				store.plan.Reservation.Authority.ID = ""
				store.plan.Plan.Reservation.Authority.ID = ""
			case "human-starter":
				store.plan.Reservation.Authority.Kind = "starter"
				store.plan.Plan.Reservation.Authority.Kind = "starter"
			case "lane-proof":
				reservation := &store.plan.Reservation
				reservation.Authority = api.LaunchAuthority{Kind: "proof", ID: "borrowed-human-proof"}
				store.plan.Plan.Reservation = cloneLaunchValue(t, *reservation)
			}
			_, _, err := s.retainedLaunchPlan(context.Background(), *store.binding)
			fixtureCode(t, err, api.CodeInvalid)
		})
	}
}

func TestReadyDriverFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	request := fixtureLaunchBinding(t, store.record)
	retainFixturePlan(t, store, request)
	store.lane.Session.Driver = api.DriverClaudock
	permit, err := s.BindLaunch(context.Background(), request)
	fixtureCode(t, err, api.CodeConflict)
	if permit != (api.LaunchPermit{}) {
		t.Fatal("fixture check: ready lane changed its reserved driver")
	}
}

func TestCurrentCaptureFixture(t *testing.T) {
	for _, rule := range []string{"valid", "disabled", "approval"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			request := fixtureLaunchBinding(t, store.record)
			retainFixturePlan(t, store, request)
			switch rule {
			case "disabled":
				store.policy.AllowCaptureRefusal = false
			case "approval":
				store.policy.CaptureRefusalApprovalID = "other-approval"
			}
			permit, err := s.BindLaunch(context.Background(), request)
			if rule == "valid" {
				if err != nil || permit.PreparedID != request.Prepared.ID {
					t.Fatalf("fixture check: approved capture disposition refused: %v", err)
				}
				return
			}
			fixtureCode(t, err, api.CodeInvalid)
			if permit != (api.LaunchPermit{}) {
				t.Fatal("fixture check: stale capture exception returned a permit")
			}
		})
	}
}

func TestGrantProjectionFixture(t *testing.T) {
	for _, rule := range []string{"empty", "nested", "changed"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			plan := fixtureLaunchPlan(t, store.record)
			if rule == "nested" {
				plan.Inputs.Grants.Resources = []api.ResourceGrant{{ID: "resource", SourceHandle: "resource-source", Provider: "fixture",
					Regions: []string{}, ImageIDs: []string{}, MachineTypes: []string{}, ExpiresAt: plan.Inputs.Grants.ExpiresAt}}
			}
			request := plannedFixtureBinding(t, store.record, plan)
			retainCustomPlan(t, store, request, plan)
			current := cloneLaunchValue(t, *store.grants)
			current.Secrets, current.Network, current.Channels = nil, nil, nil
			if rule == "nested" {
				current.Resources[0].Regions, current.Resources[0].ImageIDs, current.Resources[0].MachineTypes = nil, nil, nil
			} else {
				current.Resources = nil
			}
			if rule == "changed" {
				current.Data[0].Access = "ro"
			}
			store.grants = &current
			before := cloneLaunchValue(t, current)
			beforePlan := cloneLaunchValue(t, store.plan.Plan.Inputs.Grants)
			permit, err := s.BindLaunch(context.Background(), request)
			if rule == "changed" {
				fixtureCode(t, err, api.CodeForbidden)
				if permit != (api.LaunchPermit{}) {
					t.Fatal("fixture check: altered grant content returned a permit")
				}
				return
			}
			if err != nil || permit.PreparedID != request.Prepared.ID || !reflect.DeepEqual(before, *store.grants) ||
				!reflect.DeepEqual(beforePlan, store.plan.Plan.Inputs.Grants) {
				t.Fatalf("fixture check: equivalent grant projection refused or changed: %v", err)
			}
		})
	}
}

func TestBindingKindsFixture(t *testing.T) {
	for _, kind := range []string{"", "worker", "unknown"} {
		t.Run("kind_"+kind, func(t *testing.T) {
			_, store, _ := serviceFixture(t)
			record := store.record
			record.Kind = kind
			fixtureCode(t, validateLaunch(record), api.CodeInvalid)
		})
	}
}

func TestWorkerPermitGapFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	request := fixtureLaunchBinding(t, store.record)
	retainFixturePlan(t, store, request)
	store.binding.Record.Kind, store.binding.Record.Actor.Kind = "worker", "worker"
	store.binding.Record.Actor.Level, store.binding.Record.Actor.Role = 0, ""
	store.binding.Identity.RecordSHA256 = launchBlob(t, "record", "manifest", store.binding.Record).SHA256
	store.binding.Recovery = nil
	permit, err := s.BindLaunch(context.Background(), request)
	fixtureCode(t, err, api.CodeNotImplemented)
	if permit != (api.LaunchPermit{}) {
		t.Fatal("fixture check: missing retained worker authority returned a permit")
	}
}

func TestWorkerRequestRefusalFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	request := fixtureLaunchBinding(t, store.record)
	retainFixturePlan(t, store, request)
	stored := cloneLaunchValue(t, *store.binding)
	request.Record.Kind, request.Record.Actor.Kind = "worker", "worker"
	request.Record.Actor.Level, request.Record.Actor.Role = 0, ""
	request.Identity.RecordSHA256 = launchBlob(t, "record", "manifest", request.Record).SHA256
	request.Recovery = nil
	permit, err := s.BindLaunch(context.Background(), request)
	fixtureCode(t, err, api.CodeInvalid)
	if permit != (api.LaunchPermit{}) || !reflect.DeepEqual(stored, *store.binding) {
		t.Fatal("fixture check: request worker labels changed stored authority or returned a permit")
	}
}
