package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlannerZeroRequest(t *testing.T) {
	for _, service := range []*Service{nil, {}, newFixture(t).service} {
		_, err := service.PlanLaunch(context.Background(), api.Scope{}, api.LaunchPlanRequest{})
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeInvalid {
			t.Fatalf("zero planner request did not return its typed shape error: %v", err)
		}
	}
}

func TestPlannerNilDependencies(t *testing.T) {
	owners := map[string]string{"Store": "lb-v2-service", "Identity": "lb-v2-identity", "Clock": owner,
		"Grants": "lb-v2-grants", "Sources": "lb-v2-admin", "Worker": "lb-v2-grants", "Capture": "lb-v2-admin",
		"Credentials": "lb-v2-secrets", "Templates": "lb-v2-templates", "Guidance": "lb-v2-guidance", "Codex": "lb-v2-codex", "Claudock": "lb-v2-claudock"}
	for field, expectedOwner := range owners {
		t.Run(field, func(t *testing.T) {
			f := newLaunchFixture(t)
			if field == "Claudock" {
				f.request.Driver = api.DriverClaudock
				f.ports.enrollment.Runtimes[0].Driver = api.DriverClaudock
				for i := range f.ports.delegated.Profiles {
					f.ports.delegated.Profiles[i].Driver = api.DriverClaudock
				}
				f.service.deps.Claudock = f.ports
				f.scope = f.fixture.scope("lane.start", f.request, f.parent)
			}
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			reflect.ValueOf(&f.service.deps).Elem().FieldByName(field).SetZero()
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Owner != expectedOwner || typed.Code != api.CodeNotImplemented && typed.Code != api.CodePrerequisite {
				t.Fatalf("nil planner dependency lost its owning typed failure: %s: %v", field, err)
			}
		})
	}
}

func TestEmptyPlannerService(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	_, err := (&Service{}).PlanLaunch(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented || typed.Owner != owner {
		t.Fatalf("empty planner lost its component-owned failure: %v", err)
	}
}

func TestEmptyServiceEntries(t *testing.T) {
	service := &Service{}
	for _, field := range []string{"LaneStart", "LaneAdopt", "LaneResume", "LaneTurn", "LaneStop", "LaneMark", "LaneReview", "LaneClean", "LaneArchive", "LaneCheck", "LaneLoop", "LaneInput", "LaneStatus", "LaneList", "LaneAttach", "EventTail", "Continue", "RevokeLaunch"} {
		t.Run(field, func(t *testing.T) {
			method := reflect.ValueOf(service).MethodByName(field)
			args := []reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(api.Scope{}), reflect.Zero(method.Type().In(2))}
			results := method.Call(args)
			err, ok := results[len(results)-1].Interface().(*api.Error)
			if !ok || err.Owner == "" {
				t.Fatalf("empty service entry did not return a typed dependency error: %s", field)
			}
		})
	}
}
