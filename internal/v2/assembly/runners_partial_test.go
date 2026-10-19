//go:build laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPartialUnenrolledRunnersRefuse(t *testing.T) {
	claude, codexDriver, err := runnersForFixture(nil)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-serve" ||
		claude != nil || codexDriver != nil {
		t.Fatal("absent fixture installed substitute runners")
	}
}

func TestFixturePlanUsesReservedInputs(t *testing.T) {
	runtime, installed, values := runtimeFixture(t)
	declared, err := fixtureFromRuntime(runtime, installed, func(object api.RuntimeObject) ([]byte, error) { return values[object.ID], nil })
	if err != nil {
		t.Fatal(err)
	}
	declared.executablePath = "/runtime/serve-agent"
	declared.Mode, declared.Drivers = "lifecycle", []api.Driver{api.DriverClaudock, api.DriverCodex}
	claude, codexDriver, err := runnersForFixture(declared)
	if err != nil {
		t.Fatal(err)
	}
	for driver, runner := range map[api.Driver]api.Runner{api.DriverClaudock: claude, api.DriverCodex: codexDriver} {
		request := api.RunnerRequest{Target: api.LifeRef{LifeID: "reserved-life", Run: 1}, Executable: declared.Executable,
			Session: api.Session{ID: "session", Driver: driver, HomeID: "home", HistoryID: "history", LogicalCWD: "/work/main"},
			Home:    api.PrivateHome{ID: "home", WorkspaceID: "workspace", HistoryID: "history"},
			Prompt:  api.BlobRef{ID: "prompt", Class: "prompt", Bytes: 1, SHA256: runtime.Artifact.SHA256}, Model: "fixture-model-1", Effort: "low",
			Slot: api.CredentialSlot{ID: "slot", LeaseID: "lease", ProfileGrantID: "profile-grant", ProfileID: "profile",
				ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))}, Budget: api.Budget{WallMS: 60000}}
		if driver == api.DriverClaudock {
			request.Slot.Mode = "claude-api-key"
			request.Session.VendorID = "ceaa8ad6-75ad-4a71-9e40-4e468486184d"
			request.Session.VendorVersion = declared.Version
			missing := request
			missing.Session.VendorID = ""
			_, err := runner.Start(context.Background(), missing)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite {
				t.Fatal("fixture concealed a planner session-enrollment gap", err)
			}
		}
		plan, err := runner.Start(context.Background(), request)
		if err != nil || plan.Driver != driver || plan.Executable != request.Executable || plan.Home != request.Home ||
			plan.Prompt != request.Prompt || plan.Slot != request.Slot || plan.CWD != request.Session.LogicalCWD ||
			plan.Session.ID != request.Session.ID || len(plan.Argv) < 10 || plan.Argv[0] != declared.executablePath {
			t.Fatal("fixture plan changed reserved input", err)
		}
		if driver == api.DriverClaudock {
			if plan.Session != request.Session {
				t.Fatal("fixture replaced the planner's enrolled Claudock session")
			}
		} else if request.Session.VendorID != "" || request.Session.VendorVersion != "" ||
			plan.Session.VendorID != string(request.Session.ID) || plan.Session.VendorVersion != declared.Version {
			t.Fatal("Codex fixture session provenance differs from its enrolled runtime")
		}
		request.Home.ID = "foreign-home"
		if _, err := runner.Start(context.Background(), request); err == nil {
			t.Fatal("fixture planned a mismatched private home")
		}
	}
}

func TestEnrolledFixtureKeepsRealLaunchGate(t *testing.T) {
	runtime, installed, values := runtimeFixture(t)
	declared, err := fixtureFromRuntime(runtime, installed, func(object api.RuntimeObject) ([]byte, error) { return values[object.ID], nil })
	if err != nil {
		t.Fatal(err)
	}
	_, runner, err := runnersForFixture(declared)
	if err != nil {
		t.Fatal(err)
	}
	request := api.RunnerRequest{Executable: declared.Executable, Session: api.Session{Driver: declared.Driver}}
	for _, call := range []func(context.Context, api.RunnerRequest) (api.RunnerPlan, error){runner.Start, runner.Resume, runner.Turn} {
		plan, err := call(context.Background(), request)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-serve" ||
			!reflect.DeepEqual(plan, api.RunnerPlan{}) {
			t.Fatal("fixture bypassed real launch context")
		}
	}
	request.Executable = runtime.Artifact
	_, err = runner.Start(context.Background(), request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
		t.Fatal("fixture accepted another runtime")
	}
}
