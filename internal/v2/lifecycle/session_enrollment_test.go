package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func enrolledClaudockFixture(t *testing.T) *launchFixture {
	t.Helper()
	f := newLaunchFixture(t)
	f.request.Driver, f.ports.enrollment.Runtimes[0].Driver = api.DriverClaudock, api.DriverClaudock
	for i := range f.ports.delegated.Profiles {
		f.ports.delegated.Profiles[i].Driver = api.DriverClaudock
	}
	f.service.deps.Claudock = f.ports
	f.scope = f.fixture.scope("lane.start", f.request, f.parent)
	return f
}

func TestClaudockSessionEnrollment(t *testing.T) {
	seen := map[string]bool{}
	for _, fault := range []string{"valid", "another-version", "missing", "digest", "empty-version", "ambiguous"} {
		t.Run(fault, func(t *testing.T) {
			f := enrolledClaudockFixture(t)
			runtime := &f.ports.enrollment.Runtimes[0]
			pin := runtime.SessionExecutable
			pin.Version = "enrolled-history-release-a"
			switch fault {
			case "another-version":
				pin.Version = "enrolled-history-release-b"
			case "missing":
				pin = api.Executable{}
			case "digest":
				pin.SHA256 = digestOfBytes([]byte("another vendor"))
			case "empty-version":
				pin.Version = ""
			case "ambiguous":
				var manifest api.RuntimeManifest
				if err := api.DecodeObject(f.store.blobs[runtime.Manifest.ID], &manifest); err != nil {
					t.Fatal(err)
				}
				manifest.Objects = append(manifest.Objects, manifest.Objects[0])
				raw, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				runtime.Manifest = f.blob("ambiguous-session-runtime", "manifest", raw)
			}
			runtime.SessionExecutable = pin
			_, reservation := f.reserve(t)
			scope, claim := f.claim(t, reservation)
			plan, err := f.service.PlanLaunch(context.Background(), scope, claim)
			if fault != "valid" && fault != "another-version" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || f.ports.calls["acquire"] != 0 || f.ports.calls["runner-start"] != 0 {
					t.Fatal("missing or mismatched session enrollment did not refuse before credential access", err)
				}
				return
			}
			if err != nil || plan.Runner.Session.VendorVersion != pin.Version ||
				!regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(plan.Runner.Session.VendorID) ||
				plan.Runner.Session.VendorID == string(plan.Runner.Session.ID) || seen[plan.Runner.Session.VendorID] {
				t.Fatal("planner did not bind a fresh UUID and exact enrolled vendor version", err)
			}
			seen[plan.Runner.Session.VendorID] = true
			replayed, err := f.service.PlanLaunch(context.Background(), scope, claim)
			if err != nil || replayed.Runner.Session != plan.Runner.Session || f.ports.calls["acquire"] != 1 {
				t.Fatal("planner replay replaced the enrolled vendor session or reacquired its credential", err)
			}
		})
	}
}
