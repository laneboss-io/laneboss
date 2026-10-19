//go:build linux && laneboss_root_canary

package lifecycle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// This gate uses the real lifecycle planner and Claudock adapter. Dependency
// selectors/receipts are explicit component fixtures. A missing product
// capability remains a refusal; no synthetic RunnerPlan can credit this gate.
// The separate native-delivery canary measures the helper and kernel path.
func TestAPIKeyCanary(t *testing.T) {
	for _, mode := range []string{"claude-api-key", "claudock-headless"} {
		t.Run(mode, func(t *testing.T) { apiKeyEnrolledCanary(t, mode) })
	}
}

func apiKeyEnrolledCanary(t *testing.T, mode string, vendorPath ...string) (*launchFixture, api.LaunchPlan, string) {
	f := newLaunchFixture(t)
	f.request.Driver = api.DriverClaudock
	if len(vendorPath) == 1 {
		f.request.Model = "claude-sonnet-4-6"
	}
	for index := range f.ports.delegated.Profiles {
		f.ports.delegated.Profiles[index].Driver = api.DriverClaudock
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	vendorBytes := self
	if len(vendorPath) == 1 {
		vendorBytes, err = os.ReadFile(vendorPath[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"claudock", "claude"} {
		data := self
		if name == "claude" {
			data = vendorBytes
		}
		if err := os.WriteFile(filepath.Join(parent, name), data, 0555); err != nil {
			t.Fatal(err)
		}
	}
	wrapper := api.Executable{ID: "claudock", SHA256: digestOfBytes(self), Version: claudock.ClaudockVersion}
	vendor := api.Executable{ID: "claude", SHA256: digestOfBytes(vendorBytes), Version: claudock.ClaudeVersion}
	// Enroll the same basename, mode, role and digest-bound vendor objects
	// selected by assembly.loadRealRuntime. Keep the fixture's worker pins;
	// these stand-in bytes still supply no live compatibility evidence.
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(f.store.blobs[f.ports.enrollment.Runtimes[0].Manifest.ID], &runtime); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []api.Executable{wrapper, vendor} {
		size := len(self)
		if pin.ID == vendor.ID {
			size = len(vendorBytes)
		}
		runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: pin.ID, Role: string(pin.ID), RootID: "canary-runtime",
			RelativePath: string(pin.ID), Mode: 0555, Content: api.BlobRef{ID: pin.ID, Class: "artifact", SHA256: pin.SHA256, Bytes: int64(size)}})
	}
	runtimeBytes, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	f.ports.enrollment.Runtimes[0].Manifest = f.blob("canary-enrolled-runtime", "manifest", runtimeBytes)
	f.ports.enrollment.Runtimes[0].Driver, f.ports.enrollment.Runtimes[0].Executable = api.DriverClaudock, wrapper
	f.ports.enrollment.Runtimes[0].SessionExecutable = vendor
	broker := &apiKeyCanaryBroker{launchFixturePorts: f.ports, mode: mode}
	// Installed assembly constructs its stable real runner ports before
	// lifecycle.New. Per-run selectors are populated only after reservation;
	// constructing the adapter must not require an already-planned launch.
	var reservation api.LaunchPlanRecord
	var scope api.Scope
	var claim api.LaunchPlanRequest
	admin := &launchFixtureAdmin{ports: f.ports}
	recordPath := filepath.Join(parent, "records")
	if err := os.Mkdir(recordPath, 0700); err != nil {
		t.Fatal(err)
	}
	records, err := claudock.NewRecords(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := records.Close(); err != nil {
			t.Error(err)
		}
	})
	home, err := claudock.CreateHome(filepath.Join(parent, "home"), records)
	if err != nil {
		t.Fatal(err)
	}
	homeIdentity, err := os.Lstat(home.Path())
	if err != nil {
		t.Fatal(err)
	}
	// These component guards check their pinned inputs and real private tree.
	// They do not install compatibility proof into the production assembly.
	missing := func(capability string) error { return api.NotImplemented("lb-v2-claudock", capability) }
	modeChecked, slotChecked, homeChecked := false, false, false
	driverDeps := claudock.Dependencies{
		Config: f.scope.Config, State: f.store, Sources: admin, Storage: admin, Grants: f.ports,
		Credentials: broker, CaptureControl: admin, Clock: f.service.deps.Clock, Records: records,
		UsageWindows: broker,
		Executable:   wrapper, ExecutablePath: filepath.Join(parent, "claudock"), Claude: vendor, ClaudePath: filepath.Join(parent, "claude"),
		RuntimePath: "/runtime/claudock",
		SelectLaunch: func(_ context.Context, target api.LifeRef) (claudock.LaunchSelector, error) {
			if target != reservation.Reservation.Target {
				return claudock.LaunchSelector{}, launchMissing()
			}
			return claudock.LaunchSelector{Scope: scope, ReservationID: reservation.Reservation.ID,
				EffectID: claim.Lease.Record.Effect.ID, ClaimID: claim.Lease.ClaimID,
				HelperLeaseID: f.ports.allocations[reservation.Reservation.ID].ID}, nil
		},
		Run: func(_ context.Context, target api.LifeRef) (api.RunnerRequest, error) {
			var request api.RunnerRequest
			if api.DecodeObject(f.store.blobs[launchObjectID(reservation.Reservation.ID, "input-runner")], &request) != nil || request.Target != target {
				return request, launchMissing()
			}
			return request, nil
		},
		HomePath: func(_ context.Context, binding api.PrivateHomeBinding) (string, error) {
			lease := f.ports.allocations[reservation.Reservation.ID]
			actual, err := os.Lstat(home.Path())
			if err != nil || !os.SameFile(homeIdentity, actual) || binding != f.ports.storage[lease.ID].Home {
				return "", launchConflict()
			}
			homeChecked = true
			return home.Path(), nil
		},
		Profile: func(_ context.Context, slot api.CredentialSlot) (api.ProfileGrant, error) {
			for _, grant := range f.store.grants[reservation.Reservation.GrantSetID].Profiles {
				if grant.ID == slot.ProfileGrantID && grant.ProfileID == slot.ProfileID {
					return grant, nil
				}
			}
			return api.ProfileGrant{}, launchMissing()
		},
		VerifyMode: func(_ context.Context, actualWrapper, actualVendor api.Executable, actualMode string) error {
			if actualWrapper != wrapper || actualVendor != vendor || actualMode != mode ||
				f.ports.enrollment.Runtimes[0].SessionExecutable != actualVendor {
				return launchConflict()
			}
			modeChecked = true
			return nil
		},
		VerifySlot: func(_ context.Context, request api.RunnerRequest, umask uint32) error {
			lease := f.ports.allocations[reservation.Reservation.ID]
			if umask != claudock.RequiredUmask || request.Slot != broker.slots[request.Target] || request.Slot.Mode != mode ||
				request.Home != f.ports.storage[lease.ID].Home.Home || request.Session.VendorVersion != vendor.Version {
				return launchConflict()
			}
			slotChecked = true
			return home.AuditOwned()
		},
		Capture: func(context.Context, api.ID) (api.CaptureRecord, []byte, error) {
			return api.CaptureRecord{}, nil, missing("real capture frame")
		},
		Observation: func(context.Context, api.LifeRef) (api.ProcessObservation, error) {
			return api.ProcessObservation{}, missing("real terminal observation")
		},
		ReportHome: func(_ context.Context, actual api.PrivateHome, findings []claudock.Finding) error {
			lease := f.ports.allocations[reservation.Reservation.ID]
			if actual != f.ports.storage[lease.ID].Home.Home || len(findings) != 0 {
				return launchConflict()
			}
			return home.AuditOwned()
		},
		LimitGuard: func(context.Context, api.RunnerRequest, api.CaptureRecord, api.ProcessObservation) error {
			return missing("whole-run refusal coverage")
		},
	}
	wrongPin := vendor
	wrongPin.SHA256 = digestOfBytes([]byte("different installed vendor"))
	if driverDeps.VerifyMode(context.Background(), wrapper, wrongPin, mode) == nil || modeChecked ||
		driverDeps.VerifySlot(context.Background(), api.RunnerRequest{}, 0) == nil || slotChecked {
		t.Fatal("component mode or slot guard accepted its negative control")
	}
	driver, err := claudock.NewInstalled(driverDeps)
	if err != nil {
		t.Fatal("real API key runner construction refused", err)
	}
	deps := f.service.deps
	deps.Credentials, deps.Claudock = broker, driver
	f.service, err = New(deps)
	if err != nil {
		t.Fatal("API key lifecycle construction refused its real adapter", err)
	}
	f.scope = f.fixture.scope("lane.start", f.request, f.parent)
	_, reservation = f.reserve(t)
	scope, claim = f.claim(t, reservation)
	t.Log("API key reservation passed with the real installed Claudock adapter bound before lifecycle construction")
	plan, err := f.service.PlanLaunch(context.Background(), scope, claim)
	if err != nil {
		var request api.RunnerRequest
		if api.DecodeObject(f.store.blobs[launchObjectID(reservation.Reservation.ID, "input-runner")], &request) == nil {
			t.Logf("retained runner input: mode=%s vendor_id_present=%t vendor_version_present=%t", request.Slot.Mode,
				request.Session.VendorID != "", request.Session.VendorVersion != "")
		}
		t.Fatal("real lifecycle/runner API key canary stopped", err)
	}
	if plan.Runner.Slot.Mode != mode || len(plan.Runner.EnvironmentNames) != 1 || plan.Runner.EnvironmentNames[0] != api.ClaudeSlotEnvironment(mode) {
		t.Fatal("real lifecycle API key plan selected another mode or environment")
	}
	var retained api.RunnerRequest
	if api.DecodeObject(f.store.blobs[launchObjectID(reservation.Reservation.ID, "input-runner")], &retained) != nil ||
		!reflect.DeepEqual(plan.Runner.Session, retained.Session) || retained.Session.VendorVersion != vendor.Version ||
		!modeChecked || !slotChecked || !homeChecked {
		t.Fatal("real adapter did not consume the planner's protected enrolled session and guards")
	}
	return f, plan, home.Path()
}

type apiKeyCanaryBroker struct {
	*launchFixturePorts
	mode string
}

func (p *apiKeyCanaryBroker) Acquire(ctx context.Context, target api.LifeRef, grant api.ProfileGrant) (api.CredentialSlot, error) {
	slot, err := p.launchFixturePorts.Acquire(ctx, target, grant)
	if err != nil {
		return slot, err
	}
	slot.Mode = p.mode
	p.slots[target] = slot
	return slot, nil
}

func (*apiKeyCanaryBroker) ReadUsageWindow(context.Context, api.Scope, api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	return api.UsageWindowEvidence{}, api.NotImplemented("lb-v2-secrets", "outside usage evidence")
}
