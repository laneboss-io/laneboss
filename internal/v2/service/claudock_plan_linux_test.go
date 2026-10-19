//go:build linux

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	native "laneboss.io/laneboss/internal/v2/isolation/linux"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Actual SQLite, grant resolution, encrypted credential acquisition, source
// enrollment, lifecycle planning and the installed Claudock adapter execute.
// Kernel/compatibility receipts and vendor bytes are declared component inputs;
// this test neither starts a vendor nor replaces installed compatibility proof.
func TestClaudockReservedPlan(t *testing.T) {
	for _, mode := range []string{"claude-api-key", "claudock-headless"} {
		t.Run(mode, func(t *testing.T) { claudockReservedPlan(t, mode) })
	}
}

func claudockReservedPlan(t *testing.T, mode string) {
	f, reservation, effect := scopeDriverFixtureWith(t, 0, api.DriverClaudock, func(f *fx.Fixture) {
		f.Start.Model = "claude-sonnet-4-6"
	})
	if mode == "claude-api-key" {
		// Primitive enrollment uses Fixture.Replace, which closes and reopens
		// f.State. Finish it before any dependency captures the writer.
		claudockPlanTestBalance(t, f)
	}
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	ctx := context.Background()
	if _, err := state.Lane(ctx, f.Execution, reservation.Target); !claudockPlanCode(err, api.CodeNotFound) {
		t.Fatal("new reservation unexpectedly has an already published child lane", err)
	}
	checkedMode, checkedSlot, checkedHome := false, false, false
	var retained api.RunnerRequest
	planner := scopePlanSetup(t, state, f, effect, nil, func(p *successfulPlanPorts) {
		p.profileMode = mode
		p.runner = reservedClaudockRunner(t, p, mode, &retained, &checkedMode, &checkedSlot, &checkedHome)
	})
	if state.Service != f.State {
		t.Fatal("fixture replaced the state writer after planner dependencies were bound")
	}
	host := launchServer(t, f)
	host.deps.Store = state
	helper := &nativePlanHelper{host: host, state: state}
	launcher, err := native.New(native.Dependencies{Helper: helper, RuntimeManifest: state.sourcePorts.runtime.Manifest, Controls: host})
	if err != nil {
		t.Fatal(err)
	}
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: planner, Helper: helper, Worker: state.sourcePorts, Launcher: launcher}
	t.Cleanup(func() {
		if err := host.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := api.Scope{Config: f.Deps.Config, Source: "worker", Actor: api.Actor{Kind: "service", ID: fx.ID(t)}}
	lease, err := state.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := host.runEffect(ctx, scope, lease)
	if err != nil {
		t.Fatalf("reserved Claudock plan could not reach opened publication: component=%s err=%v", api.ErrorComponent(err), err)
	}
	if outcome.LaunchPlan == nil || outcome.Process == nil || helper.registers != 1 || helper.opens != 1 ||
		!checkedMode || !checkedSlot || !checkedHome {
		t.Fatal("real adapter omitted its retained inputs or component guards")
	}
	plan := outcome.LaunchPlan
	if plan.Runner.Slot.Mode != mode || !reflect.DeepEqual(plan.Runner.Session, retained.Session) ||
		plan.Runner.Session.VendorID == "" || plan.Runner.Session.VendorVersion != plan.Inputs.Sources.Runtime.SessionExecutable.Version ||
		!reflect.DeepEqual(plan.Runner.EnvironmentNames, []string{api.ClaudeSlotEnvironment(mode)}) {
		t.Fatal("real adapter replaced its enrolled session, slot or environment selection")
	}
	if _, err := state.CompleteEffect(ctx, scope, outcome); err != nil {
		t.Fatal(err)
	}
	stored, err := state.LaunchPlan(ctx, scope, reservation.ID)
	if err != nil || stored.Phase != "opened" {
		t.Fatal("opened Claudock plan was not durably published", err)
	}
	if state.Service != f.State {
		t.Fatal("opened publication used a different writer from the active fixture")
	}
	lane, err := state.Lane(ctx, scope, reservation.Target)
	if err != nil || lane.State != "running" || lane.Containment != "running" || lane.Session != plan.Runner.Session {
		t.Fatal("Claudock plan did not publish the exact running session", err)
	}
	t.Logf("reserved Claudock mode=%s child_lane_absent_before_plan=true opened=true", mode)
}

func claudockPlanTestBalance(t *testing.T, f *fx.Fixture) {
	t.Helper()
	ctx := context.Background()
	slot := api.CredentialSlot{ProfileID: f.Ceiling.Profiles[0].ProfileID, Mode: "claude-api-key"}
	if _, err := f.State.CheckCredentialSpend(ctx, slot); !claudockPlanCode(err, api.CodePrerequisite) {
		t.Fatal("component API profile did not require its missing balance reading", err)
	}
	path := filepath.Join(t.TempDir(), "test-balance")
	// This fixed fake reading is fixture input, like the installed canary's
	// CANARY tool. It queries no vendor and is never evidence of paid balance.
	source := []byte("#!/bin/sh\n# Fake component-test balance; no vendor query.\nprintf 'TEST-CLAUDOCK-PLAN  10.00 USD\\n'\n")
	if err := os.WriteFile(path, source, 0700); err != nil {
		t.Fatal(err)
	}
	tool := admin.BalanceTool{Command: path, Selector: "TEST-CLAUDOCK-PLAN", CredentialID: fx.ID(t),
		ProfileIDs: []api.ID{slot.ProfileID}, FloorMicros: 5000000}
	reading, err := tool.Reading(ctx)
	if err != nil {
		t.Fatal("marked test balance tool failed", err)
	}
	amount, err := admin.PoolReading(reading)
	if err != nil {
		t.Fatal("marked test balance output did not parse", err)
	}
	// This component fixture has no native administrator listener. Seed only
	// its primitive reading/mapping from the operator tool's actual stdout;
	// lifecycle, runner and store spend checks execute without replacement.
	pool := api.SpendBalance{CredentialID: reading.CredentialID, SeedMicros: amount, ReadingMicros: amount,
		RemainingMicros: amount, AnchorMicros: amount, FloorMicros: reading.FloorMicros, Generation: 1, ObservedAt: reading.ObservedAt}
	f.Replace(t, "spend_pool", pool.CredentialID, pool.Generation, pool)
	f.Replace(t, "spend_profile", slot.ProfileID, 1, struct{ CredentialID api.ID }{pool.CredentialID})
	f.Replace(t, "spend_reading", reading.ID, 1, struct {
		Reading api.SpendReading
		Balance api.SpendBalance
	}{reading, pool})
	actual, err := f.State.CheckCredentialSpend(ctx, slot)
	if err != nil || actual != pool || string(reading.Output) != "TEST-CLAUDOCK-PLAN  10.00 USD\n" {
		t.Fatal("API profile lost its exact marked test balance or mapping", err)
	}
	t.Log("API balance fixture: TEST-CLAUDOCK-PLAN fake tool reading enrolled; no authenticated vendor balance")
}

func reservedClaudockRunner(t *testing.T, p *successfulPlanPorts, mode string, retained *api.RunnerRequest, checkedMode, checkedSlot, checkedHome *bool) func(api.GrantResolver, api.CredentialBroker) api.Runner {
	t.Helper()
	ctx, f := context.Background(), p.f
	keep := func(raw []byte) api.BlobRef {
		ref := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
		cause := f.Intent(t, api.InternalOrgBootstrap)
		_, err := p.state.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
			Writes: api.StateWrites{Objects: []api.ObjectWrite{{ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256,
				Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}}})
		if err != nil {
			t.Fatal("component runtime bootstrap publication failed", err)
		}
		return ref
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := api.Executable{ID: "claudock", Version: claudock.ClaudockVersion, SHA256: fx.Digest(bytes)}
	vendor := api.Executable{ID: "claude", Version: claudock.ClaudeVersion, SHA256: fx.Digest(bytes)}
	chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: p.runtime.Manifest.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(chunk.Data, &runtime); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []api.Executable{wrapper, vendor} {
		if err := os.WriteFile(filepath.Join(parent, string(pin.ID)), bytes, 0555); err != nil {
			t.Fatal(err)
		}
		runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: pin.ID, Role: string(pin.ID), RootID: "component-vendors",
			RelativePath: string(pin.ID), Mode: 0555, Content: api.BlobRef{ID: pin.ID, Class: "artifact", Bytes: int64(len(bytes)), SHA256: pin.SHA256}})
	}
	p.runtime.Executable, p.runtime.SessionExecutable = wrapper, vendor
	p.runtime.Manifest = keep(fx.JSON(t, runtime))
	chunk, err = f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: p.enrollment.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var enrollment api.LaunchEnrollment
	if err := api.DecodeObject(chunk.Data, &enrollment); err != nil {
		t.Fatal(err)
	}
	enrollment.Runtimes = []api.LaunchRuntime{p.runtime}
	p.enrollment = keep(fx.JSON(t, enrollment))
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
	admin := &successfulPlanAdmin{p: p}
	missing := func(name string) error { return api.NotImplemented("lb-v2-service", name) }
	selectRun := func(ctx context.Context, target api.LifeRef) (claudock.LaunchSelector, error) {
		lease, ok := api.EffectLeaseFromContext(ctx)
		if !ok || lease.Record.Effect.PlanLaunch == nil || target != f.Reservation.Target || p.allocation.ID == "" {
			return claudock.LaunchSelector{}, serviceError(api.CodeForbidden, "component runner lost its planning claim")
		}
		claim := api.PlanningClaim(f.Reservation.ID, lease)
		if err := api.CheckPlanningClaim(lease.Record, claim, f.Deps.Config, f.Deps.Clock.Now()); err != nil {
			return claudock.LaunchSelector{}, err
		}
		return claudock.LaunchSelector{Scope: api.Scope{Config: f.Deps.Config, Source: "worker", PolicyGeneration: f.Reservation.PolicyGeneration,
			Actor: api.Actor{Kind: "service", ID: claim.ClaimantID}}, ReservationID: claim.ReservationID, EffectID: claim.EffectID,
			ClaimID: claim.ClaimID, HelperLeaseID: p.allocation.ID}, nil
	}
	deps := claudock.Dependencies{Config: f.Deps.Config, State: p.state, Clock: f.Deps.Clock, Sources: admin, Storage: admin,
		UsageWindows: reservedPlanUsage{}, CaptureControl: p, Records: records,
		Executable: wrapper, ExecutablePath: filepath.Join(parent, "claudock"), Claude: vendor, ClaudePath: filepath.Join(parent, "claude"),
		RuntimePath: "/runtime/claudock", SelectLaunch: selectRun,
		Run: func(ctx context.Context, target api.LifeRef) (api.RunnerRequest, error) {
			selection, err := selectRun(ctx, target)
			if err != nil {
				return api.RunnerRequest{}, err
			}
			id := api.ID(fx.Digest([]byte("launch\x00" + string(selection.ReservationID) + "\x00input-runner")))
			meta, err := p.state.ObjectMetadata(ctx, selection.Scope, id)
			if err != nil {
				return api.RunnerRequest{}, err
			}
			chunk, err := p.state.Blob(ctx, selection.Scope, api.BlobReadRequest{ObjectID: id, Limit: api.MaxChunkBytes})
			if err != nil || meta.Origin != "service" || meta.SourceOperationID != f.Reservation.OperationID || meta.ACL.LifeID != target.LifeID || fx.Digest(chunk.Data) != meta.Ref.SHA256 {
				return api.RunnerRequest{}, serviceError(api.CodeIntegrity, "component runner input lost its protected provenance")
			}
			var request api.RunnerRequest
			if api.DecodeObject(chunk.Data, &request) != nil || request.Target != target {
				return request, serviceError(api.CodeIntegrity, "component runner input differs from the reserved target")
			}
			*retained = request
			return request, nil
		},
		HomePath: func(_ context.Context, binding api.PrivateHomeBinding) (string, error) {
			if p.data == nil || binding != p.data.Stage.Storage.Storage.Home || home.AuditOwned() != nil {
				return "", serviceError(api.CodeIntegrity, "component private home changed")
			}
			*checkedHome = true
			return home.Path(), nil
		},
		Profile: func(ctx context.Context, slot api.CredentialSlot) (api.ProfileGrant, error) {
			set, err := p.state.Grants(ctx, f.Reservation.GrantSetID)
			if err != nil {
				return api.ProfileGrant{}, err
			}
			for _, profile := range set.Profiles {
				if profile.ID == slot.ProfileGrantID && profile.ProfileID == slot.ProfileID {
					return profile, nil
				}
			}
			return api.ProfileGrant{}, serviceError(api.CodeForbidden, "component slot is outside retained grants")
		},
		VerifyMode: func(_ context.Context, actualWrapper, actualVendor api.Executable, actualMode string) error {
			if actualWrapper != wrapper || actualVendor != vendor || actualMode != mode {
				return serviceError(api.CodeForbidden, "component compatibility receipt differs")
			}
			*checkedMode = true
			return nil
		},
		VerifySlot: func(ctx context.Context, request api.RunnerRequest, umask uint32) error {
			if p.broker == nil || umask != claudock.RequiredUmask || request.Slot.Mode != mode {
				return serviceError(api.CodeForbidden, "component slot bootstrap selection differs")
			}
			lease, ok := api.EffectLeaseFromContext(ctx)
			if !ok {
				return serviceError(api.CodeForbidden, "component bootstrap lost its claim")
			}
			storage, err := p.broker.VerifyRunnerSlot(ctx, api.PlanningClaim(f.Reservation.ID, lease), request)
			if err != nil {
				return err
			}
			if storage.Home.Home != request.Home {
				return serviceError(api.CodeIntegrity, "component broker returned another home")
			}
			*checkedSlot = true
			return home.AuditOwned()
		},
		ReportHome: func(_ context.Context, actual api.PrivateHome, findings []claudock.Finding) error {
			if p.data == nil || actual != p.data.Stage.Storage.Storage.Home.Home || len(findings) != 0 {
				return serviceError(api.CodeIntegrity, "component home findings differ")
			}
			return home.AuditOwned()
		},
		Capture: func(context.Context, api.ID) (api.CaptureRecord, []byte, error) {
			return api.CaptureRecord{}, nil, missing("outside capture")
		},
		Observation: func(context.Context, api.LifeRef) (api.ProcessObservation, error) {
			return api.ProcessObservation{}, missing("outside terminal observation")
		},
		LimitGuard: func(context.Context, api.RunnerRequest, api.CaptureRecord, api.ProcessObservation) error {
			return missing("outside refusal coverage")
		},
	}
	if deps.VerifyMode(ctx, vendor, wrapper, mode) == nil || *checkedMode || deps.VerifySlot(ctx, api.RunnerRequest{}, 0) == nil || *checkedSlot {
		t.Fatal("component compatibility or bootstrap guard accepted its negative control")
	}
	return func(resolver api.GrantResolver, broker api.CredentialBroker) api.Runner {
		deps.Grants, deps.Credentials = resolver, broker
		runner, err := claudock.NewInstalled(deps)
		if err != nil {
			t.Fatal(err)
		}
		return runner
	}
}

type reservedPlanUsage struct{}

func (reservedPlanUsage) ReadUsageWindow(context.Context, api.Scope, api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	return api.UsageWindowEvidence{}, api.NotImplemented("lb-v2-service", "outside usage evidence")
}

func claudockPlanCode(err error, code api.ErrorCode) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed.Code == code
}
