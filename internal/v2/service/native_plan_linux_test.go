//go:build linux

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	native "laneboss.io/laneboss/internal/v2/isolation/linux"
)

// The real Linux launcher owns spec, retained-plan and handoff validation.
// Native syscalls remain a fixture; the boundary test stops before any exec.
type nativePlanHelper struct {
	api.HelperControl
	registers int
	stop      error
	host      *Server
	state     *planningPolicyStore
	handoff   api.PreparedSpecHandoff
	prepared  api.PreparedLaunch
	process   *api.ProcessHandle
	permit    *api.LaunchPermit
	opens     int
}

func (h *nativePlanHelper) RegisterSpec(_ context.Context, handoff api.PreparedSpecHandoff) (api.PreparedSpecReceipt, error) {
	h.registers++
	if h.stop != nil {
		return api.PreparedSpecReceipt{}, h.stop
	}
	h.handoff = handoff
	return nativeSpecReceipt(handoff), nil
}

func nativeSpecReceipt(handoff api.PreparedSpecHandoff) api.PreparedSpecReceipt {
	return api.PreparedSpecReceipt{SpecID: handoff.Spec.ID, Config: handoff.Config, Target: handoff.Spec.Target,
		LeaseID: handoff.Spec.UIDLeaseID, SpecSHA256: handoff.SpecSHA256, RuntimeManifest: handoff.Spec.RuntimeManifest, OperationID: handoff.OperationID}
}

func (h *nativePlanHelper) ResolveRuntime(ctx context.Context, handoff api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	if !reflect.DeepEqual(handoff, h.handoff) {
		return api.ResolvedRuntime{}, serviceError(api.CodeIntegrity, "component runtime changed its registered handoff")
	}
	p := h.state.sourcePorts
	chunk, err := h.state.Blob(ctx, p.f.Execution, api.BlobReadRequest{ObjectID: handoff.Spec.RuntimeManifest.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	var manifest api.RuntimeManifest
	if err := api.DecodeObject(chunk.Data, &manifest); err != nil {
		return api.ResolvedRuntime{}, err
	}
	endpoint, err := wire.LaneEndpointBinding(h.host.deps.Binding, handoff.Spec, p.allocation)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	manifest.Bindings = []api.InstalledBinding{endpoint}
	return api.ResolvedRuntime{Manifest: manifest, SpecReceipt: nativeSpecReceipt(handoff), Home: handoff.Spec.Runner.Home,
		Workspace: handoff.Spec.Workspace, Network: api.NetworkLease{EndpointIDs: []api.ID{}}}, nil
}

func (h *nativePlanHelper) Prepare(ctx context.Context, request api.HelperLaunchRequest) (api.PreparedLaunch, error) {
	child, ok := api.EffectLeaseFromContext(ctx)
	if !ok || child.Record.Effect.HelperPrepare == nil {
		return api.PreparedLaunch{}, serviceError(api.CodeIntegrity, "component preparation lost its actual child claim")
	}
	expected := *child.Record.Effect.HelperPrepare
	expected.Cause.Actor = api.Actor{Kind: "service", ID: child.Record.ClaimantID}
	if request != expected {
		return api.PreparedLaunch{}, serviceError(api.CodeIntegrity, "component preparation changed its child request or current executor")
	}
	if err := h.state.ValidateLaunchControlClaim(ctx, child.Record.Effect.ID, child.ClaimID, child.Record.Generation); err != nil {
		return api.PreparedLaunch{}, err
	}
	spec, lease := h.handoff.Spec, h.state.sourcePorts.allocation
	h.prepared = api.PreparedLaunch{ID: api.ID("prepared-" + string(spec.LaunchID)), Target: spec.Target, SpecSHA256: request.SpecSHA256,
		ContainmentID: lease.ContainmentID, EndpointGeneration: lease.EndpointGeneration, ProcessGeneration: "component-process", GateID: api.ID("gate-" + string(spec.LaunchID))}
	return h.prepared, nil
}

func (h *nativePlanHelper) ReconcileGate(_ context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	if request.LeaseID != h.handoff.Spec.UIDLeaseID || request.LaunchID != h.handoff.Spec.LaunchID || request.PreparedID != h.prepared.ID || request.OperationID != h.handoff.OperationID {
		return api.LaunchReconciliation{}, serviceError(api.CodeIntegrity, "component reconciliation selected another gate")
	}
	if h.process == nil {
		return api.LaunchReconciliation{Prepared: &h.prepared, GateState: "prepared"}, nil
	}
	return api.LaunchReconciliation{Prepared: &h.prepared, Process: h.process, ConsumedPermit: h.permit, GateState: "consumed", Observation: h.observation()}, nil
}

func (h *nativePlanHelper) OpenGate(ctx context.Context, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	binding, err := h.state.LaunchBinding(ctx, request.Permit.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if request.Prepared != h.prepared || request.Permit.PreparedID != h.prepared.ID || request.Permit.CommittedSeq != binding.Identity.CommittedSeq ||
		request.Permit.RecordSHA256 != binding.Identity.RecordSHA256 || h.process != nil {
		return api.ProcessHandle{}, serviceError(api.CodeIntegrity, "component open lacks the original committed identity permit")
	}
	h.opens++
	h.permit = &request.Permit
	h.process = &api.ProcessHandle{ID: api.ID("process-" + string(request.Permit.LaunchID)), Target: h.prepared.Target,
		ContainmentID: h.prepared.ContainmentID, Generation: h.prepared.ProcessGeneration}
	return *h.process, nil
}

func (h *nativePlanHelper) observation() api.ProcessObservation {
	survivors := uint64(1)
	return api.ProcessObservation{Handle: *h.process, State: "running", Survivors: &survivors, PromptStatus: "written",
		ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
}

func (h *nativePlanHelper) ObserveGate(_ context.Context, request api.HelperObserveRequest) (api.ProcessObservation, error) {
	if h.process == nil || request.LeaseID != h.handoff.Spec.UIDLeaseID || request.Handle != *h.process {
		return api.ProcessObservation{}, serviceError(api.CodeIntegrity, "component observation selected another process")
	}
	return h.observation(), nil
}

func TestNativePlanBoundary(t *testing.T) {
	f, _, effect := scopeDriverFixture(t, 0, api.DriverClaudock)
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := scopePlanSetup(t, state, f, effect, nil, func(p *successfulPlanPorts) { p.profileMode = "helper" })
	host := launchServer(t, f)
	host.deps.Store = state
	stop := api.NotImplemented("native-test", "privileged registration boundary")
	helper := &nativePlanHelper{stop: stop}
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
	id, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: id}, Source: "worker"}
	lease, err := state.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID,
		ExpectedGeneration: 1, ClaimantID: id, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = host.runEffect(context.Background(), scope, lease)
	if helper.registers != 1 || !errors.Is(err, stop) {
		t.Fatal("store-built plan did not reach the privileged helper boundary", helper.registers, err)
	}
}

// All native syscalls remain an explicit helper fixture. The real Linux
// launcher, planner, service, broker, store, running state and events execute.
func TestNativePlanOpened(t *testing.T) {
	f, reservation, effect := scopeDriverFixture(t, 0, api.DriverClaudock)
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := scopePlanSetup(t, state, f, effect, nil, func(p *successfulPlanPorts) { p.profileMode = "helper" })
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
	id, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: id}, Source: "worker"}
	lease, err := state.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: id, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := host.runEffect(context.Background(), scope, lease)
	if err != nil {
		t.Fatal("store-built native plan did not reach opened publication", err)
	}
	if helper.registers != 1 || helper.opens != 1 || outcome.Process == nil || outcome.LaunchPlan == nil {
		t.Fatal("native plan omitted or repeated its measured launch stages")
	}
	if _, err := state.CompleteEffect(context.Background(), scope, outcome); err != nil {
		t.Fatal(err)
	}
	retained, err := state.LaunchPlan(context.Background(), scope, reservation.ID)
	if err != nil || retained.Phase != "opened" {
		t.Fatal("native launch did not retain opened state", err)
	}
	lane, err := state.Lane(context.Background(), scope, reservation.Target)
	if err != nil || lane.State != "running" || lane.Containment != "running" {
		t.Fatal("native launch did not publish the measured running state", err)
	}
	page, err := state.Events(context.Background(), scope, api.EventTailRequest{LifeID: reservation.Target.LifeID, Run: reservation.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	want := []api.EventKind{"identity.bound", "launch.prepared", "lane.created", "lane.started"}
	for _, event := range page.Events {
		if len(want) > 0 && event.Kind == want[0] {
			want = want[1:]
		}
	}
	if len(want) != 0 {
		t.Fatal("native launch omitted ordered identity, prepared, created or started events")
	}
}
