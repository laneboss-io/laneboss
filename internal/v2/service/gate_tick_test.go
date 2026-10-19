//go:build linux

package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/runner/codex"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

// Only the native reports are doubled. Plans, observations, loop health,
// mutation admission and the second launch reservation use production code.
type gateTickHelper struct {
	api.HelperControl
	api.PeerVerifier
	mu          sync.Mutex
	request     api.HelperReconcileRequest
	capture     api.CaptureBinding
	gate        api.LaunchReconciliation
	containment api.ContainmentBinding
	probe       api.IsolationCapabilities
	calls       int
}

func (h *gateTickHelper) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return api.LaunchReconciliation{}, err
	}
	if request != h.request {
		return api.LaunchReconciliation{}, serviceError(api.CodeIntegrity, "tick selected another retained gate")
	}
	h.calls++
	return h.gate, nil
}

func (h *gateTickHelper) ResolveContainment(ctx context.Context, facts api.PeerFacts, binding api.InstalledBinding) (api.ContainmentBinding, error) {
	if err := ctx.Err(); err != nil {
		return api.ContainmentBinding{}, err
	}
	if binding.LaunchID != h.request.LaunchID || binding.Target == nil || *binding.Target != h.containment.Target ||
		facts.HostUID != h.containment.Lease.UID || facts.HostGID != h.containment.Lease.GID || facts.ContainmentID != h.containment.Lease.ContainmentID {
		return api.ContainmentBinding{}, serviceError(api.CodeContainmentUnknown, "peer selected another native containment report")
	}
	return h.containment, nil
}

// Admission only probes availability. This adapter exposes the same explicit
// native report without replacing launcher or lifecycle mutation behavior.
type gateTickProbe struct {
	api.Launcher
	helper *gateTickHelper
}

func (p *gateTickProbe) Probe(ctx context.Context) (api.IsolationCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return api.IsolationCapabilities{}, err
	}
	return p.helper.probe, nil
}

func (h *gateTickHelper) ReconcileCapture(ctx context.Context, capture api.CaptureBinding) (api.CaptureBinding, error) {
	if err := ctx.Err(); err != nil {
		return api.CaptureBinding{}, err
	}
	if !reflect.DeepEqual(capture, h.capture) {
		return api.CaptureBinding{}, serviceError(api.CodeIntegrity, "tick changed the retained capture")
	}
	return capture, nil
}

func gateTickOrg(t *testing.T, f *fx.Fixture) {
	t.Helper()
	ctx := context.Background()
	policy, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	policy.Context = api.RoleContext{Level: f.Start.Level, Role: f.Start.Role}
	policy.GuidanceHalfLifeSeconds, policy.GuidanceMinRelevance, policy.SHA256 = 3600, .5, ""
	canonical, err := api.CanonicalJSON(fx.JSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	policy.SHA256 = fx.Digest(canonical)
	f.Replace(t, "policy", api.ID(f.Deps.Config), policy.Generation, policy)
	objects := []api.ObjectWrite{}
	keep := func(class string, data []byte) api.BlobRef {
		ref := api.BlobRef{ID: fx.ID(t), Class: class, Bytes: int64(len(data)), SHA256: fx.Digest(data)}
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: class, Bytes: data, SHA256: ref.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "config", Generation: 1}})
		return ref
	}
	files := []api.ResourceFile{}
	for _, source := range []struct{ path, kind, file string }{
		{templates.OrgTemplatePath, "prompt", "default.md"},
		{templates.OrgDriversPath, "drivers", "drivers.toml"},
		{templates.WorkflowPath, "policy", "workflow.toml"},
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", "org", source.file))
		if err != nil {
			t.Fatal(err)
		}
		ref := keep("artifact", data)
		files = append(files, api.ResourceFile{Source: api.SourceRef{ID: fx.ID(t), Path: source.path, SHA256: ref.SHA256, Generation: 1},
			Content: ref, Kind: source.kind, Mode: 0444, RevisionGeneration: 1})
	}
	ownership := keep("manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}))
	inventory := keep("manifest", fx.JSON(t, files))
	snapshot := api.OrgSnapshot{Config: f.Deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: inventory.SHA256},
		Sources: files, Derived: []api.ResourceFile{}, OwnershipManifest: ownership,
		Renderer:    api.Executable{ID: fx.ID(t), SHA256: inventory.SHA256, Version: "fixture-v2"},
		PublishedBy: fx.ID(t), PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalOrgBootstrap, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Objects: objects, OrgSnapshots: []api.OrgSnapshot{snapshot}}}); err != nil {
		t.Fatal(err)
	}
}

func gateTickFixture(t *testing.T) (*fx.Fixture, *Server, *gateTickHelper) {
	t.Helper()
	f := fx.New(t)
	gateTickOrg(t, f)
	// Public own-life briefing reads this task during the second start's
	// preflight. Give the initial input an explicit configuration audience.
	data := []byte("shared initial task " + string(fx.ID(t)))
	f.Start.Task = api.BlobRef{ID: fx.ID(t), Class: "task", Bytes: int64(len(data)), SHA256: fx.Digest(data)}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalOrgBootstrap, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Objects: []api.ObjectWrite{{ObjectKey: f.Start.Task.ID, Class: "task", Bytes: data, SHA256: f.Start.Task.SHA256,
			Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, Audience: "config", Generation: 1}}}}}); err != nil {
		t.Fatal(err)
	}
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlanForIdentity(t, true, uint32(os.Geteuid())+1000, uint32(os.Getegid())+1000)
	f.Spec(t)
	f.Bind(t)
	f.Process = api.ProcessHandle{ID: f.Reservation.LaunchID, Target: f.Prepared.Target,
		ContainmentID: f.Prepared.ContainmentID, Generation: f.Prepared.ProcessGeneration}
	gate := f.Observation(t, "running")
	// admin.reconcileGate measures the live bootstrap even before release.
	// Its prepared report has a running Observation but no consumed permit.
	gate.GateState, gate.Process, gate.ConsumedPermit = "prepared", nil, nil
	helper := &gateTickHelper{gate: gate, capture: f.Plan.Capture,
		containment: api.ContainmentBinding{Config: f.Deps.Config, Target: f.Reservation.Target,
			Lease: f.Plan.Lease, Backend: f.Plan.Inputs.Sources.Runtime.Backend, Generation: 1},
		probe: api.IsolationCapabilities{Backend: f.Plan.Inputs.Sources.Runtime.Backend, Available: true,
			Checks: []api.Capability{{Name: "native-report-fixture", Available: true}}},
		request: api.HelperReconcileRequest{LeaseID: f.Plan.Lease.ID, LaunchID: f.Reservation.LaunchID,
			PreparedID: f.Prepared.ID, OperationID: f.Reservation.OperationID}}
	host := launchServer(t, f)
	host.runtime = api.RuntimeServices{Store: f.State, Helper: helper}
	host.launchConfigured = true
	return f, host, helper
}

func gateTickLoop(t *testing.T, host *Server) <-chan struct{} {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); host.launchRecoveryLoop(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("tick loop did not join")
		}
	})
	return done
}

func gateTickHealthy(t *testing.T, host *Server, helper *gateTickHelper, calls int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		host.mu.RLock()
		healthy, failure := host.launchJobsActive && host.launchJobsHealthy, host.fault
		host.mu.RUnlock()
		if failure != nil {
			t.Fatal("reconcile tick stopped launch admission", failure)
		}
		helper.mu.Lock()
		seen := helper.calls
		helper.mu.Unlock()
		if healthy && seen >= calls {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("tick loop did not retain healthy admission")
		}
	}
}

func TestGateTickAdmission(t *testing.T) {
	for _, state := range []string{"prepared", "opening"} {
		t.Run(state, func(t *testing.T) {
			f, host, helper := gateTickFixture(t)
			helper.gate.GateState = state
			gateTickLoop(t, host)
			gateTickHealthy(t, host, helper, 1)
			ctx := context.Background()
			page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID})
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range page.Events {
				if event.Kind == "run.observed" {
					t.Fatal("unconsumed bootstrap became a run observation")
				}
			}
			helper.mu.Lock()
			helper.gate = f.Observation(t, "running")
			helper.gate.GateState = "consumed"
			opened := helper.gate
			next := helper.calls + 1
			helper.mu.Unlock()
			f.Opened(t, opened)
			gateTickHealthy(t, host, helper, next)
			gateTickStart(t, f, host, helper)
		})
	}
}

func gateTickStart(t *testing.T, f *fx.Fixture, host *Server, helper *gateTickHelper) {
	t.Helper()
	ctx := context.Background()
	parent := f.LaneScope(t)
	endpoint, err := wire.LaneEndpointBinding(host.deps.Binding, f.Record.Handoff.Spec, f.Plan.Lease)
	if err != nil {
		t.Fatal(err)
	}
	connection := parent.Connection.(*fx.Connection)
	connection.Endpoint = endpoint
	connection.Verified.(*fx.Peer).FactsValue.HostGID = f.Plan.Lease.GID
	start := f.Start
	start.Lane, start.Level, start.Role, start.RootTicketID = string(fx.ID(t)), 3, "executor", ""
	data := []byte("second admitted task " + string(fx.ID(t)))
	start.Task, err = f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalObjectRetain),
		Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "task", Bytes: data, SHA256: fx.Digest(data), Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: parent.Actor, LifeID: parent.Actor.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	start.Grants.Data = append([]api.DataGrantRequest{}, start.Grants.Data...)
	start.Grants.Profiles = append([]api.ProfileDelegation{}, start.Grants.Profiles...)
	start.Grants.Data[0].ParentGrantID = f.Plan.Inputs.Grants.Data[0].ID
	start.Grants.Profiles[0].ParentGrantID = f.Plan.Inputs.Grants.Profiles[0].ID
	expires := api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))
	start.Grants.Data[0].ExpiresAt, start.Grants.Profiles[0].ExpiresAt = expires, expires
	start.ProfileGrantID = f.Plan.Inputs.Grants.Profiles[0].ID
	resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &dataworker.Service{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := codex.New(codex.Dependencies{Store: f.State, Clock: f.Deps.Clock, ReadScope: parent,
		Runtime: codex.Runtime{Executable: f.Plan.Runner.Executable, ExecutablePath: "/runtime/" + string(f.Plan.Runner.Executable.ID),
			SelfHelper: f.Plan.Runner.Executable, SelfHelperPath: "/runtime/" + string(f.Plan.Runner.Executable.ID)}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.New(identity.Dependencies{Store: f.State, Clock: f.Deps.Clock, Peers: helper, Registry: helper})
	if err != nil {
		t.Fatal(err)
	}
	host.deps.Authenticator = auth
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: auth, Clock: f.Deps.Clock,
		Dispatch: host, Grants: resolver, Codex: runner, Launcher: &gateTickProbe{helper: helper}})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Register(host); err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config,
		Method: "lane.start", RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, start)}
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	parent.Request, parent.Frame = request, &fx.Frame{Raw: fx.JSON(t, request)}
	reply, _, err := host.dispatchMutation(ctx, parent, request)
	if err != nil {
		t.Fatal("second lane.start was not admitted after opening", err)
	}
	var operation api.Operation
	if err := json.Unmarshal(reply, &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Status != "pending" || operation.LifeID == "" || operation.LifeID == f.Lane.LifeID || operation.Run != 1 {
		t.Fatal("second start lost its real reserved life and operation")
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range effects {
		if effect.OperationID == operation.ID && effect.PlanLaunch != nil && effect.Context != nil && effect.Context.Target.LifeID == operation.LifeID {
			plan, err := f.State.LaunchPlan(ctx, f.Execution, effect.PlanLaunch.ReservationID)
			if err != nil || plan.Reservation.Target.LifeID != operation.LifeID || plan.Phase != "reserved" {
				t.Fatal("second start lost its durable reservation", err)
			}
			return
		}
	}
	t.Fatal("second start has no durable planning effect")
}

func TestGateTickPermitFault(t *testing.T) {
	for _, stage := range []string{"bound", "observed", "opened"} {
		reports := []string{"missing", "launch", "prepared", "digest", "sequence", "unknown", "observation"}
		if stage != "bound" {
			reports = append(reports, "rewound", "live", "opening")
		}
		for _, report := range reports {
			t.Run(stage+"/"+report, func(t *testing.T) {
				f, host, helper := gateTickFixture(t)
				measured := f.Observation(t, "running")
				measured.GateState = "consumed"
				if stage == "opened" {
					f.Opened(t, measured)
				} else if stage == "observed" {
					if err := f.State.RecordLaunchObservation(context.Background(), f.Reservation.LaunchID, measured); err != nil {
						t.Fatal(err)
					}
				}
				helper.gate = measured
				permit := *measured.ConsumedPermit
				helper.gate.ConsumedPermit = &permit
				switch report {
				case "missing":
					helper.gate.ConsumedPermit = nil
				case "launch":
					permit.LaunchID = fx.ID(t)
				case "prepared":
					permit.PreparedID = fx.ID(t)
				case "digest":
					permit.RecordSHA256 = fx.Digest([]byte(fx.ID(t)))
				case "sequence":
					permit.CommittedSeq++
				case "unknown", "observation", "rewound", "live", "opening":
					helper.gate.GateState, helper.gate.Process, helper.gate.ConsumedPermit = "prepared", nil, nil
					switch report {
					case "unknown":
						helper.gate.GateState = "unknown"
					case "observation":
						helper.gate.Observation.State = "unknown"
					case "rewound":
						helper.gate.Observation.State = "prepared"
					case "opening":
						helper.gate.GateState = "opening"
					}
				}
				done := gateTickLoop(t, host)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("consumed gate permit loss did not stop admission")
				}
				host.mu.RLock()
				failure, active := host.fault, host.launchJobsActive
				host.mu.RUnlock()
				codeIs(t, failure, api.CodeContainmentUnknown)
				if active {
					t.Fatal("faulted recovery still advertises admission")
				}
				request := f.Human.Request
				request.RequestID, request.IdempotencyKey = fx.ID(t), fx.ID(t)
				var err error
				request.RequestSHA256, err = wire.RequestDigest(request)
				if err != nil {
					t.Fatal(err)
				}
				scope := f.Human
				scope.Request, scope.Frame = request, &fx.Frame{Raw: fx.JSON(t, request)}
				_, _, err = host.dispatchMutation(context.Background(), scope, request)
				codeIs(t, err, api.CodePrerequisite)
			})
		}
	}
}
