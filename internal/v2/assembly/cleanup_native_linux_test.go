//go:build linux

package assembly

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestCleanupNativeUnbound(t *testing.T) {
	f := fx.New(t)
	port := &helperCleanupNative{}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.CleanupNative = port
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	if f.State.CleanupNativeReady() || port.CleanupNativeReady() {
		t.Fatal("unbound cleanup forwarding capability advertised readiness")
	}
	if err := port.bind(nil); err == nil {
		t.Fatal("cleanup native binding accepted a missing administrator")
	}
	ctx := context.Background()
	_, resolveErr := port.ResolveCleanupWorkspace(ctx, api.LifeRef{LifeID: fx.ID(t), Run: 1}, fx.ID(t))
	_, removalErr := port.ReadWorkspaceRemoval(ctx, api.CleanupJob{})
	_, workspaceErr := port.ReadCleanupWorkspace(ctx, api.CleanupJob{})
	for _, err := range []error{resolveErr, removalErr, workspaceErr} {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" || typed.Message != "installed protected cleanup native ports is not implemented" {
			t.Fatal("unbound cleanup port returned a fabricated native result", err)
		}
	}
}

type runPorts struct {
	api.CredentialBroker
	f     *fx.Fixture
	reads int
	deny  bool
}

func (p *runPorts) ResolveLaunchSources(ctx context.Context, q api.LaunchSourceRequest) (api.LaunchSources, error) {
	p.reads++
	e, err := p.f.State.Effect(ctx, p.f.Execution, q.Claim.EffectID)
	if err != nil {
		return api.LaunchSources{}, err
	}
	if err := api.CheckPlanningClaim(e, q.Claim, p.f.Deps.Config, p.f.Deps.Clock.Now()); err != nil {
		return api.LaunchSources{}, err
	}
	r, err := p.f.State.LaunchPlan(ctx, p.f.Execution, q.ReservationID)
	if err != nil {
		return api.LaunchSources{}, err
	}
	if r.Inputs == nil || r.Reservation.GrantSetID != q.GrantSetID {
		return api.LaunchSources{}, installError("source selection changed")
	}
	return r.Inputs.Sources, nil
}

func (p *runPorts) ResolveLaunchStorage(ctx context.Context, q api.LaunchDataRequest) (api.LaunchStorage, error) {
	r, err := p.f.State.LaunchPlan(ctx, p.f.Execution, q.ReservationID)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	if r.Plan == nil || r.Plan.Lease.ID != q.LeaseID {
		return api.LaunchStorage{}, installError("storage allocation changed")
	}
	return api.LaunchStorage{ReservationID: q.ReservationID, Target: r.Reservation.Target, LeaseID: q.LeaseID, WorkspaceID: r.Plan.Data.Workspace.ID, Home: r.Plan.Data.Home}, nil
}

func (p *runPorts) VerifyRunnerSlot(ctx context.Context, claim api.LaunchClaim, q api.RunnerRequest) (api.LaunchStorage, error) {
	p.reads++
	e, err := p.f.State.Effect(ctx, p.f.Execution, claim.EffectID)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	if err := api.CheckPlanningClaim(e, claim, p.f.Deps.Config, p.f.Deps.Clock.Now()); err != nil {
		return api.LaunchStorage{}, err
	}
	r, err := p.f.State.LaunchPlan(ctx, p.f.Execution, claim.ReservationID)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	if p.deny || r.Plan == nil || q.Target != r.Reservation.Target || q.Slot != r.Plan.Runner.Slot || q.Home != r.Plan.Runner.Home {
		return api.LaunchStorage{}, installError("slot is not the retained component selection")
	}
	return p.ResolveLaunchStorage(ctx, api.LaunchDataRequest{Claim: claim, ReservationID: claim.ReservationID, GrantSetID: r.Reservation.GrantSetID, LeaseID: r.Plan.Lease.ID})
}

type runProbe struct {
	api.Runner
	want  api.RunnerRequest
	calls int
	stop  error
}

func (p *runProbe) Start(_ context.Context, q api.RunnerRequest) (api.RunnerPlan, error) {
	p.calls++
	if !reflect.DeepEqual(q, p.want) {
		return api.RunnerPlan{}, installError("adapter received changed input")
	}
	return api.RunnerPlan{}, p.stop
}

func runnerCase(t *testing.T) (*fx.Fixture, *runPorts, Installation, api.RunnerRequest) {
	t.Helper()
	f := fx.New(t)
	f.Start.Grants.Profiles[0].ExpiresAt = f.Start.Grants.Data[0].ExpiresAt
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	p := f.Plan
	enrolled := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: f.Deps.Config, Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: p.Inputs.Sources.Project.EnrollmentID, Generation: p.Inputs.Sources.Project.Generation, ProjectID: p.Inputs.Sources.Project.ProjectID, Object: p.Inputs.Sources.Project.Object, Base: p.Inputs.Sources.Project.Base, HistoryScope: p.Inputs.Sources.Project.HistoryScope}}, Runtimes: []api.LaunchRuntime{p.Inputs.Sources.Runtime}}
	ref := f.Retain(t, "manifest", fx.JSON(t, enrolled), f.Execution.Actor, "")
	installed := Installation{Config: f.Deps.Config, LaunchEnrollment: &ref, RuntimeManifest: p.Inputs.Sources.Runtime.Manifest}
	request := api.RunnerRequest{Target: p.Reservation.Target, LogicalTurnID: f.Claim.Record.Effect.Context.LogicalTurnID, Session: p.Runner.Session, Prompt: p.Runner.Prompt, Home: p.Runner.Home, Slot: p.Runner.Slot, Executable: p.Runner.Executable, Model: f.Lane.Model, Effort: f.Lane.Effort, Budget: p.Budget}
	return f, &runPorts{f: f}, installed, request
}

func TestRunnerEnrollmentFreshStart(t *testing.T) {
	f, ports, installed, request := runnerCase(t)
	fixture := &enrollmentRunnerFixture{}
	runner := guardRunnerEnrollment(fixture, installed, api.DriverCodex, runnerDependencies{Store: f.State, Clock: f.Deps.Clock, Sources: ports, Storage: ports, Credentials: ports})
	ctx := api.WithEffectLease(context.Background(), f.Claim)
	request.Session.VendorVersion = ""
	plan, err := runner.Start(ctx, request)
	if err != nil || fixture.starts != 1 || plan.Session.VendorVersion != request.Executable.Version || plan.Home != request.Home || plan.Slot != request.Slot {
		t.Fatalf("fresh start did not let the adapter pin its vendor session: err=%v starts=%d version=%q", err, fixture.starts, plan.Session.VendorVersion)
	}
	var typed *api.Error
	if _, err := runner.Resume(ctx, request); !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || fixture.starts != 1 {
		t.Fatalf("retained run without a vendor pin reached the adapter: %v", err)
	}
	if _, err := runner.Turn(ctx, request); !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || fixture.starts != 1 {
		t.Fatalf("retained turn without a vendor pin reached the adapter: %v", err)
	}
}

type runScheduler struct{ value api.InstalledScheduler }

func (p runScheduler) VerifyScheduler(context.Context) (api.InstalledScheduler, error) {
	return p.value, nil
}

func TestRunnerLoopInput(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Opened(t)
	f.Ended(t)
	setting := api.LoopRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, Enabled: true, IdleMessage: &f.Lane.Task, BackoffMS: 1}
	f.Admit(t, "lane.loop", setting)
	next := f.Lane
	next.Generation++
	event := f.Event(t, "lane.loop", setting)
	event.Actor, event.RequestedBy = f.Human.Actor, f.Human.Actor
	event.OperationID, event.RequestID = "", f.Human.Request.RequestID
	ctx := context.Background()
	_, err := f.State.Transact(ctx, api.Transaction{Scope: f.Human, RawRequest: f.Raw,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: next.LifeID, Generation: f.Lane.Generation}},
		Writes:  api.StateWrites{Lanes: []api.Lane{next}}, Events: []api.Event{event},
		Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: f.Receipt.Operation.ID, Status: "succeeded", LifeID: next.LifeID, Run: next.Run})}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: next.LifeID, Run: next.Run})
	if err != nil {
		t.Fatal(err)
	}
	selector := api.LoopTurnSelector{Target: f.Reservation.Target, ExpectedGeneration: next.Generation, CancellationEpoch: next.CancellationEpoch, PreviousLaunchID: next.LaunchID}
	for _, row := range page.Events {
		if row.Kind == "lane.loop" {
			selector.SettingEventID, selector.SettingSeq, selector.SettingOperationID = row.ID, row.Seq, row.OperationID
		}
		if row.Kind == "lane.ended" {
			selector.EndEventID, selector.EndSeq = row.ID, row.Seq
		}
	}
	producer := runScheduler{api.InstalledScheduler{Config: f.Deps.Config, Actor: api.Actor{Kind: "scheduler", ID: fx.ID(t)}, CapabilityID: fx.ID(t), CapabilityGeneration: 1, InstallationGeneration: 1, BootID: "runner-loop-boot", PolicyGeneration: 1, ExpiresAt: fx.Expiry()}}
	scope, err := api.BindSchedulerScope(ctx, producer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := f.State.ReserveLaunch(ctx, scope, api.LaunchReservationRequest{Loop: &selector})
	if err != nil {
		t.Fatal(err)
	}
	request := api.RunnerRequest{Target: reserve.Target, LogicalTurnID: reserve.Loop.LogicalTurnID, Session: reserve.Loop.PreviousSession,
		Home: reserve.Loop.PreviousHome.Home, Executable: f.Plan.Runner.Executable, Model: f.Lane.Model, Effort: f.Lane.Effort, Budget: reserve.Loop.BudgetRemaining}
	runner := &enrolledRunner{config: f.Deps.Config, driver: reserve.Driver, deps: runnerDependencies{Store: f.State}}
	record := api.LaunchPlanRecord{Reservation: reserve}
	if err := runner.runInput(ctx, f.Execution, record, request); err != nil {
		t.Fatal("scheduled turn did not reach the retained runner input", err)
	}
	for _, mode := range []string{"session", "home", "turn", "budget", "model", "effort"} {
		t.Run(mode, func(t *testing.T) {
			changed := request
			switch mode {
			case "session":
				changed.Session.ID = fx.ID(t)
			case "home":
				changed.Home.ID = fx.ID(t)
			case "turn":
				changed.LogicalTurnID = fx.ID(t)
			case "budget":
				changed.Budget.WallMS++
			case "model":
				changed.Model += "-changed"
			case "effort":
				changed.Effort += "-changed"
			}
			if err := runner.runInput(ctx, f.Execution, record, changed); err == nil {
				t.Fatal("scheduled turn accepted changed", mode)
			}
		})
	}
}

func TestRunnerStorePins(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "config", "claim", "generation", "vendor", "home", "slot", "profile", "revoked", "no_claim", "model", "effort", "budget", "run", "manifest"} {
		t.Run(mode, func(t *testing.T) {
			f, ports, installed, request := runnerCase(t)
			probe := &runProbe{want: request, stop: api.NotImplemented("test", "exact adapter boundary")}
			allowed := captureAllowed(t)
			lease := f.Claim
			switch mode {
			case "missing":
				installed.LaunchEnrollment.ID = fx.ID(t)
			case "config":
				installed.Config += "-other"
			case "claim":
				lease.ClaimID = fx.ID(t)
			case "generation":
				lease.Record.Generation++
			case "vendor":
				request.Executable.SHA256 = fx.Digest([]byte(fx.ID(t)))
			case "home":
				request.Home.ID, request.Session.HomeID = fx.ID(t), ""
				request.Session.HomeID = request.Home.ID
			case "slot":
				request.Slot.ID = fx.ID(t)
			case "profile":
				request.Slot.ProfileGrantID = fx.ID(t)
			case "revoked":
				ports.deny = true
			case "model":
				request.Model += "-other"
			case "effort":
				request.Effort = "other"
			case "budget":
				request.Budget.WallMS--
			case "run":
				request.Target.Run++
			case "manifest":
				installed.RuntimeManifest.ID = fx.ID(t)
			}
			runner := guardRunnerEnrollment(probe, installed, api.DriverCodex, runnerDependencies{Store: f.State, Clock: f.Deps.Clock, Sources: ports, Storage: ports, Credentials: ports})
			ctx := api.WithEffectLease(context.Background(), lease)
			if mode == "no_claim" {
				ctx = context.Background()
			}
			_, err := runner.Start(ctx, request)
			switch mode {
			case "valid":
				if err != probe.stop || probe.calls != 1 || ports.reads < 2 || len(allowed()) != 0 {
					t.Fatal("protected enrollment did not reach the exact adapter boundary", err, allowed())
				}
				_, err = runner.Start(ctx, request)
				if err != probe.stop || probe.calls != 2 {
					t.Fatal("same live planning input failed replay", err)
				}
			case "vendor":
				// Owner R181-R192: the vendor pin is allowed and logged, so the changed executable reaches the adapter.
				if probe.calls != 1 || !slices.Contains(allowed(), "runner_vendor") {
					t.Fatal("vendor pin was not allowed and logged", err, probe.calls, allowed())
				}
			case "no_claim":
				// Owner R181-R192: without a live planning attempt the verification is skipped, allowed and logged.
				if err != probe.stop || probe.calls != 1 || !slices.Contains(allowed(), "runner_planning_attempt") {
					t.Fatal("missing planning attempt was not allowed and logged", err, probe.calls, allowed())
				}
			default:
				if err == nil || probe.calls != 0 {
					t.Fatal("foreign or missing enrollment authority reached the adapter", mode, err)
				}
			}
		})
	}
}
