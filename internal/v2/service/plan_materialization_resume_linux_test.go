//go:build linux

package service

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The scheduling hook exposes actual retained phases to the real planner.
// It never substitutes an effect, claim, result or returned store projection.
func (s *planningPolicyStore) LaunchDataStage(ctx context.Context, scope api.Scope, request api.LaunchDataRequest) (api.LaunchDataStage, error) {
	stage, err := s.Service.LaunchDataStage(ctx, scope, request)
	if err != nil || s.dataStageHook == nil {
		return stage, err
	}
	hook := s.dataStageHook
	s.dataStageHook = nil
	hook(ctx, request)
	return s.Service.LaunchDataStage(ctx, scope, request)
}

// Native process and identity observations are explicit component fixtures.
// A running observation releases actual worker-result submission; the next
// observation sees that acknowledgement, with no sleep choosing the outcome.
type resumeDataHelper struct {
	*dataHelperFixture
	p            *successfulPlanPorts
	delivered    bool
	returned     bool
	observes     int
	storageReads int
	gate         api.LaunchReconciliation
	deliverAfter int
}

func (h *resumeDataHelper) submit(t *testing.T) {
	t.Helper()
	d := h.p.data
	d.BindWorker(t)
	_, raw := d.Result(t)
	if _, err := d.F.State.WorkerResult(context.Background(), d.Worker, d.Submission(raw)); err != nil {
		t.Fatal(err)
	}
	h.delivered = true
}

func (h *resumeDataHelper) ObserveDataWorker(ctx context.Context, request api.StorageProjectionRequest) (api.ProcessObservation, error) {
	h.observes++
	h.running = !h.delivered
	observation, err := h.dataHelperFixture.ObserveDataWorker(ctx, request)
	if err == nil && !h.delivered && (h.deliverAfter == 0 || h.observes >= h.deliverAfter) {
		h.submit(h.t)
	}
	return observation, err
}

func (h *resumeDataHelper) MeasureDataWorker(ctx context.Context, request api.StorageProjectionRequest, receipt api.WorkerResultReceipt) (api.LaunchDataResult, error) {
	result, err := h.dataHelperFixture.MeasureDataWorker(ctx, request, receipt)
	if err == nil {
		h.returned = true
	}
	return result, err
}

func (h *resumeDataHelper) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	return h.p.ResolveLaunchSources(ctx, request)
}

func (h *resumeDataHelper) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	if !h.returned {
		return api.LaunchStorage{}, serviceError(api.CodeIntegrity, "component agent storage is still loaned to its worker")
	}
	h.storageReads++
	return h.p.ResolveLaunchStorage(ctx, request)
}

func (h *resumeDataHelper) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	f := h.p.f
	if request.LeaseID != f.Plan.Lease.ID || request.LaunchID != f.Reservation.LaunchID || request.PreparedID != f.Prepared.ID || request.OperationID != f.Reservation.OperationID {
		return api.LaunchReconciliation{}, serviceError(api.CodeIntegrity, "component launch selected another retained gate")
	}
	return h.gate, ctx.Err()
}

type resumeDataControl struct {
	host           *Server
	helper         *resumeDataHelper
	starts, awaits int
	joinFailure    error
}

func (c *resumeDataControl) MaterializationStage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchDataStage, error) {
	c.starts++
	stage, err := c.host.MaterializationStage(ctx, request)
	if err == nil {
		c.helper.p.data.Stage = stage
	}
	return stage, err
}

func (c *resumeDataControl) AwaitMaterialization(ctx context.Context, id api.ID) (api.LaunchDataResult, error) {
	c.awaits++
	result, err := c.host.AwaitMaterialization(ctx, id)
	if err != nil && c.joinFailure != nil {
		return result, errors.Join(err, c.joinFailure)
	}
	return result, err
}

// The actual planner reaches the native launch boundary. Only native prepare/
// identity/open observations use the existing explicit fixture; the reconciler
// alone completes the original parent effect in the real writer afterwards.
type resumeDataPlanner struct {
	api.LaunchPlanner
	p       *successfulPlanPorts
	helper  *resumeDataHelper
	stop    context.CancelFunc
	calls   int
	waits   int
	failure error
}

func (p *resumeDataPlanner) PlanLaunch(ctx context.Context, scope api.Scope, request api.LaunchPlanRequest) (api.LaunchPlan, error) {
	p.calls++
	plan, err := p.LaunchPlanner.PlanLaunch(ctx, scope, request)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeUnavailable && typed.Retryable && typed.Owner == "lb-v2-service" && typed.Message == "materialization stage is in flight" {
			p.waits++
			return plan, err
		}
		p.failure = err
		p.stop() // A hang guard can never satisfy the progress assertion.
		return plan, err
	}
	f, t := p.p.f, p.p.t
	if err := p.p.sync(ctx); err != nil {
		t.Fatal(err)
	}
	f.Plan = plan
	turn, err := f.State.Turn(ctx, scope, plan.Reservation.Target, request.Lease.Record.Effect.Context.LogicalTurnID)
	if err != nil {
		t.Fatal(err)
	}
	f.Bind(t, turn)
	p.helper.gate = f.Observation(t, "running")
	if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, p.helper.gate); err != nil {
		t.Fatal(err)
	}
	f.Lane.Generation++
	f.Lane.State, f.Lane.Containment = "running", "running"
	record := f.Record
	record.Generation++
	record.Phase = "opened"
	f.Transition(t, record, api.StateWrites{Lanes: []api.Lane{f.Lane}}, nil, api.InternalHelperOpen, "")
	return plan, nil
}

func TestPlanMaterializationResume(t *testing.T) {
	phases := []string{"pending", "in_flight", "measured_complete", "joined_wait_failure"}
	for trial := 0; trial < 20; trial++ {
		phases = append(phases, "box22-"+strconv.Itoa(trial))
	}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			f, reservation, effect := scopePlanningFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			policy := &planningPolicyStore{Service: f.State, effect: effect.ID, stop: cancel}
			planner := successfulScopePlanner(t, policy, f, effect)
			p := policy.sourcePorts
			state := policy
			host := fixtureServer(t)
			host.verified, host.bound, host.controller = true, true, fx.ID(t)
			host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, f.Deps.Clock
			helper := &resumeDataHelper{p: p, dataHelperFixture: &dataHelperFixture{t: t}}
			if strings.HasPrefix(phase, "box22-") {
				helper.deliverAfter = 14
			}
			control := &resumeDataControl{host: host, helper: helper}
			if phase == "joined_wait_failure" {
				_, control.joinFailure = f.State.ObjectMetadata(context.Background(), f.Execution, fx.ID(t))
				if control.joinFailure == nil {
					t.Fatal("mixed-wait control did not reach its real missing-object read")
				}
			}
			worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: state, Helper: helper,
				Controls: control, Launcher: &healthLauncher{}, Clock: f.Deps.Clock})
			if err != nil {
				t.Fatal(err)
			}
			p.materializeData = worker.MaterializeLaunch
			launch := &resumeDataPlanner{LaunchPlanner: planner, p: p, helper: helper, stop: cancel}
			host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: launch, Helper: helper, Worker: worker, Launcher: &healthLauncher{}}
			state.dataStageHook = func(seedCtx context.Context, request api.LaunchDataRequest) {
				p.data = fx.DataForLaunch(t, f, request)
				helper.d = p.data
				host.deps.Binding = p.data.HostBinding()
				host.deps.Authenticator = &dataAuthFixture{authFixture: &authFixture{}, d: p.data}
				if phase == "pending" {
					p.data.Stage, err = f.State.SealDataStage(seedCtx, f.Execution, p.data.Stage.ID, p.data.Projection, p.data.Allocation)
				} else {
					p.data.Stage, err = host.MaterializationStage(seedCtx, request)
				}
				if err != nil {
					t.Fatal("retained materialization phase setup failed", err)
				}
				if phase == "measured_complete" {
					helper.submit(t)
					if _, err := host.AwaitMaterialization(seedCtx, p.data.Stage.ID); err != nil {
						t.Fatal("actual owner could not measure retained setup", err)
					}
				}
			}
			host.reconcileLoop(ctx)
			if phase == "joined_wait_failure" {
				parent, err := f.State.Effect(context.Background(), f.Execution, effect.ID)
				if !errors.Is(host.fault, control.joinFailure) || err != nil || parent.Outcome != nil || helper.measures != 0 || launch.calls != 1 {
					t.Fatal("typed wait hid its joined real store failure or fabricated progress", host.fault, err)
				}
				if err := host.Close(); !errors.Is(err, control.joinFailure) {
					t.Fatal("host close lost its original mixed-wait fault", err)
				}
				return
			}
			wantCalls, wantWaits := 2, 1
			if helper.deliverAfter > 0 {
				wantCalls, wantWaits = helper.deliverAfter+1, helper.deliverAfter
			}
			if phase == "measured_complete" {
				wantCalls, wantWaits = 1, 0
			}
			if host.fault != nil || launch.failure != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("retained materialization did not progress through the actual planner", host.fault, launch.failure)
			}
			if launch.calls != wantCalls || launch.waits != wantWaits {
				t.Fatal("running materialization did not expose and drive its typed stage-in-flight wait", launch.calls, launch.waits)
			}
			parent, err := f.State.Effect(context.Background(), f.Execution, effect.ID)
			if err != nil || parent.State != api.EffectCompleted || parent.Outcome == nil || parent.Outcome.Process == nil || parent.Outcome.LaunchPlan == nil {
				t.Fatal("resumed materialization did not reach launch completion", err)
			}
			child, err := f.State.Effect(context.Background(), f.Execution, p.data.Stage.Worker.EffectID)
			if err != nil {
				t.Fatal(err)
			}
			measured, err := f.State.DataResult(context.Background(), f.Execution, p.data.Stage.ID)
			if err != nil || child.State != api.EffectCompleted || child.Outcome == nil || child.Outcome.Observation == nil ||
				helper.opens != 1 || helper.measures != 1 || !helper.returned || !p.storageBeforeCredentials ||
				!reflect.DeepEqual(parent.Outcome.LaunchPlan.Data, measured.Data) {
				t.Fatal("resumed plan lost its one measured child or early returned-storage check", err)
			}
			if phase != "measured_complete" && (control.awaits != wantCalls || helper.observes != wantCalls) {
				t.Fatal("in-flight child had no actual owner driving its completion")
			}
			operation, err := f.State.Operation(context.Background(), f.Execution, reservation.OperationID)
			if err != nil || operation.Status != "succeeded" || operation.Error != nil {
				t.Fatal("launched plan did not complete its original operation", err)
			}
			if strings.HasPrefix(phase, "box22-") {
				t.Logf("box22 order verified: waits=%d planner_calls=%d completed_child=true completed_parent=true", launch.waits, launch.calls)
			}
			if err := host.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
