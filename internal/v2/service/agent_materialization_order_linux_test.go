//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only the native gate is a component fixture. The materialization and agent
// stage owners retain, claim, measure, bind, open and complete in the real store.
type ownerResumeHelper struct {
	*resumeDataHelper
	owner *agentOwnerHelper
}

func (h *ownerResumeHelper) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	return h.owner.ReconcileGate(ctx, request)
}

type ownerResumePlanner struct {
	api.LaunchPlanner
	host          *Server
	helper        *resumeDataHelper
	completeFirst bool
	waits, calls  int
	failure       error
	stop          context.CancelFunc
}

func (p *ownerResumePlanner) PlanLaunch(ctx context.Context, scope api.Scope, request api.LaunchPlanRequest) (api.LaunchPlan, error) {
	p.calls++
	plan, err := p.LaunchPlanner.PlanLaunch(ctx, scope, request)
	if err == nil {
		return plan, nil
	}
	if materializationWaiting(err) {
		p.waits++
		if p.completeFirst && p.waits == p.helper.deliverAfter {
			// The worker has submitted its actual acknowledgement at this
			// point. Drive its original owner before the next planner read.
			if _, completeErr := p.host.AwaitMaterialization(ctx, p.helper.p.data.Stage.ID); completeErr != nil {
				p.failure = completeErr
				p.stop()
				return plan, completeErr
			}
		}
		return plan, err
	}
	p.failure = err
	p.stop()
	return plan, err
}

func TestAgentMaterializationOrders(t *testing.T) {
	for _, completeFirst := range []bool{true, false} {
		for trial := 0; trial < 20; trial++ {
			t.Run(fmt.Sprintf("completion-first=%t/trial-%d", completeFirst, trial), func(t *testing.T) {
				f, reservation, effect := scopePlanningFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				state := &planningPolicyStore{Service: f.State, effect: effect.ID, stop: cancel}
				planner := scopePlanSetup(t, state, f, effect, nil, func(p *successfulPlanPorts) {
					p.profileMode = "helper"
				})
				p := state.sourcePorts
				host := fixtureServer(t)
				host.verified, host.bound, host.controller = true, true, fx.ID(t)
				host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, f.Deps.Clock
				dataHelper := &resumeDataHelper{p: p, deliverAfter: 14, dataHelperFixture: &dataHelperFixture{t: t}}
				helper := &ownerResumeHelper{resumeDataHelper: dataHelper, owner: &agentOwnerHelper{state: state}}
				control := &resumeDataControl{host: host, helper: dataHelper}
				worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: state, Helper: helper,
					Controls: control, Launcher: &healthLauncher{}, Clock: f.Deps.Clock})
				if err != nil {
					t.Fatal(err)
				}
				p.materializeData = worker.MaterializeLaunch
				launch := &ownerResumePlanner{LaunchPlanner: planner, host: host, helper: dataHelper, completeFirst: completeFirst, stop: cancel}
				host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: launch, Helper: helper, Worker: worker, Launcher: &agentOwnerLauncher{state: state}}
				state.dataStageHook = func(seedCtx context.Context, request api.LaunchDataRequest) {
					p.data = fx.DataForLaunch(t, f, request)
					dataHelper.d = p.data
					host.deps.Binding = p.data.HostBinding()
					host.deps.Authenticator = &dataAuthFixture{authFixture: &authFixture{}, d: p.data}
					p.data.Stage, err = host.MaterializationStage(seedCtx, request)
					if err != nil {
						t.Fatal("actual materialization owner setup failed", err)
					}
				}
				host.reconcileLoop(ctx)
				if host.fault != nil || launch.failure != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Fatal("ordered agent materialization failed", host.fault, launch.failure)
				}
				if launch.waits != 14 || launch.calls != 15 || dataHelper.opens != 1 || dataHelper.measures != 1 || !dataHelper.returned || !p.storageBeforeCredentials {
					t.Fatal("order did not drive the original child through fourteen waits and one measured return", launch.waits, launch.calls)
				}
				parent, err := state.Effect(context.Background(), f.Execution, effect.ID)
				if err != nil || parent.State != api.EffectCompleted || parent.Outcome == nil || parent.Outcome.LaunchPlan == nil || parent.Outcome.Process == nil {
					t.Fatal("actual agent owner did not complete its planning parent", err)
				}
				for _, id := range []api.ID{p.data.Stage.Worker.EffectID, agentStageID(reservation.ID, "prepare-effect")} {
					child, err := state.Effect(context.Background(), f.Execution, id)
					if err != nil || child.State != api.EffectCompleted || child.Outcome == nil {
						t.Fatal("actual owner did not complete its retained materialization or prepare child", err)
					}
				}
				retained, err := state.LaunchPlan(context.Background(), f.Execution, reservation.ID)
				if err != nil || retained.Phase != "opened" {
					t.Fatal("actual agent owner did not publish opened", err)
				}
				binding, err := state.LaunchBinding(context.Background(), reservation.LaunchID)
				if err != nil || binding.Prepared.ID == "" || binding.Identity.CommittedSeq == 0 {
					t.Fatal("actual agent owner omitted its measured gate and committed identity", err)
				}
				operation, err := state.Operation(context.Background(), f.Execution, reservation.OperationID)
				if err != nil || operation.Status != "succeeded" || operation.Error != nil {
					t.Fatal("actual agent owner did not complete its original operation", err)
				}
				t.Logf("agent owner order verified: completion_first=%t waits=%d planner_calls=%d", completeFirst, launch.waits, launch.calls)
				if err := host.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
