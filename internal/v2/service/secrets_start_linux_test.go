//go:build linux

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The native process boundary remains a fixture. Unlike the older owner
// launcher, this exercises the private control lookup the installed broker
// performs without inheriting the reconciler's in-process context values.
type secretsStartLauncher struct {
	*agentOwnerLauncher
	host *Server
	open api.HelperOpenRequest
}

func (l *secretsStartLauncher) Launch(ctx context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.ProcessHandle, error) {
	request, err := l.host.Open(context.Background(), prepared, permit)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	l.open = request
	again, err := l.host.Open(context.Background(), prepared, permit)
	if err != nil || !reflect.DeepEqual(request, again) {
		return api.ProcessHandle{}, serviceError(api.CodeIntegrity, "secrets start lost the original broker open cause")
	}
	return l.agentOwnerLauncher.Launch(ctx, prepared, permit)
}

func TestSecretsStartBrokerOpen(t *testing.T) {
	a := newAgentOwnerAttempt(t)
	launcher := &secretsStartLauncher{agentOwnerLauncher: a.launcher, host: a.host}
	a.host.runtime.Launcher = launcher
	outcome, err := a.host.runEffect(context.Background(), a.scope, a.lease)
	if err != nil || outcome.Process == nil || outcome.LaunchPlan == nil || launcher.open.EffectID != a.lease.Record.Effect.ID {
		t.Fatal("secrets start did not reach its actual broker open control", err)
	}
	if _, err := a.state.CompleteEffect(context.Background(), a.scope, outcome); err != nil {
		t.Fatal("secrets start did not durably complete its planning owner", err)
	}
	if _, err := a.host.Open(context.Background(), launcher.open.Prepared, launcher.open.Permit); err == nil {
		t.Fatal("secrets start reused broker open authority after planning completed")
	}
}

func TestSecretsStartMaterializedBrokerOpen(t *testing.T) {
	f, reservation, effect := scopeDriverFixture(t, 0, api.DriverClaudock)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	state := &planningPolicyStore{Service: f.State, effect: effect.ID, stop: cancel}
	planner := scopePlanSetup(t, state, f, effect, nil, func(p *successfulPlanPorts) { p.profileMode = "helper" })
	p := state.sourcePorts
	host := fixtureServer(t)
	host.verified, host.bound, host.controller = true, true, fx.ID(t)
	host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, f.Deps.Clock
	dataHelper := &resumeDataHelper{p: p, deliverAfter: 3, dataHelperFixture: &dataHelperFixture{t: t}}
	helper := &ownerResumeHelper{resumeDataHelper: dataHelper, owner: &agentOwnerHelper{state: state}}
	control := &resumeDataControl{host: host, helper: dataHelper}
	worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: state, Helper: helper,
		Controls: control, Launcher: &healthLauncher{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	p.materializeData = worker.MaterializeLaunch
	launch := &ownerResumePlanner{LaunchPlanner: planner, host: host, helper: dataHelper, completeFirst: true, stop: cancel}
	launcher := &secretsStartLauncher{agentOwnerLauncher: &agentOwnerLauncher{state: state}, host: host}
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: launch, Helper: helper, Worker: worker, Launcher: launcher}
	state.dataStageHook = func(seedCtx context.Context, request api.LaunchDataRequest) {
		p.data = fx.DataForLaunch(t, f, request)
		dataHelper.d = p.data
		host.deps.Binding = p.data.HostBinding()
		host.deps.Authenticator = &dataAuthFixture{authFixture: &authFixture{}, d: p.data}
		p.data.Stage, err = host.MaterializationStage(seedCtx, request)
		if err != nil {
			t.Fatal("secrets startup could not retain the original materialization stage", err)
		}
	}
	host.reconcileLoop(ctx)
	if host.fault != nil || launch.failure != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("materialized secrets start did not reach its actual broker open", host.fault, launch.failure)
	}
	parent, err := state.Effect(context.Background(), f.Execution, effect.ID)
	if err != nil || parent.Outcome == nil || parent.Outcome.Process == nil || launcher.open.EffectID != effect.ID {
		t.Fatal("materialized secrets start lost the original planning and broker open cause", err)
	}
	retained, err := state.LaunchPlan(context.Background(), f.Execution, reservation.ID)
	if err != nil || retained.Phase != "opened" || retained.DataStageID == "" {
		t.Fatal("materialized secrets start did not retain its opened plan", err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
}
