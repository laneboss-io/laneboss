//go:build linux && laneboss_root_canary && laneboss_gate_integration

package lifecycle

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// ExerciseCaptureLifetimeCanary issues the actual capture stage in the real
// unprivileged writer. Its private test transport supplies native producer
// evidence; the parent uses the production deadline and kernel kill owner.
func ExerciseCaptureLifetimeCanary(t *testing.T, exchange func(string, any, any) error) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("capture writer must remain unprivileged")
	}
	ctx := context.Background()
	var identity struct {
		UID    uint32
		Config string
	}
	if err := exchange("identity", api.Empty{}, &identity); err != nil {
		t.Fatal(err)
	}
	f := fx.New(t, identity.Config)
	f.Reserve(t)
	f.Source(t)
	f.ExpireClaim(t)
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: f.Claim.Record.Effect.ID, ExpectedGeneration: f.Claim.Record.Generation,
		ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	f.Claim = claim
	allocation := api.HelperLease{ID: fx.ID(t), UID: identity.UID, GID: identity.UID, ContainmentID: fx.ID(t), EndpointGeneration: 1}
	ports := &captureLifetimePort{fixture: f, allocation: allocation, exchange: exchange}
	s := &Service{deps: Dependencies{Store: f.State, Clock: f.Deps.Clock, Capture: ports}}
	execution := &planExecution{service: s, scope: f.Execution, lease: claim, record: f.Record, input: launchInput{budget: f.Start.Budget, turn: claim.Record.Effect.Context.LogicalTurnID}}
	binding, err := execution.capture(ctx, *f.Record.Inputs, allocation)
	if err != nil {
		t.Fatal("capture stage did not retain the actual native job", err)
	}
	worker, err := f.State.WorkerLease(ctx, f.Execution, binding.WorkerLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	var observed api.ProcessObservation
	if err := exchange("capture-past-planning", struct {
		ExpiresAt api.Timestamp `json:"expires_at"`
	}{claim.ExpiresAt}, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.State != "running" || observed.Handle.ID != binding.ProducerID || observed.Handle.Generation != binding.ProducerGeneration {
		t.Fatal("planner expiry killed the original native capture before its run budget", observed.State)
	}
	freshScope := f.Execution
	freshScope.Actor.ID = fx.ID(t)
	fresh, err := f.State.ClaimEffect(ctx, freshScope, api.EffectClaimRequest{EffectID: claim.Record.Effect.ID, ExpectedGeneration: claim.Record.Generation,
		ClaimantID: freshScope.Actor.ID, Deadline: api.Timestamp(time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	execution.scope, execution.lease = freshScope, fresh
	again, err := execution.capture(ctx, *f.Record.Inputs, allocation)
	if err != nil || !reflect.DeepEqual(again, binding) || ports.calls != 1 {
		t.Fatal("reclaim replaced or restarted the native producer", err)
	}
	retained, err := f.State.WorkerLease(ctx, freshScope, worker.ID)
	if err != nil || !reflect.DeepEqual(retained, worker) {
		t.Fatal("reclaim renewed the original capture deadline", err)
	}
	execution.scope, execution.lease = f.Execution, claim
	if _, err := execution.capture(ctx, *f.Record.Inputs, allocation); err == nil {
		t.Fatal("capture lifetime revived an expired planning claim")
	}
	var complete bool
	if err := exchange("capture-finish-lifetime", api.Empty{}, &complete); err != nil || !complete {
		t.Fatal("native capture lost late bytes, EOF or its hard deadline control", err)
	}
}

type captureLifetimePort struct {
	api.CaptureControl
	fixture    *fx.Fixture
	allocation api.HelperLease
	exchange   func(string, any, any) error
	calls      int
}

func (p *captureLifetimePort) RegisterCapture(ctx context.Context, request api.CaptureRegistrationRequest) (api.CaptureBinding, error) {
	worker, err := p.fixture.State.WorkerLease(ctx, p.fixture.Execution, request.WorkerLeaseID)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	current, err := p.fixture.State.Effect(ctx, p.fixture.Execution, request.Cause.EffectID)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	if current.ClaimID != p.fixture.Claim.ClaimID || worker.EffectID != current.Effect.ID || request.Cause.Target != p.fixture.Reservation.Target {
		return api.CaptureBinding{}, &api.Error{Code: api.CodeForbidden, Message: "native capture fixture lost its current retained stage"}
	}
	p.calls++
	input := struct {
		Request     api.CaptureRegistrationRequest
		Worker      api.WorkerLease
		Reservation api.LaunchReservation
		Lease       api.HelperLease
	}{request, worker, p.fixture.Reservation, p.allocation}
	var binding api.CaptureBinding
	err = p.exchange("capture-lifetime", input, &binding)
	return binding, err
}
