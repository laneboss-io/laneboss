//go:build linux

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type policyReadFailure struct {
	*store.Service
	err error
}

func (p policyReadFailure) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if p.err != nil {
		return api.EffectivePolicy{}, p.err
	}
	return p.Service.CurrentApprovedPolicy(ctx, scope)
}

func TestCurrentPolicySource(t *testing.T) {
	f := fx.Ready(t, true)
	host := launchServer(t, f)
	if _, err := host.Binding(context.Background(), f.Reservation.LaunchID); err != nil {
		t.Fatal("current service policy control failed", err)
	}
	sentinel := errors.New("component approved policy read unavailable")
	host.deps.Store = policyReadFailure{Service: f.State, err: sentinel}
	if _, err := host.Binding(context.Background(), f.Reservation.LaunchID); !errors.Is(err, sentinel) {
		t.Fatal("service hid current policy source failure", err)
	}
}

type allocationSpy struct {
	api.HelperControl
	calls int
}

func (h *allocationSpy) Allocate(context.Context, api.HelperLeaseRequest) (api.HelperLease, error) {
	h.calls++
	return api.HelperLease{}, serviceError(api.CodeIntegrity, "component unexpected allocation call")
}

type claimClock struct{ at time.Time }

func (c *claimClock) Now() time.Time { return c.at }

func TestReclaimedAllocation(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	ctx := context.Background()
	clock := &claimClock{at: time.Now().UTC()}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.Clock = clock
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.State.Close(); err != nil {
			t.Error(err)
		}
	})
	r := f.Reservation
	cause := f.Intent(t, api.InternalHelperAllocate)
	cause.EffectID = fx.ID(t)
	effect := api.Effect{ID: cause.EffectID, OperationID: r.OperationID, Context: &cause,
		HelperAllocate: &api.HelperLeaseRequest{ReservationID: r.ID, Cause: cause, Config: r.Config, LifeID: r.Target.LifeID,
			Backend: f.Record.Inputs.Sources.Runtime.Backend, Budget: f.Start.Budget, RuntimeManifestID: f.Record.Inputs.Sources.Runtime.Manifest.ID}}
	parent := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("allocation intent setup failed", err)
	}
	request := api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID,
		Deadline: api.Timestamp(clock.Now().Add(time.Second).Format(time.RFC3339Nano))}
	first, err := f.State.ClaimEffect(ctx, f.Execution, request)
	if err != nil {
		t.Fatal(err)
	}
	clock.at = clock.at.Add(2 * time.Second)
	request.ExpectedGeneration, request.Deadline = first.Record.Generation, api.Timestamp(clock.Now().Add(time.Minute).Format(time.RFC3339Nano))
	second, err := f.State.ClaimEffect(ctx, f.Execution, request)
	if err != nil || second.Record.State != api.EffectClaimed {
		t.Fatal("reclaimed allocation setup failed", err)
	}
	spy := &allocationSpy{}
	host := fixtureServer(t)
	host.deps.Store, host.deps.Clock = f.State, clock
	host.runtime.Helper = spy
	_, err = host.runEffect(ctx, f.Execution, second)
	var refusal *api.Error
	if !errors.As(err, &refusal) || refusal.Code != api.CodeContainmentUnknown || spy.calls != 0 {
		t.Fatal("reclaimed allocation repeated native work", err)
	}
}
