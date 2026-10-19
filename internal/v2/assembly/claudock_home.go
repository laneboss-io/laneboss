package assembly

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// Both installed Claudock adapters use the same authenticated root worker.
// Standing in for vendor execution does not stand in for bootstrap measurement
// or private-home planning, and neither path receives a physical home path.
func (r *enrolledRunner) verifyClaudockBootstrap(ctx context.Context, request api.RunnerRequest, umask uint32) error {
	if umask != claudock.RequiredUmask {
		return runError(api.CodeIntegrity, "real runner umask differs")
	}
	selected, bound, storage, err := r.realRun(ctx, request.Target)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bound, request) {
		return runError(api.CodeForbidden, "real runner slot differs")
	}
	native, ok := r.deps.Storage.(interface {
		VerifyClaudockBootstrap(context.Context, admin.ClaudockPlanningRequest) error
	})
	if !ok {
		return api.NotImplemented("lb-v2-admin", "measured credential bootstrap proof")
	}
	lease, _ := api.EffectLeaseFromContext(ctx)
	return native.VerifyClaudockBootstrap(ctx, admin.ClaudockPlanningRequest{Request: bound, Home: storage.Home, LeaseID: storage.LeaseID,
		Claim: api.PlanningClaim(selected.ReservationID, lease), RequiredUmask: umask})
}

func (r *enrolledRunner) planClaudockHome(ctx context.Context, input claudock.HomePlanRequest) error {
	selected, bound, storage, err := r.realRun(ctx, input.Request.Target)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bound, input.Request) || input.Home != storage.Home || input.ReservationID != selected.ReservationID {
		return runError(api.CodeForbidden, "real credential home differs from retained runner input")
	}
	native, ok := r.deps.Storage.(interface {
		PlanClaudockHome(context.Context, admin.ClaudockPlanningRequest) error
	})
	if !ok {
		return api.NotImplemented("lb-v2-admin", "confined credential home worker")
	}
	lease, _ := api.EffectLeaseFromContext(ctx)
	return native.PlanClaudockHome(ctx, admin.ClaudockPlanningRequest{Request: bound, Home: storage.Home, LeaseID: storage.LeaseID,
		Claim: api.PlanningClaim(selected.ReservationID, lease), RequiredUmask: claudock.RequiredUmask, Plan: &input})
}
