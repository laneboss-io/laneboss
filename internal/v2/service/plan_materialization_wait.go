package service

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type materializationPollKey struct{}

const materializationWaitMessage = "materialization stage is in flight"

func materializationWaiting(err error) bool {
	switch cause := err.(type) {
	case *api.Error:
		return cause != nil && cause.Code == api.CodeUnavailable && cause.Retryable && cause.Owner == "lb-v2-service" && cause.Message == materializationWaitMessage
	case interface{ Unwrap() []error }:
		causes := cause.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, child := range causes {
			if !materializationWaiting(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return materializationWaiting(cause.Unwrap())
	}
	return false
}

// A running child does not surrender the parent claim or cancel its private
// endpoint. This same bounded attempt keeps driving the original stage until
// its owner measures completion, an actual failure occurs, or the lease ends.
func runPlanning(ctx context.Context, planner api.LaunchPlanner, scope api.Scope, lease api.EffectLease) (result api.LaunchPlan, resultErr error) {
	check := "planning_dispatch"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	ctx = context.WithValue(ctx, materializationPollKey{}, true)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			check = "planning_wait"
			return api.LaunchPlan{}, contextError(err)
		}
		plan, err := planner.PlanLaunch(ctx, scope, api.LaunchPlanRequest{Lease: lease})
		if !materializationWaiting(err) {
			return plan, err
		}
		select {
		case <-ctx.Done():
			check = "planning_wait"
			return api.LaunchPlan{}, contextError(ctx.Err())
		case <-ticker.C:
		}
	}
}
