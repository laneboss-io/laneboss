package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.LaunchPlanner = (*Service)(nil)

func (s *Service) PlanLaunch(ctx context.Context, scope api.Scope, request api.LaunchPlanRequest) (planned api.LaunchPlan, planErr error) {
	check := "plan_entry"
	if err := contextReady(ctx); err != nil {
		return api.LaunchPlan{}, err
	}
	defer func() { api.ObserveHelperReason(ctx, planErr, check) }()
	lease := request.Lease
	if lease.Record.Effect.PlanLaunch == nil || lease.Record.Effect.Context == nil ||
		!validID(lease.Record.Effect.ID) || !validID(lease.ClaimID) || !validID(lease.Record.Effect.PlanLaunch.ReservationID) {
		return api.LaunchPlan{}, invalid("launch planning requires a complete effect lease")
	}
	if err := s.ready(); err != nil {
		return api.LaunchPlan{}, err
	}
	execution := &planExecution{service: s, scope: scope, lease: request.Lease}
	check = "plan_claim"
	if err := execution.checkClaim(ctx); err != nil {
		return api.LaunchPlan{}, err
	}
	selector := request.Lease.Record.Effect.PlanLaunch.ReservationID
	unlock, err := s.lockLife(ctx, launchObjectID(selector, "planner-gate"))
	if err != nil {
		return api.LaunchPlan{}, err
	}
	defer unlock()
	// This is one reservation's gate, not a global lifecycle/store lock.
	// Manual stop/revocation uses its life gate and durable cancellation epoch.
	check = "plan_record"
	record, err := s.deps.Store.LaunchPlan(ctx, scope, selector)
	if err != nil {
		return api.LaunchPlan{}, failure(err)
	}
	if api.ValidateLaunchPlanRecord(record) != nil || record.Reservation.ID != selector {
		return api.LaunchPlan{}, integrity("planner loaded an invalid or foreign reservation")
	}
	execution.record = record
	if err := execution.checkClaim(ctx); err != nil {
		return api.LaunchPlan{}, err
	}
	if record.Phase == "failed" {
		if record.Error == nil {
			return api.LaunchPlan{}, integrity("failed launch plan has no recorded error")
		}
		return api.LaunchPlan{}, record.Error
	}
	defer func() {
		// Opened reconciliation is historical authentication, not abandonment
		// of a failed pre-execution plan or permission to stop a running gate.
		if planErr != nil && record.Phase != "opened" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			planErr = execution.failPlan(cleanup, planErr)
		}
	}()
	if record.Phase == "opened" {
		if err := execution.currentPolicy(ctx); err != nil {
			return api.LaunchPlan{}, err
		}
		if err := execution.original(ctx); err != nil {
			return api.LaunchPlan{}, err
		}
		lane, err := s.lane(ctx, scope, record.Reservation.Target, true)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		if record.Plan == nil || lane.Cleaned || lane.LaunchID != record.Reservation.LaunchID || lane.CancellationEpoch != record.Reservation.CancellationEpoch {
			return api.LaunchPlan{}, integrity("opened launch no longer has its actual current binding")
		}
		grants, err := s.revalidate(ctx, scope, lane)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		if grants.PolicyGeneration != record.Reservation.PolicyGeneration {
			return api.LaunchPlan{}, integrity("opened launch grants changed their historical policy")
		}
		execution.input.budget = record.Plan.Budget
		if err := execution.verifyPlanned(ctx, *record.Plan); err != nil {
			return api.LaunchPlan{}, err
		}
		if err := execution.verifyCapture(ctx, *record.Plan); err != nil {
			return api.LaunchPlan{}, err
		}
		if err := execution.recovery(ctx, *record.Plan); err != nil {
			return api.LaunchPlan{}, err
		}
		return *record.Plan, nil
	}
	check = "plan_original"
	if err := execution.original(ctx); err != nil {
		return api.LaunchPlan{}, err
	}
	check = "plan_sources"
	inputs, err := execution.sourceInputs(ctx)
	if err != nil {
		return api.LaunchPlan{}, err
	}
	if record.Phase == "reserved" {
		next := record
		next.Phase, next.Inputs = "sourced", &inputs
		if err := execution.save(ctx, next); err != nil {
			return api.LaunchPlan{}, err
		}
	}
	if execution.record.Plan == nil {
		check = "plan_allocation"
		allocation, err := execution.allocate(ctx, inputs)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		check = "plan_materialize"
		data, err := execution.materialize(ctx, inputs, allocation)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		check = "plan_runner"
		runner, injection, err := execution.runnerPlan(ctx, inputs, data)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		check = "plan_capture"
		capture, err := execution.capture(ctx, inputs, allocation)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		capturePolicy, err := execution.capturePolicy(ctx, capture)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		plan := api.LaunchPlan{CapturePolicy: capturePolicy, Reservation: execution.record.Reservation, Inputs: inputs,
			Lease: allocation, Data: data, Runner: runner, Injection: injection, Budget: execution.input.budget, Capture: capture}
		check = "plan_validate"
		if err := api.ValidateLaunchPlan(plan); err != nil {
			api.ObserveHelperReason(ctx, err, api.HelperReason(err))
			return api.LaunchPlan{}, failure(err)
		}
		check = "plan_retain"
		if _, err := execution.retain(ctx, "plan", "manifest", plan); err != nil {
			return api.LaunchPlan{}, err
		}
		next := execution.record
		next.Phase, next.Plan = "planned", &plan
		next.Generation = execution.record.Generation + 1
		kind := api.EventKind("capture.bound")
		if capture.Status == "refused" {
			kind = "capture.refused"
		}
		check = "plan_events"
		captureEvent, err := execution.event(kind, capture)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		planned, err := execution.event("launch.planned", next)
		if err != nil {
			return api.LaunchPlan{}, err
		}
		check = "plan_publish"
		if err := execution.save(ctx, next, captureEvent, planned); err != nil {
			return api.LaunchPlan{}, err
		}
	}
	plan := *execution.record.Plan
	if !reflect.DeepEqual(plan.Reservation, execution.record.Reservation) || api.ValidateLaunchPlan(plan) != nil {
		return api.LaunchPlan{}, integrity("retained plan no longer matches its reservation")
	}
	check = "plan_verify"
	if err := execution.verifyPlanned(ctx, plan); err != nil {
		return api.LaunchPlan{}, err
	}
	if err := execution.verifyCapture(ctx, plan); err != nil {
		return api.LaunchPlan{}, err
	}
	if execution.record.Phase == "planned" {
		check = "plan_seal"
		if err := execution.seal(ctx, plan); err != nil {
			return api.LaunchPlan{}, err
		}
	}
	check = "plan_recovery"
	if err := execution.recovery(ctx, plan); err != nil {
		return api.LaunchPlan{}, err
	}
	if plan.Capture.Status == "refused" {
		if err := execution.verifyCapture(ctx, plan); err != nil {
			return api.LaunchPlan{}, err
		}
	}
	return plan, nil
}
