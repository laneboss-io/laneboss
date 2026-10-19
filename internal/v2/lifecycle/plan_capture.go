package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The outside producer has its own physical job lifetime. Leave one bounded
// release-attempt window after the run for EOF, wait and authenticated drain;
// this never extends an agent budget or a planner's mutation authority.
const captureDrainWindow = 30 * time.Second

func (execution *planExecution) capture(ctx context.Context, inputs api.LaunchInputs, allocation api.HelperLease) (api.CaptureBinding, error) {
	r, s := execution.record.Reservation, execution.service
	if absent(s.deps.Capture) {
		return api.CaptureBinding{}, api.NotImplemented("lb-v2-admin", "CaptureControl.RegisterCapture")
	}
	cause := execution.cause(api.InternalLaunchPlan, "capture")
	request := api.CaptureRegistrationRequest{Claim: api.PlanningClaim(r.ID, execution.lease), Cause: cause, ReservationID: r.ID, HelperLeaseID: allocation.ID,
		WorkerLeaseID: launchObjectID(r.ID, "capture-worker")}
	input, err := execution.retain(ctx, "capture-request", "manifest", request)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	worker := api.WorkerLease{ID: request.WorkerLeaseID, Kind: "capture_supervisor", Target: r.Target,
		OperationID: r.OperationID, EffectID: cause.EffectID, Input: input, RuntimeManifest: inputs.Sources.Runtime.Manifest,
		GrantSetID: r.GrantSetID, Generation: 1}
	retained, lookupErr := s.deps.Store.WorkerLease(ctx, execution.scope, worker.ID)
	if lookupErr != nil && !notFound(lookupErr) {
		return api.CaptureBinding{}, failure(lookupErr)
	}
	if notFound(lookupErr) {
		planningEnd, err := time.Parse(time.RFC3339Nano, string(execution.lease.ExpiresAt))
		wall := execution.input.budget.WallMS
		if err != nil || wall <= 0 || wall > 604800000 {
			return api.CaptureBinding{}, integrity("capture lifetime lost its bounded planning window or run budget")
		}
		worker.ExpiresAt = api.Timestamp(planningEnd.Add(time.Duration(wall)*time.Millisecond + captureDrainWindow).UTC().Format(time.RFC3339Nano))
		if err := execution.transact(ctx, api.StateWrites{WorkerLeases: []api.WorkerLease{worker}}, nil, nil, nil); err != nil {
			return api.CaptureBinding{}, err
		}
	} else {
		// Expiry belongs to the original job. Renewing the planner claim must
		// not silently replace its kernel/producer ownership or input binding.
		worker.ExpiresAt = retained.ExpiresAt
		if !reflect.DeepEqual(worker, retained) {
			return api.CaptureBinding{}, integrity("capture retry changed its original worker lease")
		}
	}
	binding, err := launchStage(ctx, execution, "capture", request, func() (api.CaptureBinding, error) {
		return s.deps.Capture.RegisterCapture(ctx, request)
	})
	if err != nil {
		return api.CaptureBinding{}, err
	}
	if api.ValidateCaptureBinding(binding) != nil || binding.Config != r.Config || binding.ReservationID != r.ID ||
		binding.Target != r.Target || binding.LaunchID != r.LaunchID || binding.HelperLeaseID != allocation.ID ||
		binding.OperationID != r.OperationID || binding.RequestID != r.RequestID || binding.RequestedBy != r.RequestedBy ||
		binding.Status == "registered" && (binding.WorkerLeaseID != worker.ID || binding.EffectID != cause.EffectID) {
		return api.CaptureBinding{}, integrity("capture disposition differs from its reserved producer and cause")
	}
	// A stub/error is propagated above. Refused is accepted only as the
	// helper's explicit validated no-producer disposition; it is never invented
	// from authentication, integrity, partial-job or unknown-ownership failures.
	return binding, nil
}

func (execution *planExecution) verifyCapture(ctx context.Context, plan api.LaunchPlan) error {
	if plan.Capture.Status == "refused" {
		policy, err := execution.capturePolicy(ctx, plan.Capture)
		if err != nil {
			return err
		}
		if plan.CapturePolicy == nil || !reflect.DeepEqual(*plan.CapturePolicy, *policy) {
			return integrity("capture refusal policy changed before release")
		}
		return nil
	}
	if absent(execution.service.deps.Capture) {
		return api.NotImplemented("lb-v2-admin", "CaptureControl.ReconcileCapture")
	}
	current, err := execution.service.deps.Capture.ReconcileCapture(ctx, plan.Capture)
	if err != nil {
		return failure(err)
	}
	if !reflect.DeepEqual(current, plan.Capture) {
		return integrity("capture recovery changed the registered producer or pipe")
	}
	return nil
}

func (execution *planExecution) capturePolicy(ctx context.Context, binding api.CaptureBinding) (*api.EffectivePolicy, error) {
	if err := execution.currentPolicy(ctx); err != nil {
		return nil, err
	}
	policy, err := execution.service.deps.Store.Policy(ctx, execution.scope)
	if err != nil {
		return nil, failure(err)
	}
	if err := api.ValidateCapturePolicy(binding, policy); err != nil {
		return nil, failure(err)
	}
	if binding.Status != "refused" {
		return nil, nil
	}
	return &policy, nil
}
