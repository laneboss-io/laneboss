package linux

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The installed source owns the durable claim and Scope. The shared reader
// preserves its error and validates the retained selector and record.
func readAgentPlan(ctx context.Context, source ControlSource, id api.ID) (api.LaunchPlanRecord, error) {
	if err := contextError(ctx); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	return api.ReadLaunchPlan(ctx, source, id)
}

func validatePlanSelector(record api.LaunchPlanRecord, id api.ID) error {
	if record.Reservation.ID != id {
		return failure(api.CodeIntegrity, "plan lookup returned another reservation")
	}
	return nil
}

func validatePreparePhase(plan api.LaunchPlanRecord) error {
	if plan.Phase != "spec_retained" {
		return failure(api.CodeIntegrity, "bound or opened plans require original-gate recovery")
	}
	return nil
}

// These are consumer checks on records read under the service's current claim.
// They cannot attest enrollment, issue a reservation or reconstruct lost data.
func validateAgentHandoff(spec api.LaunchSpec, handoff api.PreparedSpecHandoff, original []byte, record api.LaunchPlanRecord) error {
	if err := validatePlanSelector(record, spec.PlanID); err != nil {
		return err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return err
	}
	if record.Phase != "spec_retained" && record.Phase != "bound" && record.Phase != "opened" ||
		record.Plan == nil || record.Handoff == nil {
		return failure(api.CodeIntegrity, "agent prepare has no retained spec and plan")
	}
	if err := api.ValidateAgentLaunchSpec(spec, *record.Plan); err != nil {
		return err
	}
	if !reflect.DeepEqual(handoff, *record.Handoff) {
		return failure(api.CodeIntegrity, "handoff differs from the retained launch plan")
	}
	return validateHandoff(spec, handoff, original)
}

func validateAgentRuntime(plan api.LaunchPlan, runtime api.ResolvedRuntime) error {
	if plan.Runner.Driver != plan.Reservation.Driver {
		return failure(api.CodeIntegrity, "runner differs from the reserved driver")
	}
	if err := validatePlanCapture(plan); err != nil {
		return err
	}
	if runtime.Workspace != plan.Data.Workspace || runtime.Home != plan.Data.Home.Home {
		return failure(api.CodeIntegrity, "runtime differs from reserved private storage")
	}
	// An executable label is not enrollment. The helper resolves these objects
	// from its protected manifest and pins their opened bytes independently.
	executable := plan.Inputs.Sources.Runtime.Executable
	return validateEnrolledExecutable(executable, runtime)
}

func validateEnrolledExecutable(executable api.Executable, runtime api.ResolvedRuntime) error {
	matches := 0
	for _, object := range runtime.Manifest.Objects {
		if object.ID == executable.ID && object.Content.SHA256 == executable.SHA256 &&
			object.Mode&0111 != 0 {
			matches++
		}
	}
	if matches != 1 {
		return failure(api.CodeIntegrity, "enrolled executable has no unique runtime object")
	}
	return nil
}

func validatePlanCapture(plan api.LaunchPlan) error {
	if plan.Capture.Status != "refused" {
		capture := plan.Capture
		return api.ValidateCaptureBinding(capture)
	}
	policy := plan.CapturePolicy
	if policy == nil || policy.Generation != plan.Reservation.PolicyGeneration {
		return failure(api.CodeIntegrity, "capture refusal lacks the reserved policy snapshot")
	}
	if err := api.ValidateCapturePolicy(plan.Capture, *policy); err != nil {
		return err
	}
	return nil
}

func validateReservedActor(record api.LaunchRecord, reservation api.LaunchReservation) error {
	if record.Actor.Level != reservation.Level || record.Actor.Role != reservation.Role {
		return failure(api.CodeIntegrity, "bound actor differs from the reserved level or role")
	}
	return nil
}

func validateAgentBinding(binding api.LaunchBindingRequest, record api.LaunchPlanRecord, manifest api.BlobRef) error {
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return err
	}
	if record.Phase != "bound" && record.Phase != "opened" || record.Plan == nil || record.Handoff == nil ||
		binding.Recovery == nil {
		return failure(api.CodeIntegrity, "agent launch has no retained bound recovery")
	}
	recovery := binding.Recovery
	if !reflect.DeepEqual(recovery.Handoff, *record.Handoff) {
		return failure(api.CodeIntegrity, "binding differs from the retained handoff")
	}
	if err := validateReservedActor(binding.Record, record.Reservation); err != nil {
		return err
	}
	if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); err != nil {
		return err
	}
	// Expiry and the installed manifest are checked anew after a restart. The
	// service and helper also independently check current policy and revocation.
	return validateSpec(recovery.Handoff.Spec, manifest, time.Now())
}

func validateStageCause(ctx context.Context, cause api.InternalIntent, kind api.InternalKind, handoff api.PreparedSpecHandoff) error {
	if err := validateCause(cause, kind, handoff.Spec.Target); err != nil {
		return err
	}
	original := handoff.Cause
	if cause.Actor.Kind != "service" || cause.Config != handoff.Config ||
		cause.CauseOperationID != handoff.OperationID || cause.CauseRequestID != handoff.RequestID ||
		cause.RequestedBy != original.RequestedBy || cause.CancellationEpoch != original.CancellationEpoch ||
		cause.ID == original.ID {
		return failure(api.CodeIntegrity, "helper stage differs from its original requester or fence")
	}
	if cause.EffectID == original.EffectID && (kind != api.InternalHelperOpen || !planningOpenClaim(ctx, cause, handoff)) {
		return failure(api.CodeIntegrity, "helper stage differs from its original requester or fence")
	}
	return nil
}

// Source.Open has already reloaded the durable claim. The parent PlanLaunch
// owns open as well as planning; prepare retains its distinct child effect.
// Match that exact parent here instead of requiring a fabricated new effect.
func planningOpenClaim(ctx context.Context, cause api.InternalIntent, handoff api.PreparedSpecHandoff) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	lease, ok := api.EffectLeaseFromContext(ctx)
	record := lease.Record
	effect := record.Effect
	if !ok || !api.EffectLeaseClaimed(lease) || record.Outcome != nil || record.Generation == 0 || record.ClaimID == "" ||
		record.ClaimID != lease.ClaimID || record.ClaimExpiresAt != lease.ExpiresAt || record.ClaimantID == "" ||
		effect.ID != cause.EffectID || effect.OperationID != handoff.OperationID || effect.PlanLaunch == nil ||
		effect.PlanLaunch.ReservationID != handoff.Spec.PlanID || effect.Context == nil || effect.Context.Kind != api.InternalLaunchPlan {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if err != nil || !expires.After(time.Now()) {
		return false
	}
	current := *effect.Context
	current.Kind, current.ID = api.InternalHelperOpen, cause.ID
	current.Actor = api.Actor{Kind: "service", ID: record.ClaimantID}
	return current == cause
}
