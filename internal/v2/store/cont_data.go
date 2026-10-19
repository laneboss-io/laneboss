package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// A continued prompt and retained workspace snapshot keep their true original
// owner operation. Only exact references from the prior bound plan qualify.
func (s *Service) retainedPlanRef(ctx context.Context, db queryer, plan api.LaunchPlan, ref api.BlobRef, operation api.ID) (bool, error) {
	r := plan.Reservation
	if r.PreviousLaunchID == "" {
		return false, nil
	}
	binding, err := s.launchBinding(ctx, db, r.PreviousLaunchID)
	if err != nil {
		return false, err
	}
	if binding.Recovery == nil {
		return false, fault(api.CodeIntegrity, "retained data has no previous recovery")
	}
	var prior api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", binding.Recovery.PlanID, &prior); err != nil {
		return false, err
	}
	if prior.Plan == nil || operation != prior.Reservation.OperationID || prior.Reservation.Target.LifeID != r.Target.LifeID || prior.Reservation.Target.Run+1 != r.Target.Run {
		return false, nil
	}
	if ref == prior.Plan.Data.Workspace.Snapshot && plan.Data.Workspace.ID == prior.Plan.Data.Workspace.ID {
		return true, nil
	}
	return r.Mode == "continue" && ref == prior.Plan.Runner.Prompt && plan.Runner.Prompt == ref, nil
}
