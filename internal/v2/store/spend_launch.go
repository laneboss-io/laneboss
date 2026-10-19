package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// The check is repeated under the writer lock when prepare/open authority is
// issued. A plan or an earlier adapter check is not a reservation of money.
func (s *Service) checkSpendPlan(ctx context.Context, db queryer, plan api.LaunchPlanRecord) error {
	if plan.Plan == nil {
		return nil
	}
	if err := api.ValidateSpendCapture(*plan.Plan); err != nil {
		return err
	}
	_, err := s.checkCredentialSpend(ctx, db, plan.Plan.Runner.Slot)
	return err
}

func (s *Service) checkSpendLaunchTransaction(ctx context.Context, db queryer, input api.Transaction) error {
	if input.Internal != nil && (input.Internal.Kind == api.InternalHelperOpen || input.Internal.Kind == api.InternalHelperPrepare) {
		for _, plan := range input.Writes.LaunchPlans {
			if err := s.checkSpendPlan(ctx, db, plan); err != nil {
				return err
			}
		}
	}
	for _, effect := range input.Effects {
		if effect.Launch != nil && effect.Launch.Kind == "agent" {
			if effect.Launch.Runner == nil {
				return fault(api.CodeIntegrity, "agent launch has no sealed runner")
			}
			if _, err := s.checkCredentialSpend(ctx, db, effect.Launch.Runner.Slot); err != nil {
				return err
			}
		}
	}
	for _, lane := range input.Writes.Lanes {
		if lane.CredentialSpend != nil {
			return fault(api.CodeForbidden, "credential balance status cannot be written as lane state")
		}
	}
	return nil
}
