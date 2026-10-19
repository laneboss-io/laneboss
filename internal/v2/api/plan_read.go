package api

import "context"

// The installed source resolves current durable claim authority internally.
// A launcher cannot manufacture Scope or reconstruct a plan from its spec.
func ReadLaunchPlan(ctx context.Context, source LaunchControlSource, reservationID ID) (LaunchPlanRecord, error) {
	if source == nil {
		return LaunchPlanRecord{}, NotImplemented("lb-v2-service", "launch control Plan")
	}
	if !launchID(reservationID) {
		return LaunchPlanRecord{}, launchInvalid("invalid retained launch-plan selector")
	}
	record, err := source.Plan(ctx, reservationID)
	if err != nil {
		return LaunchPlanRecord{}, err
	}
	if record.Reservation.ID != reservationID {
		return LaunchPlanRecord{}, launchInvalid("retained plan lookup returned another reservation")
	}
	if err := ValidateLaunchPlanRecord(record); err != nil {
		return LaunchPlanRecord{}, err
	}
	return record, nil
}
