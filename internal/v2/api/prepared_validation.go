package api

// The helper_prepare row's agent authority always requires its retained plan,
// even when an erroneous producer omits LaunchPlans entirely. Worker bindings
// use their separate fixed WorkerLease and can never create agent Lane rows.
func validPreparedPlanBindings(tx Transaction) bool {
	if tx.Internal == nil || tx.Internal.Kind != InternalHelperPrepare {
		return true
	}
	bound := func(planID, launchID ID, target LifeRef) *LaunchReservation {
		for _, record := range tx.Writes.LaunchPlans {
			if record.Phase == "bound" && record.Reservation.ID == planID && record.Reservation.LaunchID == launchID &&
				record.Reservation.Target == target && ValidateLaunchPlanRecord(record) == nil && validLaunchPlanWrite(tx, record) {
				copy := record.Reservation
				return &copy
			}
		}
		return nil
	}
	for _, binding := range tx.Writes.IdentityBindings {
		if binding.Record.Kind == "worker" {
			if binding.Record.Actor.Kind != "worker" {
				return false
			}
			continue
		}
		if binding.Record.Kind != "agent" || binding.Recovery == nil ||
			bound(binding.Recovery.PlanID, binding.Record.ID, binding.Record.Target) == nil {
			return false
		}
		valid := false
		for _, record := range tx.Writes.LaunchPlans {
			valid = valid || record.Reservation.ID == binding.Recovery.PlanID && record.Plan != nil &&
				ValidateLaunchBindingPlan(binding, *record.Plan) == nil
		}
		if !valid {
			return false
		}
	}
	for _, lane := range tx.Writes.Lanes {
		matched := false
		for _, record := range tx.Writes.LaunchPlans {
			r := bound(record.Reservation.ID, lane.LaunchID, LifeRef{LifeID: lane.LifeID, Run: lane.Run})
			matched = matched || r != nil && lane.Level == r.Level && lane.Role == r.Role && lane.Session.Driver == r.Driver
		}
		if !matched {
			return false
		}
	}
	for _, event := range tx.Events {
		if event.Kind != "lane.created" && event.Kind != "lane.adopted" {
			continue
		}
		matched := false
		for _, record := range tx.Writes.LaunchPlans {
			r := bound(record.Reservation.ID, record.Reservation.LaunchID, LifeRef{LifeID: event.LifeID, Run: event.Run})
			matched = matched || r != nil && (event.Kind == "lane.created" && r.Mode == "start" || event.Kind == "lane.adopted" && r.Mode == "adopt")
		}
		if !matched {
			return false
		}
	}
	return true
}
