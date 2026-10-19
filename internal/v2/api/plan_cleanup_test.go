package api

import "testing"

func failedCleanupFixture(t *testing.T) (Transaction, []PlanCleanup) {
	t.Helper()
	p := launchFixture(t)
	r := p.Reservation
	actor := Actor{Kind: "service", ID: "planner"}
	cause := InternalIntent{ID: "failed-write", Kind: InternalLaunchPlan, Config: r.Config, Actor: actor, RequestedBy: r.RequestedBy,
		CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: "planning-effect", Target: r.Target, CancellationEpoch: r.CancellationEpoch}
	tx := Transaction{Scope: Scope{Config: r.Config, Actor: actor, PolicyGeneration: r.PolicyGeneration}, Internal: &cause,
		Writes:  StateWrites{LaunchPlans: []LaunchPlanRecord{{Reservation: r, Generation: 2, Phase: "failed", Error: &Error{Code: CodeUnavailable, Owner: "lb-v2-lifecycle"}}}},
		Compare: []Compare{{Kind: CompareLaunchPlan, ID: r.ID, Generation: 1}},
		Guards:  []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
	jobs := []PlanCleanup{}
	for _, kind := range []string{"release", "revoke_injection"} {
		c := cause
		c.ID, c.Kind, c.EffectID = ID("cleanup-cause-"+kind), InternalHelperRelease, ID("cleanup-"+kind)
		jobs = append(jobs, PlanCleanup{ID: c.EffectID, Kind: kind, Cause: c, ReservationID: r.ID, LaunchID: r.LaunchID,
			Slot: p.Runner.Slot, SlotKnown: true, SlotResult: launchFixtureBlob("slot-result", "manifest")})
	}
	return tx, jobs
}

func TestPlanCleanup(t *testing.T) {
	for _, fault := range []string{"missing", "reservation", "slot", "epoch", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			tx, jobs := failedCleanupFixture(t)
			if err := ValidateFailedPlanWrite(tx, jobs); err != nil {
				t.Fatal("valid atomic cleanup request was refused", err)
			}
			if fault == "missing" {
				jobs = jobs[:1]
			}
			for i := range jobs {
				switch fault {
				case "reservation":
					jobs[i].ReservationID = "foreign-reservation"
				case "slot":
					jobs[i].Slot.LeaseID = ""
				case "epoch":
					jobs[i].Cause.CancellationEpoch++
				case "unknown":
					jobs[i].SlotKnown, jobs[i].Slot = false, CredentialSlot{}
				}
			}
			contractCode(t, ValidateFailedPlanWrite(tx, jobs), CodeInvalid, "failed plan cleanup boundary was bypassed")
		})
	}
}

func TestCleanupPending(t *testing.T) {
	tx, jobs := failedCleanupFixture(t)
	job := jobs[0]
	job.Kind, job.ID = "withdraw", "cleanup-withdraw"
	job.Cause.Kind, job.Cause.EffectID = InternalHelperAbort, job.ID
	job.Issues = []*Error{{Code: CodeContainmentUnknown, Owner: "lb-v2-admin"}}
	if err := ValidateFailedPlanWrite(tx, []PlanCleanup{job}); err != nil {
		t.Fatal("uncertain projection must retain reconciliation", err)
	}
	job.Issues = nil
	contractCode(t, ValidateFailedPlanWrite(tx, []PlanCleanup{job}), CodeInvalid, "uncertain projection lost its reconciliation issue")
}

func retainedCleanup(t *testing.T, loop, projected bool) (Transaction, []PlanCleanup) {
	t.Helper()
	tx, jobs := failedCleanupFixture(t)
	p := launchFixture(t)
	if loop {
		p = loopPlanFixture(t)
		r := p.Reservation
		tx.Writes.LaunchPlans[0].Reservation = r
		tx.Internal.RequestedBy, tx.Internal.Target = r.RequestedBy, r.Target
		tx.Internal.EffectID, tx.Internal.LogicalTurnID = r.Loop.PlanEffectID, r.Loop.LogicalTurnID
		for i := range jobs {
			jobs[i].Cause.RequestedBy, jobs[i].Cause.Target = r.RequestedBy, r.Target
			jobs[i].Cause.LogicalTurnID = r.Loop.LogicalTurnID
		}
	}
	tx.Writes.LaunchPlans[0].Inputs, tx.Writes.LaunchPlans[0].Plan = &p.Inputs, &p
	for i := range jobs {
		injection := p.Injection
		jobs[i].Injection = &injection
	}
	if projected {
		binding := launchFixtureBinding(t, p)
		tx.Writes.LaunchPlans[0].Handoff = &binding.Recovery.Handoff
		job := jobs[0]
		job.ID, job.Kind = "cleanup-withdraw", "withdraw"
		job.Cause.Kind, job.Cause.EffectID = InternalHelperAbort, job.ID
		job.Prepared = &binding.Prepared
		job.Withdrawal = &CredentialWithdrawalRequest{ProjectionID: "projection-one", ExpectedGeneration: 1, Cause: job.Cause, Reason: "refused"}
		jobs = []PlanCleanup{job}
	}
	return tx, jobs
}

func TestCleanupFields(t *testing.T) {
	for _, fault := range []string{"grants", "workers", "grants_event", "capture_event", "cause", "planner_cause", "planner_effect", "profile_grant", "profile", "expiry", "plan_slot", "plan_injection", "unknown_slot", "loop_turn", "prepared_id", "prepared_launch", "containment", "endpoint", "gate", "process", "foreign_container", "foreign_endpoint"} {
		t.Run(fault, func(t *testing.T) {
			tx, jobs := failedCleanupFixture(t)
			switch fault {
			case "plan_slot", "plan_injection", "unknown_slot", "loop_turn":
				tx, jobs = retainedCleanup(t, fault == "loop_turn", false)
			case "prepared_id", "prepared_launch", "containment", "endpoint", "gate", "process", "foreign_container", "foreign_endpoint":
				tx, jobs = retainedCleanup(t, false, true)
			}
			if err := ValidateFailedPlanWrite(tx, jobs); err != nil {
				t.Fatal("valid retained cleanup was refused", err)
			}
			switch fault {
			case "grants":
				tx.Writes.Grants = []GrantSet{launchFixture(t).Inputs.Grants}
			case "workers":
				tx.Writes.WorkerLeases = []WorkerLease{{ID: "unrelated-worker"}}
			case "grants_event":
				tx.Events = []Event{{Kind: "grants.issued"}}
			case "capture_event":
				tx.Events = []Event{{Kind: "capture.bound"}}
			case "cause":
				jobs[1].Cause.ID = jobs[0].Cause.ID
			case "planner_cause":
				jobs[0].Cause.ID = tx.Internal.ID
			case "planner_effect":
				jobs[0].ID, jobs[0].Cause.EffectID = tx.Internal.EffectID, tx.Internal.EffectID
			}
			for i := range jobs {
				switch fault {
				case "profile_grant":
					jobs[i].Slot.ProfileGrantID = ""
				case "profile":
					jobs[i].Slot.ProfileID = ""
				case "expiry":
					jobs[i].Slot.ExpiresAt = ""
				case "plan_slot":
					jobs[i].Slot.ID = "different-slot"
				case "plan_injection":
					jobs[i].Injection.Outcome = "different-outcome"
				case "unknown_slot":
					jobs[i].SlotKnown, jobs[i].Slot = false, CredentialSlot{}
					jobs[i].Issues = []*Error{{Code: CodeUnavailable, Owner: "lb-v2-secrets"}}
				case "loop_turn":
					jobs[i].Cause.LogicalTurnID = "foreign-turn"
				case "prepared_id":
					jobs[i].Prepared.ID = ""
				case "prepared_launch":
					jobs[i].Prepared.ID = jobs[i].LaunchID
				case "containment":
					jobs[i].Prepared.ContainmentID = ""
				case "endpoint":
					jobs[i].Prepared.EndpointGeneration = 0
				case "gate":
					jobs[i].Prepared.GateID = ""
				case "process":
					jobs[i].Prepared.ProcessGeneration = ""
				case "foreign_container":
					jobs[i].Prepared.ContainmentID = "foreign-container"
				case "foreign_endpoint":
					jobs[i].Prepared.EndpointGeneration++
				}
			}
			contractCode(t, ValidateFailedPlanWrite(tx, jobs), CodeInvalid, "failed cleanup correlation was bypassed")
		})
	}
}

func TestCleanupAtomic(t *testing.T) {
	tx, jobs := retainedCleanup(t, false, false)
	if err := ValidateFailedPlanWrite(tx, jobs); err != nil {
		t.Fatal("valid atomic cleanup was refused", err)
	}
	contractCode(t, ValidateTransactionShape(tx), CodeInvalid, "planner failure bypassed its atomic cleanup writer")
	if validLaunchPlanWrite(tx, tx.Writes.LaunchPlans[0]) {
		t.Fatal("plain plan write bypassed cleanup batch")
	}
}
