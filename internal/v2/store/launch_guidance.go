package store

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// ReserveLaunchGuidance uses the actual planning claim and original launch
// receipt. It never reconstructs a public guidance request or human identity.
func (s *Service) ReserveLaunchGuidance(ctx context.Context, scope api.Scope, request api.LaunchGuidanceRequest) (result api.LaunchGuidanceInput, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if scope.ReadView != nil {
		return result, fault(api.CodeForbidden, "launch guidance mutation requires a fresh writer scope")
	}
	prompt, err := s.launchPrompt(ctx, s.db, scope, request.Prompt)
	if err != nil {
		return result, err
	}
	result.Prompt = prompt
	r, lane, turn := prompt.Reservation, prompt.Lane, prompt.Turn
	prior, err := s.guidanceReservation(ctx, s.db, r.Target.LifeID, turn.LogicalTurnID)
	if err == nil {
		if prior.LaunchReservationID != r.ID || prior.Task != lane.Task || prior.PolicyGeneration != r.PolicyGeneration {
			return result, fault(api.CodeConflict, "launch guidance belongs to another retained selection")
		}
		result.Claim = prior
		return result, nil
	}
	if !absent(err) {
		return result, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(request.Deadline))
	now := s.deps.Clock.Now()
	if err != nil || !deadline.After(now) || deadline.After(now.Add(5*time.Second)) || !wire.ValidID(string(request.AttemptID)) {
		return result, fault(api.CodeInvalid, "launch guidance needs one bounded deadline and internal attempt")
	}
	page, err := s.decisionCandidates(ctx, scope, api.DecisionQuery{Target: r.Target, Kind: "binding", Limit: 200}, &lane)
	if err != nil {
		return result, err
	}
	var snapshot decisionSnapshot
	if err := storedProjection(ctx, s.db, "decision_snapshot", page.SnapshotID, &snapshot); err != nil {
		return result, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", r.ID, &plan); err != nil {
		return result, err
	}
	receipt, err := s.reservationReceipt(ctx, s.db, plan)
	if err != nil {
		return result, err
	}
	id, err := wire.NewID()
	if err != nil {
		return result, err
	}
	claimID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	claim := api.GuidanceReservation{LaunchReservationID: r.ID, LaunchEffectID: request.Prompt.Lease.Record.Effect.ID,
		Config: r.Config, ID: id, Target: r.Target, LogicalTurnID: turn.LogicalTurnID, Task: lane.Task, PolicyGeneration: r.PolicyGeneration,
		TurnGeneration: turn.Generation, CandidateSnapshotID: snapshot.ID, Generation: 1, ClaimID: claimID, Status: "pending",
		ReservedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano)), Deadline: request.Deadline, OwnerAttemptID: request.AttemptID,
		OwnerOperationID: r.OperationID, OwnerRequestID: r.RequestID, OwnerKey: receipt.Key, RequestedBy: r.RequestedBy,
		CancellationEpoch: r.CancellationEpoch, MaxCostMicros: lane.BudgetRemaining.SpendMicros, BindingItems: []api.GuidanceItem{}}
	if s.deps.JudgeMaxCostMicros > 0 {
		claim.MaxCostMicros = min(claim.MaxCostMicros, s.deps.JudgeMaxCostMicros)
	}
	for _, candidate := range snapshot.Candidates {
		if candidate.Binding {
			at, err := time.Parse(time.RFC3339Nano, string(candidate.EffectiveAt))
			if err != nil {
				return result, err
			}
			claim.BindingItems = append(claim.BindingItems, api.GuidanceItem{DecisionID: candidate.ID, Source: candidate.Source,
				AgeSeconds: max(0, int64(now.Sub(at)/time.Second)), Weight: 1, Binding: true})
		}
	}
	if err := api.ValidateGuidanceReservation(claim); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	if err := putGenerated(ctx, tx, "turn", turn.LogicalTurnID, turn.Generation, turn); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "guidance", id, 1, claim); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "guidance_turn", guidanceKey(r.Config, r.Target.LifeID, turn.LogicalTurnID), 1, guidanceTurn{ReservationID: id}); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	claim.Acquired = true
	result.Claim, result.Candidates = claim, append([]api.DecisionCandidate{}, snapshot.Candidates...)
	s.notifyChanged()
	return result, nil
}
