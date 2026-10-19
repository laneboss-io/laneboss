package store

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type decisionSnapshot struct {
	ID         api.ID
	Target     api.LifeRef
	Policy     api.Generation
	AsOf       api.Timestamp
	Candidates []api.DecisionCandidate
}
type guidanceTurn struct{ ReservationID api.ID }

func guidanceKey(config string, life, turn api.ID) api.ID {
	return api.ID(hash([]byte(config + ":" + string(life) + ":" + string(turn))))
}

func (s *Service) guidanceScope(ctx context.Context, scope api.Scope, target api.LifeRef) error {
	if scope.Actor.Kind == "lane" && scope.Actor.LifeID != target.LifeID || scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" && !internalScope(scope) {
		return fault(api.CodeForbidden, "guidance lookup belongs to another life")
	}
	return s.readScope(ctx, scope)
}

func (s *Service) DecisionCandidates(ctx context.Context, scope api.Scope, request api.DecisionQuery) (api.DecisionPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result api.DecisionPage
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.guidanceScope(ctx, scope, request.Target); err != nil {
		return result, err
	}
	return s.decisionCandidates(ctx, scope, request, nil)
}

func (s *Service) decisionCandidates(ctx context.Context, scope api.Scope, request api.DecisionQuery, reserved *api.Lane) (result api.DecisionPage, err error) {
	if request.Limit < 1 || request.Limit > 200 || request.Kind != "binding" && request.Kind != "reminder" {
		return result, wire.Invalid("candidate snapshot requires bounded binding or reminder pages")
	}
	var snapshot decisionSnapshot
	if request.SnapshotID != "" {
		if err := storedProjection(ctx, s.db, "decision_snapshot", request.SnapshotID, &snapshot); err != nil {
			return result, err
		}
		if snapshot.Target != request.Target {
			return result, fault(api.CodeForbidden, "candidate snapshot belongs to another target")
		}
	} else {
		if request.Cursor != "" {
			return result, wire.Invalid("candidate cursor requires its retained snapshot")
		}
		var lane api.Lane
		var policy api.EffectivePolicy
		if reserved != nil {
			lane = *reserved
		} else if err := storedProjection(ctx, s.db, "lane", request.Target.LifeID, &lane); err != nil {
			return result, err
		}
		if lane.Run != request.Target.Run || lane.Cleaned {
			return result, fault(api.CodeConflict, "candidate snapshot target changed")
		}
		if err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &policy); err != nil {
			return result, err
		}
		id, err := wire.NewID()
		if err != nil {
			return result, err
		}
		snapshot = decisionSnapshot{ID: id, Target: request.Target, Policy: policy.Generation, AsOf: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), Candidates: []api.DecisionCandidate{}}
		rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='decision' ORDER BY id LIMIT 12801")
		if err != nil {
			return result, err
		}
		scanned := 0
		for rows.Next() {
			scanned++
			var data []byte
			var decision api.DecisionProjection
			if err := rows.Scan(&data); err != nil {
				rows.Close()
				return result, err
			}
			if err := decodeStored(data, &decision); err != nil {
				rows.Close()
				return result, err
			}
			if decision.Status != "active" {
				continue
			}
			c := decision.Candidate
			a := c.AppliesTo
			if len(a.Levels) > 0 && !slices.Contains(a.Levels, lane.Level) || len(a.Roles) > 0 && !slices.Contains(a.Roles, lane.Role) || len(a.ProjectIDs) > 0 && !slices.Contains(a.ProjectIDs, lane.Workspace.ProjectID) || len(a.LifeIDs) > 0 && !slices.Contains(a.LifeIDs, lane.LifeID) {
				continue
			}
			if c.ID != decision.RecordID || c.Authority.SourceSeq == 0 || c.Authority.Kind != "human" && c.Authority.Kind != "d6" {
				rows.Close()
				return result, fault(api.CodeIntegrity, "candidate lost canonical decision authority")
			}
			snapshot.Candidates = append(snapshot.Candidates, c)
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil {
			return result, readErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		if scanned > 12800 {
			return result, fault(api.CodeUnavailable, "candidate snapshot exceeds complete retrieval bound")
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return result, err
		}
		defer tx.Rollback()
		if err := put(ctx, tx, "decision_snapshot", id, 1, snapshot); err != nil {
			return result, err
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
	}
	filter := struct {
		Snapshot api.ID
		Kind     string
		Target   api.LifeRef
	}{snapshot.ID, request.Kind, request.Target}
	current, err := s.cursor(scope, filter, request.Cursor)
	if err != nil {
		return result, err
	}
	items := []api.DecisionCandidate{}
	for _, candidate := range snapshot.Candidates {
		if candidate.Binding == (request.Kind == "binding") {
			items = append(items, candidate)
		}
	}
	if current.Position > uint64(len(items)) {
		return result, wire.Invalid("candidate cursor exceeds its immutable snapshot")
	}
	end := min(len(items), int(current.Position)+request.Limit)
	result = api.DecisionPage{SnapshotID: snapshot.ID, PolicyGeneration: snapshot.Policy, AsOf: snapshot.AsOf, Candidates: append([]api.DecisionCandidate{}, items[int(current.Position):end]...), Complete: end == len(items)}
	if !result.Complete {
		current.Position = uint64(end)
		result.Cursor, err = s.signCursor(current)
	}
	return result, err
}

func (s *Service) guidanceReservation(ctx context.Context, db queryer, life, turn api.ID) (api.GuidanceReservation, error) {
	var pointer guidanceTurn
	var result api.GuidanceReservation
	if err := storedProjection(ctx, db, "guidance_turn", guidanceKey(s.deps.Config, life, turn), &pointer); err != nil {
		return result, err
	}
	if err := storedProjection(ctx, db, "guidance", pointer.ReservationID, &result); err != nil {
		return result, err
	}
	result.Acquired = false
	return result, api.ValidateGuidanceReservation(result)
}

func (s *Service) GuidanceReservation(ctx context.Context, scope api.Scope, target api.LifeRef, turn api.ID) (api.GuidanceReservation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result api.GuidanceReservation
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.guidanceScope(ctx, scope, target); err != nil {
		return result, err
	}
	result, err := s.guidanceReservation(ctx, s.db, target.LifeID, turn)
	if err == nil && (result.Target.LifeID != target.LifeID || result.Target.Run > target.Run) {
		return api.GuidanceReservation{}, fault(api.CodeForbidden, "guidance claim belongs to a foreign run")
	}
	return result, err
}

func (s *Service) ReserveGuidance(ctx context.Context, scope api.Scope, request api.GuidanceReservationRequest) (api.GuidanceReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result api.GuidanceReservation
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.guidanceScope(ctx, scope, request.Target); err != nil {
		return result, err
	}
	var lane api.Lane
	var turn api.TurnSnapshot
	if err := storedProjection(ctx, s.db, "lane", request.Target.LifeID, &lane); err != nil {
		return result, err
	}
	if err := storedProjection(ctx, s.db, "turn", request.LogicalTurnID, &turn); err != nil {
		return result, err
	}
	if lane.Cleaned || lane.Run != request.Target.Run || lane.LogicalTurnID != request.LogicalTurnID || turn.Task != request.ExpectedTask || lane.CancellationEpoch != request.CancellationEpoch {
		return result, fault(api.CodeConflict, "guidance target task or cancellation fence changed")
	}
	result, err := s.guidanceReservation(ctx, s.db, lane.LifeID, request.LogicalTurnID)
	if err == nil {
		return result, nil
	}
	if !absent(err) {
		return result, err
	}
	if scope.Request.Method != "guidance.select" || scope.Request.Proof != nil || !wire.ValidID(string(request.AttemptID)) || request.ExpectedTurnGeneration != turn.Generation || request.MaxCostMicros <= 0 || request.MaxCostMicros > 1<<53-1 {
		return result, fault(api.CodeForbidden, "guidance reservation lacks its actual pending owner request and budget")
	}
	receipt, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return result, err
	}
	if receipt.Reply != nil {
		return result, fault(api.CodeConflict, "completed guidance request cannot acquire a new evaluator")
	}
	var policy api.EffectivePolicy
	var snapshot decisionSnapshot
	if err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return result, err
	}
	if err := storedProjection(ctx, s.db, "decision_snapshot", request.CandidateSnapshotID, &snapshot); err != nil {
		return result, err
	}
	if request.PolicyGeneration != policy.Generation || snapshot.Policy != policy.Generation || snapshot.Target != request.Target {
		return result, fault(api.CodeConflict, "fresh guidance inputs are not at current approved policy")
	}
	now := s.deps.Clock.Now()
	deadline, err := time.Parse(time.RFC3339Nano, string(request.Deadline))
	if err != nil || !deadline.After(now) || deadline.After(now.Add(5*time.Second)) {
		return result, wire.Invalid("guidance deadline exceeds the one total budget")
	}
	id, err := wire.NewID()
	if err != nil {
		return result, err
	}
	claim, err := wire.NewID()
	if err != nil {
		return result, err
	}
	result = api.GuidanceReservation{Config: s.deps.Config, ID: id, Target: request.Target, LogicalTurnID: request.LogicalTurnID, Task: turn.Task, PolicyGeneration: policy.Generation, TurnGeneration: turn.Generation, CandidateSnapshotID: request.CandidateSnapshotID, Generation: 1, ClaimID: claim, Status: "pending", ReservedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano)), Deadline: request.Deadline, OwnerAttemptID: request.AttemptID, OwnerOperationID: receipt.Operation.ID, OwnerRequestID: scope.Request.RequestID, OwnerKey: receipt.Key, RequestedBy: scope.Actor, CancellationEpoch: request.CancellationEpoch, MaxCostMicros: request.MaxCostMicros, BindingItems: []api.GuidanceItem{}}
	for _, candidate := range snapshot.Candidates {
		if candidate.Binding {
			at, err := time.Parse(time.RFC3339Nano, string(candidate.EffectiveAt))
			if err != nil {
				return api.GuidanceReservation{}, err
			}
			age := max(int64(0), int64(now.Sub(at)/time.Second))
			result.BindingItems = append(result.BindingItems, api.GuidanceItem{DecisionID: candidate.ID, Source: candidate.Source, AgeSeconds: age, Weight: 1, Binding: true})
		}
	}
	if err := api.ValidateGuidanceReservation(result); err != nil {
		return api.GuidanceReservation{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.GuidanceReservation{}, err
	}
	defer tx.Rollback()
	if err := put(ctx, tx, "guidance", id, 1, result); err != nil {
		return api.GuidanceReservation{}, err
	}
	if err := put(ctx, tx, "guidance_turn", guidanceKey(s.deps.Config, lane.LifeID, turn.LogicalTurnID), 1, guidanceTurn{ReservationID: id}); err != nil {
		return api.GuidanceReservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return api.GuidanceReservation{}, err
	}
	s.notifyChanged()
	result.Acquired = true
	return result, nil
}

func (s *Service) writeGuidance(ctx context.Context, tx *sql.Tx, input api.Transaction) error {
	if len(input.Writes.Guidance) != 1 || len(input.Events) != 1 {
		return fault(api.CodeForbidden, "guidance completion requires one result and event")
	}
	selection := input.Writes.Guidance[0]
	var retained api.GuidanceReservation
	if err := storedProjection(ctx, tx, "guidance", selection.ReservationID, &retained); err != nil {
		return err
	}
	if input.Internal == nil {
		return fault(api.CodeForbidden, "guidance completion requires its original internal owner")
	}
	if err := api.ValidateGuidanceCompletion(retained, selection, *input.Internal, s.deps.Clock.Now()); err != nil {
		return err
	}
	if selection.Result.Status == "scored" || len(selection.Result.JudgmentIDs) != 0 || selection.Result.JudgmentID != "" || selection.Result.WeightedScore != nil && (selection.Result.Status != "empty" || *selection.Result.WeightedScore != 0) {
		if err := s.verifyGuidanceJudgments(ctx, tx, retained, selection.Result); err != nil {
			return err
		}
	}
	if retained.LaunchReservationID != "" {
		var plan api.LaunchPlanRecord
		if err := storedProjection(ctx, tx, "launch_plan", retained.LaunchReservationID, &plan); err != nil {
			return err
		}
		r := plan.Reservation
		if r.OperationID != retained.OwnerOperationID || r.RequestID != retained.OwnerRequestID || r.RequestedBy != retained.RequestedBy || r.Target != retained.Target || r.CancellationEpoch != retained.CancellationEpoch {
			return fault(api.CodeForbidden, "guidance launch owner differs from its protected reservation")
		}
		if r.Loop != nil {
			receipt, err := s.reservationReceipt(ctx, tx, plan)
			if err != nil {
				return err
			}
			if retained.OwnerKey != receipt.Key || retained.LaunchEffectID != r.Loop.PlanEffectID || retained.LogicalTurnID != r.Loop.LogicalTurnID {
				return fault(api.CodeForbidden, "loop guidance changed its retained private owner key")
			}
		}
		if input.Internal.Kind == api.InternalGuidanceComplete {
			current, err := effectRow(ctx, tx, retained.LaunchEffectID)
			if err != nil {
				return err
			}
			lease := api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt}
			if _, err := s.launchPrompt(ctx, tx, input.Scope, api.LaunchPromptRequest{ReservationID: r.ID, Lease: lease}); err != nil {
				return err
			}
			if input.Internal.EffectID != retained.LaunchEffectID {
				return fault(api.CodeForbidden, "guidance completion lost its planning effect")
			}
		}
	}
	if selection.Result.Status == "empty" {
		var snapshot decisionSnapshot
		if err := storedProjection(ctx, tx, "decision_snapshot", retained.CandidateSnapshotID, &snapshot); err != nil {
			return err
		}
		for _, candidate := range snapshot.Candidates {
			if !candidate.Binding {
				return fault(api.CodeForbidden, "empty guidance requires an actually empty reminder snapshot")
			}
		}
	}
	for _, item := range selection.Result.Items {
		if selection.Result.Status != "scored" && (!item.Binding || item.Score != nil) {
			return fault(api.CodeForbidden, "unscored guidance cannot claim a historical score")
		}
	}
	event := input.Events[0]
	if event.Kind != "guidance.selected" || event.LifeID != retained.Target.LifeID || event.Run != retained.Target.Run || !sameValue(event.Payload, selection.Result) {
		return fault(api.CodeForbidden, "guidance completion event differs from its one retained result")
	}
	var turn api.TurnSnapshot
	if err := storedProjection(ctx, tx, "turn", retained.LogicalTurnID, &turn); err != nil {
		return err
	}
	if turn.Generation != retained.TurnGeneration {
		return fault(api.CodeConflict, "guidance logical turn revision changed")
	}
	turn.Generation++
	turn.GuidanceID = selection.Result.ID
	for _, submitted := range input.Writes.Turns {
		if !sameValue(submitted, turn) {
			return fault(api.CodeForbidden, "guidance completion changed unrelated turn inputs")
		}
	}
	if err := put(ctx, tx, "turn", turn.LogicalTurnID, turn.Generation, turn); err != nil {
		return err
	}
	retained.Acquired, retained.Status, retained.Generation, retained.Result = false, "completed", 2, &selection.Result
	if err := put(ctx, tx, "guidance", retained.ID, 2, retained); err != nil {
		return err
	}
	return nil
}

func (s *Service) AwaitGuidance(ctx context.Context, scope api.Scope, request api.GuidanceAwaitRequest) (api.GuidanceReservation, error) {
	deadline, err := time.Parse(time.RFC3339Nano, string(request.Deadline))
	if err != nil {
		return api.GuidanceReservation{}, err
	}
	for {
		s.mu.RLock()
		if err := s.available(); err != nil {
			s.mu.RUnlock()
			return api.GuidanceReservation{}, err
		}
		var result api.GuidanceReservation
		err := storedProjection(ctx, s.db, "guidance", request.ReservationID, &result)
		if err == nil {
			err = s.guidanceScope(ctx, scope, result.Target)
		}
		changed := s.changed
		s.mu.RUnlock()
		if err != nil {
			return result, err
		}
		result.Acquired = false
		if err := api.ValidateGuidanceReservation(result); err != nil {
			return result, err
		}
		if result.Status == "completed" {
			return result, nil
		}
		claimDeadline, err := time.Parse(time.RFC3339Nano, string(result.Deadline))
		if err != nil {
			return result, err
		}
		if claimDeadline.Before(deadline) {
			deadline = claimDeadline
		}
		remaining := deadline.Sub(s.deps.Clock.Now())
		if remaining <= 0 {
			return result, fault(api.CodeDeadline, "guidance await exceeded its existing total deadline")
		}
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, ctx.Err()
		case <-changed:
			timer.Stop()
		case <-timer.C:
			return result, fault(api.CodeDeadline, "guidance await did not observe completion")
		}
	}
}
