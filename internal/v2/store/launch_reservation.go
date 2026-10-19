package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type launchOwner struct {
	Request       api.LaunchReservationRequest
	ReservationID api.ID
	Actor         api.Actor
}

type launchName struct {
	LifeID        api.ID
	ReservationID api.ID
}

type launchAuthority struct {
	Ceiling  api.GrantSet
	TicketID api.ID
}

func absent(err error) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed.Code == api.CodeNotFound
}

// ReserveLaunch is the receipt-owner handoff. It runs under the sole writer
// lock and never waits for its own pending receipt or performs external work.
func (s *Service) ReserveLaunch(ctx context.Context, scope api.Scope, request api.LaunchReservationRequest) (result api.LaunchReservation, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := api.ValidateLaunchReservationRequest(scope, request); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if request.Loop != nil {
		return s.reserveLoop(ctx, scope, *request.Loop)
	}
	if !wire.ValidID(string(request.OperationID)) || request.ContinuationID != "" && !wire.ValidID(string(request.ContinuationID)) {
		return result, wire.Invalid("launch reservation requires its original operation")
	}
	if request.ContinuationID != "" && scope.Request.Method == "" {
		return s.reserveInternalContinuation(ctx, scope, request)
	}
	if err := wire.ValidateRequest(scope.Request); err != nil {
		return result, err
	}
	receipt, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return result, err
	}
	if receipt.Operation.ID != request.OperationID || receipt.Actor != scope.Actor {
		return result, fault(api.CodeForbidden, "launch reservation belongs to another operation or actor")
	}
	var owner launchOwner
	err = storedProjection(ctx, s.db, "launch_operation", request.OperationID, &owner)
	if err == nil {
		if !sameValue(owner.Request, request) || owner.Actor != scope.Actor {
			return result, fault(api.CodeIdempotencyConflict, "launch reservation retry changed its inputs")
		}
		var saved api.LaunchPlanRecord
		if err := storedProjection(ctx, s.db, "launch_plan", owner.ReservationID, &saved); err != nil {
			return result, err
		}
		if saved.Reservation.RequestSHA256 != scope.Request.RequestSHA256 || saved.Reservation.OperationID != request.OperationID {
			return result, fault(api.CodeIntegrity, "launch reservation lost its original receipt")
		}
		if err := s.checkLaunchBytes(ctx, s.db, saved); err != nil {
			return result, err
		}
		var operationData []byte
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(request.OperationID)).Scan(&operationData); err != nil {
			return result, err
		}
		var current api.Operation
		if err := wire.Decode(operationData, &current); err != nil {
			return result, err
		}
		if current.Status == "failed" || current.Status == "cancelled" {
			return result, fault(api.CodeConflict, "failed launch operation cannot reserve again")
		}
		return saved.Reservation, nil
	}
	if !absent(err) {
		return result, err
	}
	if receipt.Reply != nil || receipt.Operation.Status != "pending" {
		return result, fault(api.CodeConflict, "completed operation cannot reserve a new launch")
	}
	original, err := wire.DecodeRequest(receipt.RawRequest)
	if err != nil {
		return result, err
	}
	encoded, err := json.Marshal(scope.Request)
	if err != nil || !wire.SameJSON(encoded, receipt.RawRequest) {
		return result, fault(api.CodeConflict, "launch handoff differs from the reserved original frame")
	}
	if original.Config != s.deps.Config || len(receipt.RawRequest) > api.MaxFrameBytes {
		return result, wire.Invalid("invalid retained launch frame")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, tx, "policy", api.ID(scope.Config), &policy); err != nil {
		return result, err
	}
	if policy.Generation == 0 || scope.PolicyGeneration != policy.Generation {
		return result, fault(api.CodeConflict, "launch policy generation is stale")
	}
	result = api.LaunchReservation{Config: scope.Config, OperationID: request.OperationID, RequestID: original.RequestID,
		RequestSHA256: original.RequestSHA256, RequestedBy: receipt.Actor, PolicyGeneration: policy.Generation, StarterChain: []api.ID{}}
	for _, id := range []*api.ID{&result.ID, &result.LaunchID, &result.SpecID} {
		*id, err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	var guards []api.TransactionGuard
	var name string
	if request.ContinuationID != "" {
		result.Mode = "continue"
		err = s.reserveContinuation(ctx, tx, scope, request, &result)
	} else {
		switch original.Method {
		case "lane.start", "lane.adopt":
			var start api.StartRequest
			if original.Method == "lane.start" {
				err = api.DecodeObject(original.Params, &start)
				result.Mode = "start"
			} else {
				var adopt api.AdoptRequest
				err = api.DecodeObject(original.Params, &adopt)
				start = api.StartRequest{Lane: adopt.Lane, Level: adopt.Level, Role: adopt.Role, Task: adopt.Task, Grants: adopt.Grants, Driver: adopt.Driver,
					ProfileGrantID: adopt.ProfileGrantID, Model: adopt.Model, Effort: adopt.Effort, Budget: adopt.Budget,
					RootTicketID: adopt.RootTicketID, ExpectedPolicyGeneration: adopt.ExpectedPolicyGeneration}
				result.Mode = "adopt"
				if err == nil {
					err = s.launchInput(ctx, tx, scope, adopt.ImportManifest)
				}
			}
			if err != nil {
				return result, err
			}
			name = start.Lane
			guards, err = s.reserveNewLife(ctx, tx, scope, start, &result)
		case "lane.resume":
			var resume api.ResumeRequest
			if err = api.DecodeObject(original.Params, &resume); err == nil {
				result.Mode = "resume"
				err = s.launchInput(ctx, tx, scope, resume.Message)
				if err == nil {
					err = s.reserveRetainedLife(ctx, tx, scope, resume.Target, resume.ExpectedGeneration, resume.Budget, &result)
				}
			}
		case "lane.turn":
			var turn api.TurnRequest
			if err = api.DecodeObject(original.Params, &turn); err == nil {
				result.Mode = "turn"
				if turn.IdleMessage != nil {
					err = s.launchInput(ctx, tx, scope, *turn.IdleMessage)
				}
				if err == nil {
					err = s.reserveRetainedLife(ctx, tx, scope, turn.Target, turn.ExpectedGeneration, turn.Budget, &result)
				}
			}
		default:
			err = fault(api.CodeForbidden, "operation is not a launch intent")
		}
	}
	if err != nil {
		return result, err
	}
	// The submitted guards are required authority, not hints that may be
	// silently replaced by an inferred ticket/proof. Assign only the new ID
	// that did not exist when the caller supplied its root TicketUse.
	if len(guards) != 0 {
		if len(request.Guards) != len(guards) {
			return result, fault(api.CodeForbidden, "reservation authority differs from retained ticket")
		}
		for i := range guards {
			want := *guards[i].Ticket
			want.Target = api.LifeRef{}
			if request.Guards[i].Ticket == nil || *request.Guards[i].Ticket != want {
				return result, fault(api.CodeForbidden, "reservation authority differs from retained ticket")
			}
		}
	} else {
		guards = request.Guards
	}
	result.Authority = api.LaunchAuthority{Kind: "starter", ID: scope.LaunchID}
	for _, guard := range guards {
		if guard.Ticket != nil {
			result.Authority = api.LaunchAuthority{Kind: "ticket", ID: guard.Ticket.TicketID}
		}
		if guard.Proof != nil {
			result.Authority = api.LaunchAuthority{Kind: "proof", ID: guard.Proof.Proof.ID}
		}
	}
	if err := s.guards(ctx, tx, api.Transaction{Scope: scope, Guards: guards}, result.OperationID); err != nil {
		return result, err
	}
	objectID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	serviceActor := api.Actor{Kind: "service", ID: s.storeID}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	result.OriginalRequest, err = s.retain(ctx, tx, api.Scope{Config: scope.Config, Actor: serviceActor}, api.ObjectWrite{
		ObjectKey: objectID, Class: "launch_request", Bytes: receipt.RawRequest, SHA256: api.Digest(hash(receipt.RawRequest)), Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: serviceActor, LifeID: result.Target.LifeID, Audience: "owner", Generation: 1}}, result.OperationID, now)
	if err != nil {
		return result, err
	}
	if err := api.ValidateLaunchReservation(result); err != nil {
		return result, err
	}
	plan := api.LaunchPlanRecord{Reservation: result, Generation: 1, Phase: "reserved"}
	if err := put(ctx, tx, "launch_plan", result.ID, 1, plan); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "launch_operation", result.OperationID, 1, launchOwner{Request: request, ReservationID: result.ID, Actor: scope.Actor}); err != nil {
		return result, err
	}
	if name != "" {
		if err := put(ctx, tx, "launch_name", api.ID(name), 1, launchName{LifeID: result.Target.LifeID, ReservationID: result.ID}); err != nil {
			return result, err
		}
	}
	effectID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	intentID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	turnID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	cause := api.InternalIntent{ID: intentID, Kind: api.InternalLaunchPlan, Config: scope.Config, Actor: serviceActor, RequestedBy: result.RequestedBy,
		CauseOperationID: result.OperationID, CauseRequestID: result.RequestID, EffectID: effectID, Target: result.Target, CancellationEpoch: result.CancellationEpoch, LogicalTurnID: turnID}
	effect := api.Effect{ID: effectID, OperationID: result.OperationID, Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: result.ID}}
	if err := insertLaunchEffect(ctx, tx, effect); err != nil {
		return result, err
	}
	operation := receipt.Operation
	simulated, err := s.transactionPresence(ctx, tx, api.Transaction{Scope: scope, Guards: guards})
	if err != nil {
		return result, err
	}
	operation.SimulatedPresence = operation.SimulatedPresence || simulated
	receipt.SimulatedPresence, receipt.PolicyGeneration = operation.SimulatedPresence, policy.Generation
	operation.LifeID, operation.Run = result.Target.LifeID, result.Target.Run
	operationData, err := json.Marshal(operation)
	if err != nil {
		return result, err
	}
	receipt.Operation, receipt.Reply = operation, &api.RPCReply{Result: operationData}
	receiptData, err := json.Marshal(storedReceipt{Config: scope.Config, Receipt: receipt})
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=? AND principal=?", operationData, string(operation.ID), principal(scope)); err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO receipts VALUES(?,?,?,?,?,?)", principal(scope), string(original.Method), string(original.IdempotencyKey), string(original.RequestSHA256), receipt.RawRequest, operationData); err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replies VALUES(?,?,?,?)", principal(scope), string(original.Method), string(original.IdempotencyKey), receiptData); err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM reservations WHERE operation_id=?", string(operation.ID)); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return result, nil
}

func insertLaunchEffect(ctx context.Context, tx *sql.Tx, effect api.Effect) error {
	if err := validateEffect(effect); err != nil {
		return err
	}
	data, err := json.Marshal(effect)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO effects(id,operation_id,data) VALUES(?,?,?)", string(effect.ID), string(effect.OperationID), data); err != nil {
		return err
	}
	state, err := encodeEffectState(api.EffectRecord{Effect: effect, Generation: 1, State: api.EffectPending})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO effect_states VALUES(?,?)", string(effect.ID), state)
	return err
}

func (s *Service) launchInput(ctx context.Context, db queryer, scope api.Scope, ref api.BlobRef) error {
	metadata, _, err := objectRow(ctx, db, ref.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != ref || !objectVisible(scope, metadata.ACL) {
		return fault(api.CodeForbidden, "launch input differs from authorized committed bytes")
	}
	return nil
}

func (s *Service) reserveNewLife(ctx context.Context, tx *sql.Tx, scope api.Scope, start api.StartRequest, result *api.LaunchReservation) ([]api.TransactionGuard, error) {
	result.Level, result.Role, result.Driver = start.Level, start.Role, start.Driver
	if !wire.ValidID(start.Lane) || start.Level < 3 || start.Level > 6 || start.Role == "" ||
		start.ExpectedPolicyGeneration != result.PolicyGeneration || !positiveBudget(start.Budget) {
		return nil, fault(api.CodeConflict, "new launch level, policy or budget is invalid")
	}
	if err := s.launchInput(ctx, tx, scope, start.Task); err != nil {
		return nil, err
	}
	var claimed launchName
	err := storedProjection(ctx, tx, "launch_name", api.ID(start.Lane), &claimed)
	if err == nil {
		var prior api.Lane
		laneErr := storedProjection(ctx, tx, "lane", claimed.LifeID, &prior)
		released := laneErr == nil && prior.Cleaned
		if absent(laneErr) {
			var failed api.LaunchPlanRecord
			if err := storedProjection(ctx, tx, "launch_plan", claimed.ReservationID, &failed); err != nil {
				return nil, err
			}
			released = failed.Phase == "failed" && failed.Reservation.Target.LifeID == claimed.LifeID
		} else if laneErr != nil {
			return nil, laneErr
		}
		if !released {
			return nil, fault(api.CodeConflict, "lane name is already reserved")
		}
	} else if !absent(err) {
		return nil, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='lane' AND json_extract(data,'$.name')=? AND json_extract(data,'$.cleaned')=0", start.Lane).Scan(&count); err != nil {
		return nil, err
	}
	if count != 0 {
		return nil, fault(api.CodeConflict, "lane name is already live")
	}
	result.Target.LifeID, err = wire.NewID()
	if err != nil {
		return nil, err
	}
	result.GrantSetID, err = wire.NewID()
	if err != nil {
		return nil, err
	}
	result.Target.Run, result.Generation, result.CancellationEpoch = 1, 1, 1
	var ceiling api.GrantSet
	var guards []api.TransactionGuard
	switch scope.Actor.Kind {
	case "human":
		var ticket ticketRecord
		if err := storedProjection(ctx, tx, "ticket", start.RootTicketID, &ticket); err != nil {
			return nil, err
		}
		if err := storedProjection(ctx, tx, "grants", ticket.Ticket.GrantSetID, &ceiling); err != nil {
			return nil, err
		}
		guards = append(guards, api.TransactionGuard{Ticket: &api.TicketUse{TicketID: start.RootTicketID, PrincipalID: scope.Actor.ID, Config: scope.Config,
			EndpointGeneration: scope.EndpointGeneration, Level: start.Level, Role: start.Role, GrantSetID: ceiling.ID, Target: result.Target}})
		result.RootLifeID = result.Target.LifeID
	case "lane":
		if start.RootTicketID != "" || scope.Connection == nil {
			return nil, fault(api.CodeForbidden, "child launch requires the actual starter endpoint")
		}
		var parent api.Lane
		if err := storedProjection(ctx, tx, "lane", scope.Actor.LifeID, &parent); err != nil {
			return nil, err
		}
		if parent.Cleaned || parent.State != "running" || parent.Level != scope.Actor.Level || parent.Role != scope.Actor.Role || start.Level >= parent.Level || parent.PolicyGeneration != result.PolicyGeneration {
			return nil, fault(api.CodeForbidden, "child launch exceeds the current starter level or policy")
		}
		if err := storedProjection(ctx, tx, "grants", parent.GrantSetID, &ceiling); err != nil {
			return nil, err
		}
		if ceiling.LifeID != parent.LifeID {
			return nil, fault(api.CodeForbidden, "starter grants belong to another life")
		}
		event, err := starterEvent(ctx, tx, parent.LifeID)
		if err != nil {
			return nil, err
		}
		result.ParentLifeID, result.RootLifeID, result.StarterEventSeq = parent.LifeID, parent.RootLifeID, event.Seq
		result.StarterChain = append(append([]api.ID{}, parent.StarterChain...), parent.LifeID)
	default:
		return nil, fault(api.CodeForbidden, "new life requires a human ticket or authenticated starter")
	}
	if ceiling.Revoked || ceiling.PolicyGeneration != result.PolicyGeneration || !future(ceiling.ExpiresAt, s.deps.Clock.Now()) {
		return nil, fault(api.CodeForbidden, "launch grant ceiling is stale or revoked")
	}
	if err := s.launchCeiling(start.Grants, ceiling, scope.Actor.Kind == "lane"); err != nil {
		return nil, err
	}
	if err := put(ctx, tx, "launch_authority", result.ID, 1, launchAuthority{Ceiling: ceiling, TicketID: start.RootTicketID}); err != nil {
		return nil, err
	}
	return guards, nil
}

func starterEvent(ctx context.Context, db queryer, life api.ID) (api.Event, error) {
	var data []byte
	var event api.Event
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.kind') IN ('lane.created','lane.adopted') ORDER BY seq LIMIT 1", string(life)).Scan(&data); err != nil {
		return event, fault(api.CodeIntegrity, "starter has no authentic created or adopted event")
	}
	if err := wire.Decode(data, &event); err != nil {
		return event, err
	}
	var payload api.LaunchEvent
	if err := wire.Decode(event.Payload, &payload); err != nil {
		return event, err
	}
	if event.Origin != "service" || event.Actor.Kind != "service" || payload.Lane.LifeID != life || payload.LaunchID != payload.Lane.LaunchID {
		return event, fault(api.CodeIntegrity, "starter event is not an authoritative life edge")
	}
	return event, nil
}

func positiveBudget(b api.Budget) bool {
	return b.WallMS > 0 && b.CPUSeconds > 0 && b.MemoryBytes > 0 && b.Processes > 0 && b.DiskBytes > 0 && b.SpendMicros >= 0
}

func budgetWithin(b, ceiling api.Budget) bool {
	return positiveBudget(b) && b.WallMS <= ceiling.WallMS && b.CPUSeconds <= ceiling.CPUSeconds && b.MemoryBytes <= ceiling.MemoryBytes &&
		b.Processes <= ceiling.Processes && b.DiskBytes <= ceiling.DiskBytes && b.SpendMicros <= ceiling.SpendMicros && b.Currency == ceiling.Currency
}

func (s *Service) reserveRetainedLife(ctx context.Context, tx *sql.Tx, scope api.Scope, target api.LifeRef, generation api.Generation, budget api.Budget, result *api.LaunchReservation) error {
	var lane api.Lane
	if err := storedProjection(ctx, tx, "lane", target.LifeID, &lane); err != nil {
		return err
	}
	if lane.Cleaned || lane.Run != target.Run || lane.Generation != generation || lane.Generation >= 1<<53-1 || lane.Run >= 1<<53-1 ||
		lane.PolicyGeneration != result.PolicyGeneration || lane.State != "verifying" && lane.State != "idle" && lane.State != "profile_wait" || !budgetWithin(budget, lane.BudgetRemaining) {
		return fault(api.CodeConflict, "retained launch base, state, policy or remaining budget changed")
	}
	if scope.Actor.Kind == "lane" && (scope.Connection == nil || !slices.Contains(lane.StarterChain, scope.Actor.LifeID)) ||
		scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" && !internalScope(scope) {
		return fault(api.CodeForbidden, "retained launch caller is not an authentic controller")
	}
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.target.life_id')=? AND json_extract(data,'$.phase') NOT IN ('opened','failed')", string(lane.LifeID)).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return fault(api.CodeConflict, "life already has a reserved launch")
	}
	prior, err := s.launchBinding(ctx, tx, lane.LaunchID)
	if err != nil {
		return err
	}
	if prior.Recovery == nil || prior.Record.Target != target || prior.Recovery.Home.Home != prior.Recovery.Handoff.Spec.Runner.Home ||
		!samePrivateSession(lane.Session, prior.Recovery.Handoff.Spec.Runner.Session) || lane.Session.VendorID == "" || lane.Workspace.ID != prior.Recovery.Handoff.Spec.Workspace.ID || lane.Workspace.Branch != prior.Recovery.Handoff.Spec.Workspace.Branch || lane.Workspace.ProjectID != prior.Recovery.Handoff.Spec.Workspace.ProjectID || lane.Workspace.Base != prior.Recovery.Handoff.Spec.Workspace.Base || lane.Workspace.LogicalCWD != prior.Recovery.Handoff.Spec.Workspace.LogicalCWD {
		return fault(api.CodeIntegrity, "retained launch lost its private home, workspace or session binding")
	}
	var observed []byte
	if err := tx.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind')='lane.ended' ORDER BY seq DESC LIMIT 1", string(target.LifeID), uint64(target.Run)).Scan(&observed); err != nil {
		return fault(api.CodeContainmentUnknown, "prior run has no retained measured end")
	}
	var event api.Event
	if err := wire.Decode(observed, &event); err != nil {
		return err
	}
	var end api.RunEndEvent
	if err := wire.Decode(event.Payload, &end); err != nil {
		return err
	}
	if event.Origin != "service" || end.LaunchID != lane.LaunchID || end.Observation.State != "exited" || end.Observation.Survivors == nil || *end.Observation.Survivors != 0 ||
		end.Observation.Handle.Target != target || end.Observation.Handle.ContainmentID != prior.Record.ContainmentID || end.Observation.Handle.Generation != prior.Record.ProcessGeneration {
		return fault(api.CodeContainmentUnknown, "prior containment is not independently quiescent")
	}
	var measured struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	if err := storedProjection(ctx, tx, "launch_observation", lane.LaunchID, &measured); err != nil {
		return err
	}
	if !sameValue(measured.Observation, end.Observation) {
		return fault(api.CodeContainmentUnknown, "prior end differs from the retained independent helper observation")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, tx, "grants", lane.GrantSetID, &grants); err != nil {
		return err
	}
	if grants.LifeID != lane.LifeID || grants.Revoked || grants.PolicyGeneration > result.PolicyGeneration || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeForbidden, "retained life grants are stale or revoked")
	}
	if !sameValue(grants, prior.Recovery.Handoff.Spec.Grants) && !s.narrowedLaunchGrants(prior.Recovery.Handoff.Spec.Grants, grants) {
		return fault(api.CodeForbidden, "retained launch grants widened beyond its prior binding")
	}
	result.Target, result.BaseGeneration, result.Generation = api.LifeRef{LifeID: lane.LifeID, Run: lane.Run + 1}, lane.Generation, lane.Generation+1
	result.Level, result.Role, result.Driver = lane.Level, lane.Role, lane.Session.Driver
	result.CancellationEpoch, result.GrantSetID, result.PreviousLaunchID = lane.CancellationEpoch, lane.GrantSetID, lane.LaunchID
	result.ParentLifeID, result.RootLifeID, result.StarterChain, result.StarterEventSeq = lane.ParentLifeID, lane.RootLifeID, append([]api.ID{}, lane.StarterChain...), lane.StarterEventSeq
	if err := put(ctx, tx, "launch_authority", result.ID, 1, launchAuthority{Ceiling: grants}); err != nil {
		return err
	}
	return s.cancelContinuations(ctx, tx, lane, result.Mode == "continue")
}

func samePrivateSession(a, b api.Session) bool {
	a.VendorID, b.VendorID = "", ""
	return a == b
}

func (s *Service) cancelContinuations(ctx context.Context, tx *sql.Tx, lane api.Lane, continuing bool) error {
	rows, err := tx.QueryContext(ctx, "SELECT data FROM projections WHERE kind='continuation' AND json_extract(data,'$.Target.life_id')=?", string(lane.LifeID))
	if err != nil {
		return err
	}
	var intents []api.ContinuationIntent
	for rows.Next() {
		var data []byte
		var intent api.ContinuationIntent
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(data, &intent); err != nil {
			rows.Close()
			return err
		}
		intents = append(intents, intent)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, intent := range intents {
		if intent.Status == "cancelled" || intent.Status == "completed" {
			continue
		}
		if intent.CancellationEpoch != lane.CancellationEpoch {
			return fault(api.CodeConflict, "continuation cancellation fence changed")
		}
		if continuing {
			continue
		}
		intent.Status, intent.Generation = "cancelled", intent.Generation+1
		if err := put(ctx, tx, "continuation", intent.ID, intent.Generation, intent); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reserveContinuation(ctx context.Context, tx *sql.Tx, scope api.Scope, request api.LaunchReservationRequest, result *api.LaunchReservation) error {
	if !internalScope(scope) {
		return fault(api.CodeForbidden, "continuation requires its authentic internal requester")
	}
	var intent api.ContinuationIntent
	if err := storedProjection(ctx, tx, "continuation", request.ContinuationID, &intent); err != nil {
		return err
	}
	var lane api.Lane
	if err := storedProjection(ctx, tx, "lane", intent.Target.LifeID, &lane); err != nil {
		return err
	}
	if err := s.continuationFence(ctx, tx, lane, intent); err != nil {
		return err
	}
	swap, eligibility := intent.Swap, intent.Eligibility
	if intent.Status != "claimed" || intent.OperationID != request.OperationID || intent.Target.Run != lane.Run || intent.ExpectedGeneration != lane.Generation ||
		intent.CancellationEpoch != lane.CancellationEpoch || intent.LogicalTurnID != lane.LogicalTurnID || swap.ExpectedGeneration != lane.Generation ||
		swap.CancellationEpoch != lane.CancellationEpoch || swap.CausingRun != lane.Run || swap.ContinuationRun != lane.Run+1 || swap.LogicalTurnID != lane.LogicalTurnID ||
		swap.OperationID != request.OperationID || swap.EligibilityID != eligibility.ID || !eligibility.Compatible || !future(eligibility.ExpiresAt, s.deps.Clock.Now()) ||
		eligibility.Request.Target != intent.Target || eligibility.Request.Session != lane.Session || eligibility.Request.HistoryID != lane.Session.HistoryID ||
		eligibility.Request.GrantSetID != lane.GrantSetID || intent.Slot == nil || intent.Slot.ProfileGrantID != swap.ProfileGrantID || intent.Slot.ProfileID != swap.ToProfileID || !future(intent.Slot.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeConflict, "continuation claim, eligibility, slot or logical-turn fence changed")
	}
	if err := s.reserveRetainedLife(ctx, tx, scope, intent.Target, intent.ExpectedGeneration, lane.BudgetRemaining, result); err != nil {
		return err
	}
	intent.Status, intent.Generation = "completed", intent.Generation+1
	return put(ctx, tx, "continuation", intent.ID, intent.Generation, intent)
}
