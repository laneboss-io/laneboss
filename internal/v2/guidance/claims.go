package guidance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) lookupClaim(ctx context.Context, scope api.Scope, request api.GuidanceRequest) (api.GuidanceReservation, bool, error) {
	r, err := s.deps.Store.GuidanceReservation(ctx, scope, request.Target, request.LogicalTurnID)
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
		return api.GuidanceReservation{}, false, nil
	}
	return r, err == nil, err
}

func (s *Service) checkClaim(ctx context.Context, scope api.Scope, request api.GuidanceRequest, turn api.TurnSnapshot, policy api.EffectivePolicy, r api.GuidanceReservation) error {
	if r.Config != scope.Config || r.Target.LifeID != request.Target.LifeID || r.Target.Run > request.Target.Run ||
		r.LogicalTurnID != request.LogicalTurnID || r.Task != request.Task || r.PolicyGeneration != turn.PolicyGeneration || r.TurnGeneration > turn.Generation {
		return integrity("guidance reservation does not match the retained turn input")
	}
	if r.Result != nil {
		if _, err := validateCompletedSelection(r, request, turn.PolicyGeneration); err != nil {
			return err
		}
	}
	if err := api.ValidateGuidanceReservation(r); err != nil {
		return err
	}
	if r.BindingItems == nil {
		return integrity("guidance claim omitted its complete binding snapshot")
	}
	generation, err := api.PolicyGenerationFor(api.PolicyRetainedSelection, policy.Generation, r.PolicyGeneration)
	if err != nil {
		return err
	}
	history, err := s.deps.Store.PolicyAt(ctx, scope, generation)
	if err != nil {
		return err
	}
	if history.Generation != generation || !validDigest(history.SHA256) {
		return integrity("retained guidance policy is not an approved immutable snapshot")
	}
	return nil
}

func (s *Service) observeClaim(ctx context.Context, scope api.Scope, request api.GuidanceRequest, lane api.Lane, turn api.TurnSnapshot, policy api.EffectivePolicy, r api.GuidanceReservation) (api.Guidance, error) {
	if err := s.checkClaim(ctx, scope, request, turn, policy, r); err != nil {
		return api.Guidance{}, err
	}
	if r.Status == "pending" {
		deadline, _ := time.Parse(time.RFC3339Nano, string(r.Deadline))
		if !s.deps.Clock.Now().Before(deadline) {
			return s.recoverClaim(ctx, scope, request, lane, turn, r)
		}
		awaited, err := s.deps.Store.AwaitGuidance(ctx, scope, api.GuidanceAwaitRequest{ReservationID: r.ID, Deadline: r.Deadline})
		if err != nil {
			var typed *api.Error
			if errors.As(err, &typed) && typed.Code == api.CodeDeadline && ctx.Err() == nil && !s.deps.Clock.Now().Before(deadline) {
				latest, found, readErr := s.lookupClaim(ctx, scope, request)
				if readErr != nil {
					return api.Guidance{}, readErr
				}
				if !found || !sameClaim(r, latest) {
					return api.Guidance{}, integrity("expired guidance await lost its original claim")
				}
				if latest.Status == "completed" {
					return s.observeClaim(ctx, scope, request, lane, turn, policy, latest)
				}
				return s.recoverClaim(ctx, scope, request, lane, turn, latest)
			}
			return api.Guidance{}, err
		}
		if awaited.Acquired || awaited.Status != "completed" || !sameClaim(r, awaited) {
			return api.Guidance{}, integrity("guidance await changed its retained claim or evaluation rights")
		}
		if err := s.checkClaim(ctx, scope, request, turn, policy, awaited); err != nil {
			return api.Guidance{}, err
		}
		r = awaited
	}
	result, err := validateCompletedSelection(r, request, turn.PolicyGeneration)
	if err != nil {
		return api.Guidance{}, err
	}
	return s.sealReplay(ctx, scope, request.Target, *result)
}

func sameClaim(first, second api.GuidanceReservation) bool {
	first.Acquired, second.Acquired = false, false
	first.Generation, second.Generation = 0, 0
	first.Status, second.Status = "", ""
	first.Result, second.Result = nil, nil
	return reflect.DeepEqual(first, second)
}

func (s *Service) selectFresh(ctx context.Context, scope api.Scope, request api.GuidanceRequest, lane api.Lane, turn api.TurnSnapshot, policy api.EffectivePolicy, entered time.Time) (api.Guidance, error) {
	if turn.Generation >= maxInteger {
		return api.Guidance{}, integrity("guidance turn revision cannot advance")
	}
	generation, err := api.PolicyGenerationFor(api.PolicyNewSelection, policy.Generation, 0)
	if err != nil {
		return api.Guidance{}, err
	}
	if lane.PolicyGeneration != generation {
		advance := api.PolicyAdvanceRequest{Target: request.Target, ExpectedLaneGeneration: lane.Generation,
			FromGeneration: lane.PolicyGeneration, ToGeneration: generation, CancellationEpoch: lane.CancellationEpoch}
		receipt, err := s.deps.Store.RefreshLanePolicy(ctx, scope, advance)
		if err != nil {
			return api.Guidance{}, err
		}
		if err := api.ValidatePolicyAdvance(lane, advance, policy, receipt); err != nil {
			return api.Guidance{}, err
		}
		lane = receipt.Lane
	}
	if lane.BudgetRemaining.SpendMicros <= 0 || lane.BudgetRemaining.SpendMicros > maxInteger {
		return api.Guidance{}, &api.Error{Code: api.CodeBudget, Owner: "lb-v2-guidance", Message: "guidance requires a positive authoritative remaining budget", Instead: "Resolve the actual remaining life budget before selecting guidance."}
	}
	candidates, snapshot, err := s.candidateSnapshot(ctx, scope, request.Target, generation)
	if err != nil {
		return api.Guidance{}, err
	}
	task, err := s.taskBytes(ctx, scope, turn.Task)
	if err != nil {
		return api.Guidance{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return api.Guidance{}, err
	}
	budget := 5 * time.Second
	if policy.Judge.GuidanceDeadlineMS > 0 && policy.Judge.GuidanceDeadlineMS < 5000 {
		budget = time.Duration(policy.Judge.GuidanceDeadlineMS) * time.Millisecond
	}
	costLimit := lane.BudgetRemaining.SpendMicros
	if s.deps.MaxCostMicros > 0 {
		costLimit = min(costLimit, s.deps.MaxCostMicros)
	}
	claim := api.GuidanceReservationRequest{AttemptID: api.ID(hex.EncodeToString(nonce[:])), Target: request.Target,
		LogicalTurnID: request.LogicalTurnID, ExpectedTask: turn.Task, ExpectedTurnGeneration: turn.Generation,
		PolicyGeneration: generation, CandidateSnapshotID: snapshot, CancellationEpoch: lane.CancellationEpoch,
		MaxCostMicros: costLimit, Deadline: api.Timestamp(entered.UTC().Add(budget).Format(time.RFC3339Nano))}
	if err := contextError(ctx); err != nil {
		return api.Guidance{}, err
	}
	reservation, err := s.deps.Store.ReserveGuidance(ctx, scope, claim)
	if err != nil {
		return api.Guidance{}, err
	}
	if !reservation.Acquired {
		// Even the same attempt/key is only an observer on a repeated call.
		turn.PolicyGeneration = reservation.PolicyGeneration
		return s.observeClaim(ctx, scope, request, lane, turn, policy, reservation)
	}
	if reservation.Deadline != claim.Deadline || !claimBindings(candidates, reservation.BindingItems) {
		return api.Guidance{}, integrity("guidance winning claim changed its deadline or binding snapshot")
	}
	if !api.GuidanceCanEvaluate(claim, reservation, s.deps.Clock.Now()) {
		reserved, _ := time.Parse(time.RFC3339Nano, string(reservation.ReservedAt))
		deadline, _ := time.Parse(time.RFC3339Nano, string(reservation.Deadline))
		if api.GuidanceCanEvaluate(claim, reservation, reserved) && !s.deps.Clock.Now().Before(deadline) {
			turn.PolicyGeneration = reservation.PolicyGeneration
			return s.recoverClaim(ctx, scope, request, lane, turn, reservation)
		}
		return api.Guidance{}, integrity("guidance reserve did not return this invocation's atomic winning claim")
	}
	if reservation.Config != scope.Config || reservation.RequestedBy != scope.Actor ||
		scope.Request.Method == "guidance.select" && (reservation.OwnerRequestID != scope.Request.RequestID || reservation.OwnerKey != requestKey(scope)) {
		return api.Guidance{}, integrity("guidance winning claim differs from its authenticated requester")
	}
	turn.PolicyGeneration = reservation.PolicyGeneration
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return api.Guidance{}, err
	}
	if grants.ID != lane.GrantSetID || grants.LifeID != lane.LifeID || grants.Revoked || !validDigest(grants.SHA256) {
		return api.Guidance{}, forbidden("guidance judge grants differ from the current life")
	}
	deadline, _ := time.Parse(time.RFC3339Nano, string(reservation.Deadline))
	remaining := deadline.Sub(s.deps.Clock.Now())
	evaluation, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	judgeRequest := api.JudgeRequest{ID: claim.AttemptID, Purpose: "guidance", Rules: []api.JudgeRule{}, Decisions: candidates, Task: task,
		Config: policy.Judge, MaxCostMicros: reservation.MaxCostMicros,
		Context: api.JudgeContext{Config: scope.Config, Target: reservation.Target, LogicalTurnID: reservation.LogicalTurnID,
			Role: policy.Context, PolicyGeneration: reservation.PolicyGeneration, GrantSetID: grants.ID, GrantsSHA256: grants.SHA256, CWD: lane.Workspace.LogicalCWD}}
	scope.PolicyGeneration = reservation.PolicyGeneration
	asOf, _ := time.Parse(time.RFC3339Nano, string(reservation.ReservedAt))
	result, err := s.evaluateBatchesAt(evaluation, scope, judgeRequest, policy, asOf)
	if err != nil {
		// Interruption leaves the original durable claim for post-deadline
		// reconciliation. It never acquires another attempt or judges again.
		return api.Guidance{}, err
	}
	if !s.deps.Clock.Now().Before(deadline) {
		return s.recoverClaim(ctx, scope, request, lane, turn, reservation)
	}
	return s.completeClaim(ctx, scope, request, turn, reservation, result, api.InternalGuidanceComplete)
}

func requestKey(scope api.Scope) api.RequestKey {
	return api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
}

func claimBindings(candidates []api.DecisionCandidate, items []api.GuidanceItem) bool {
	if items == nil {
		return false
	}
	bindings := make(map[api.ID]api.SourceRef)
	for _, item := range candidates {
		if item.Binding {
			bindings[item.ID] = item.Source
		}
	}
	if len(bindings) != len(items) {
		return false
	}
	for _, item := range items {
		source, exists := bindings[item.DecisionID]
		if !exists || !item.Binding || source != item.Source {
			return false
		}
		delete(bindings, item.DecisionID)
	}
	return len(bindings) == 0
}

// RecoverGuidance is a private scheduler entry, not an RPC. The caller supplies
// a currently authorized scope; stored owner facts supply the original cause.
// The scheduler invokes it after the fixed deadline, with its own I/O context.
func (s *Service) RecoverGuidance(ctx context.Context, scope api.Scope, request api.GuidanceRequest) (api.Guidance, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := contextError(ctx); err != nil {
		return api.Guidance{}, err
	}
	if err := validateRequest(request); err != nil {
		return api.Guidance{}, err
	}
	var err error
	scope, err = authorizeTarget(ctx, scope, request.Target)
	if err != nil {
		return api.Guidance{}, err
	}
	lane, err := s.deps.Store.Lane(ctx, scope, request.Target)
	if err != nil {
		return api.Guidance{}, err
	}
	if lane.Cleaned || lane.LifeID != request.Target.LifeID || lane.Run != request.Target.Run || lane.LogicalTurnID != request.LogicalTurnID {
		return api.Guidance{}, forbidden("guidance recovery target is no longer current")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.Guidance{}, err
	}
	if policy.Generation == 0 || scope.PolicyGeneration != 0 && scope.PolicyGeneration != policy.Generation {
		return api.Guidance{}, integrity("current policy differs from the authorization scope")
	}
	turn, err := s.deps.Store.Turn(ctx, scope, request.Target, request.LogicalTurnID)
	if err != nil {
		return api.Guidance{}, err
	}
	if turn.Target.LifeID != request.Target.LifeID || turn.Target.Run == 0 || turn.Target.Run > request.Target.Run ||
		turn.LogicalTurnID != request.LogicalTurnID || turn.Task != request.Task || turn.Generation == 0 {
		return api.Guidance{}, integrity("guidance recovery turn differs from its retained input")
	}
	r, found, err := s.lookupClaim(ctx, scope, request)
	if err != nil {
		return api.Guidance{}, err
	}
	if !found {
		return api.Guidance{}, &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-guidance", Message: "guidance recovery has no retained claim"}
	}
	if err := s.checkClaim(ctx, scope, request, turn, policy, r); err != nil {
		return api.Guidance{}, err
	}
	if r.Status == "completed" {
		return s.observeClaim(ctx, scope, request, lane, turn, policy, r)
	}
	return s.recoverClaim(ctx, scope, request, lane, turn, r)
}

func (s *Service) recoverClaim(ctx context.Context, scope api.Scope, request api.GuidanceRequest, lane api.Lane, turn api.TurnSnapshot, r api.GuidanceReservation) (api.Guidance, error) {
	deadline, err := time.Parse(time.RFC3339Nano, string(r.Deadline))
	if err != nil || s.deps.Clock.Now().Before(deadline) {
		return api.Guidance{}, integrity("guidance recovery cannot precede the retained deadline")
	}
	if lane.CancellationEpoch != r.CancellationEpoch {
		return api.Guidance{}, forbidden("guidance recovery cannot revive a cancelled claim")
	}
	result := api.Guidance{Status: "unavailable", Items: append([]api.GuidanceItem{}, r.BindingItems...), JudgmentIDs: []api.ID{},
		AsOf: r.ReservedAt, Notice: "Historical guidance unavailable: the original evaluator was interrupted or expired. Binding context is retained."}
	return s.completeClaim(ctx, scope, request, turn, r, result, api.InternalGuidanceRecover)
}

func (s *Service) completeClaim(ctx context.Context, scope api.Scope, request api.GuidanceRequest, turn api.TurnSnapshot, r api.GuidanceReservation, result api.Guidance, kind api.InternalKind) (api.Guidance, error) {
	if turn.Generation >= maxInteger {
		return api.Guidance{}, integrity("guidance turn revision cannot advance")
	}
	result.ID = api.ID(string(digestBytes([]byte(string(r.ID) + ":" + string(r.ClaimID))))[:32])
	result.Target, result.Task, result.LogicalTurnID = r.Target, r.Task, r.LogicalTurnID
	result.PolicyGeneration, result.CandidateSnapshotID, result.ReservationID = r.PolicyGeneration, r.CandidateSnapshotID, r.ID
	if kind == api.InternalGuidanceComplete {
		items := append([]api.GuidanceItem{}, r.BindingItems...)
		for _, item := range result.Items {
			if !item.Binding {
				items = append(items, item)
			}
		}
		result.Items = items
	}
	selection := api.GuidanceSelection{AttemptID: r.OwnerAttemptID, ReservationID: r.ID, ClaimID: r.ClaimID, ExpectedGeneration: r.Generation, Result: result}
	cause := api.InternalIntent{ID: api.ID(string(digestBytes([]byte(string(r.ClaimID) + ":" + string(kind))))[:32]), Kind: kind,
		Config: r.Config, Actor: api.Actor{Kind: "service", ID: "guidance"}, RequestedBy: r.RequestedBy,
		CauseOperationID: r.OwnerOperationID, CauseRequestID: r.OwnerRequestID, Target: r.Target, LogicalTurnID: r.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	if r.LaunchReservationID != "" {
		cause.Actor, cause.EffectID = scope.Actor, r.LaunchEffectID
	}
	if err := api.ValidateGuidanceCompletion(r, selection, cause, s.deps.Clock.Now()); err != nil {
		return api.Guidance{}, err
	}
	// Validate the full receipt before any durable write, including its IDs,
	// scores, clocks and immutable reservation pins.
	done := r
	done.Status, done.Generation, done.Acquired, done.Result = "completed", 2, false, &result
	if _, err := validateCompletedSelection(done, request, r.PolicyGeneration); err != nil {
		return api.Guidance{}, err
	}
	turn.GuidanceID, turn.PolicyGeneration = result.ID, r.PolicyGeneration
	turn.Generation++
	payload, err := json.Marshal(result)
	if err != nil {
		return api.Guidance{}, err
	}
	internalScope := scope
	internalScope.Request = api.Request{}
	tx := api.Transaction{Scope: internalScope, Internal: &cause, Writes: api.StateWrites{Guidance: []api.GuidanceSelection{selection}, Turns: []api.TurnSnapshot{turn}},
		Compare: []api.Compare{{Kind: api.CompareGuidance, ID: r.ID, Generation: r.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}},
		Events: []api.Event{{Schema: api.SchemaVersion, ID: api.ID(string(digestBytes([]byte(string(r.ClaimID) + ":selected-event")))[:32]), Kind: "guidance.selected", Config: r.Config, Origin: "service", LifeID: r.Target.LifeID, Run: r.Target.Run,
			LogicalTurnID: r.LogicalTurnID, Actor: cause.Actor, RequestedBy: r.RequestedBy, OperationID: r.OwnerOperationID, RequestID: r.OwnerRequestID, Payload: payload}}}
	if r.LaunchReservationID != "" {
		plan, err := s.deps.Store.LaunchPlan(ctx, scope, r.LaunchReservationID)
		if err != nil {
			return api.Guidance{}, err
		}
		if plan.Reservation.Target != r.Target || plan.Reservation.OperationID != r.OwnerOperationID || plan.Reservation.RequestedBy != r.RequestedBy {
			return api.Guidance{}, integrity("guidance event lineage differs from its original launch")
		}
		tx.Events[0].RootLifeID, tx.Events[0].ParentLifeID = plan.Reservation.RootLifeID, plan.Reservation.ParentLifeID
		tx.Events[0].StarterChain, tx.Events[0].StarterEventSeq = append([]api.ID{}, plan.Reservation.StarterChain...), plan.Reservation.StarterEventSeq
	}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Guidance{}, err
	}
	commit, err := s.deps.Store.Transact(ctx, tx)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeConflict {
			latest, found, readErr := s.lookupClaim(ctx, scope, request)
			if readErr != nil {
				return api.Guidance{}, readErr
			}
			if found && latest.Status == "completed" && !latest.Acquired && sameClaim(r, latest) {
				if validation := api.ValidateGuidanceReservation(latest); validation != nil {
					return api.Guidance{}, validation
				}
				retained, validation := validateCompletedSelection(latest, request, r.PolicyGeneration)
				if validation != nil {
					return api.Guidance{}, validation
				}
				if r.LaunchReservationID != "" {
					return *retained, nil
				}
				return s.sealReplay(ctx, scope, request.Target, *retained)
			}
		}
		return api.Guidance{}, err
	}
	if commit.Operation.Error != nil {
		return api.Guidance{}, commit.Operation.Error
	}
	if r.LaunchReservationID == "" {
		if commit.Operation.Status != "succeeded" {
			return api.Guidance{}, integrity("guidance completion has no successful durable commit")
		}
	} else {
		// This transaction commits a guidance selection inside the still
		// pending launch operation. Verify its exact durable event receipt;
		// finishing guidance must not mark the entire launch succeeded.
		if commit.Operation.ID != r.OwnerOperationID || commit.Operation.Status != "pending" && commit.Operation.Status != "running" ||
			commit.FirstSeq == 0 || commit.LastSeq != commit.FirstSeq || commit.Operation.LastSeq < commit.LastSeq {
			return api.Guidance{}, integrity("launch guidance completion has no exact durable event commit")
		}
		page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{LifeID: r.Target.LifeID, Run: r.Target.Run, Since: commit.FirstSeq - 1})
		if err != nil {
			return api.Guidance{}, err
		}
		if len(page.Events) == 0 {
			return api.Guidance{}, integrity("launch guidance completion event is absent")
		}
		event := page.Events[0]
		var selected api.Guidance
		if event.Seq != commit.FirstSeq || event.ID != tx.Events[0].ID || event.Kind != "guidance.selected" ||
			event.OperationID != r.OwnerOperationID || event.RequestID != r.OwnerRequestID || event.RequestedBy != r.RequestedBy ||
			api.DecodeObject(event.Payload, &selected) != nil || !reflect.DeepEqual(selected, result) {
			return api.Guidance{}, integrity("launch guidance completion event differs from its committed selection")
		}
	}
	retained, err := s.completedSelection(ctx, scope, request, r.PolicyGeneration)
	if err != nil {
		return api.Guidance{}, err
	}
	if retained == nil || !reflect.DeepEqual(*retained, result) {
		return api.Guidance{}, integrity("guidance completion read-back differs from the committed receipt")
	}
	if r.LaunchReservationID != "" {
		return *retained, nil
	}
	return s.sealReplay(ctx, scope, request.Target, *retained)
}
