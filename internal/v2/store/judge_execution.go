package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	clientwire "laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

var _ api.JudgeExecutionStore = (*Service)(nil)

func judgeExecutionPin(request api.JudgeRequest) (api.Digest, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	return api.Digest(hash(raw)), nil
}

func judgeExecutionID(scope api.Scope, id api.ID) api.ID {
	return api.ID(hash([]byte(scope.Config + ":" + principal(scope) + ":" + string(id))))
}

// ReserveJudgeExecution atomically retains the exact once-only egress effect,
// its fixed deadline, original operation and unknown-cost reservation. Observers
// never acquire it, including after a crash or the original claim's expiry.
func (s *Service) ReserveJudgeExecution(ctx context.Context, scope api.Scope, input api.JudgeExecutionRequest) (result api.JudgeExecution, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return result, err
	}
	r := input.Request
	if scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" || !wire.ValidID(input.AttemptID) || !wire.ValidID(r.ID) ||
		r.Context.Config != scope.Config || scope.Actor.Kind == "lane" && r.Context.Target.LifeID != scope.Actor.LifeID {
		return result, fault(api.CodeForbidden, "judge execution differs from its authenticated requester")
	}
	if scope.Request.Method != "judge.ask" && scope.Request.Method != "policy.evaluate" && scope.Request.Method != "guidance.select" {
		return result, fault(api.CodeForbidden, "judge execution has no admitted parent method")
	}
	receipt, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return result, err
	}
	if receipt.Actor != scope.Actor || receipt.Config != scope.Config || receipt.Reply != nil || receipt.Key != requestKey(scope.Request) {
		return result, fault(api.CodeConflict, "judge execution parent is foreign or completed")
	}
	pin, err := judgeExecutionPin(r)
	if err != nil {
		return result, err
	}
	id := judgeExecutionID(scope, r.ID)
	if err := storedProjection(ctx, s.db, "judge_execution", id, &result); err == nil {
		if result.Pin != pin || !sameValue(result.Request, r) || result.Intent.RequestedBy != scope.Actor || result.Intent.CauseOperationID != receipt.Operation.ID {
			return api.JudgeExecution{}, fault(api.CodeIdempotencyConflict, "judge execution ID has different exact inputs or cause")
		}
		result.Acquired = false
		return result, nil
	} else if !absent(err) {
		return result, err
	}
	var priorExecution api.ID
	if err := storedProjection(ctx, s.db, "judge_request_id", r.ID, &priorExecution); err == nil {
		return api.JudgeExecution{}, fault(api.CodeIdempotencyConflict, "judge correlation ID is already reserved by another execution")
	} else if !absent(err) {
		return result, err
	}
	if s.deps.JudgeMaxCostMicros <= 0 {
		return result, fault(api.CodePrerequisite, "installed approved judge inference ceiling is absent")
	}
	if r.MaxCostMicros <= 0 || r.MaxCostMicros > s.deps.JudgeMaxCostMicros || r.MaxCostMicros > 1<<53-1 {
		return result, fault(api.CodeBudget, "judge execution exceeds its approved inference ceiling")
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return result, err
	}
	if err := wire.ValidateConfig(r.Config); err != nil {
		return result, err
	}
	body, _, err := wire.Payload(r)
	if err != nil {
		return result, err
	}
	var decoded map[string]any
	if json.Unmarshal(body, &decoded) != nil || wire.RequestSensitive(decoded, "") {
		return result, fault(api.CodeUnscored, "judge execution withheld credential-shaped input")
	}
	now := s.deps.Clock.Now()
	deadline, err := time.Parse(time.RFC3339Nano, string(input.Deadline))
	limit := min(r.DeadlineMS, r.Config.CommandDeadlineMS)
	if r.Purpose == "guidance" {
		limit = min(r.DeadlineMS, r.Config.GuidanceDeadlineMS)
	}
	if err != nil || limit < 1 || !deadline.After(now) || deadline.After(now.Add(time.Duration(limit)*time.Millisecond)) {
		return result, fault(api.CodeDeadline, "judge execution deadline exceeds its original total budget")
	}
	claim, err := clientwire.NewID()
	if err != nil {
		return result, err
	}
	result = api.JudgeExecution{ID: id, Pin: pin, Request: r, ClaimID: claim, AttemptID: input.AttemptID,
		ReservedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano)), Deadline: input.Deadline, Outcome: "pending"}
	result.Intent = api.InternalIntent{ID: id, Kind: api.InternalJudgeEvaluate, Config: scope.Config,
		Actor: api.Actor{Kind: "service", ID: "lb-v2-judge"}, RequestedBy: scope.Actor,
		CauseOperationID: receipt.Operation.ID, CauseRequestID: scope.Request.RequestID, EffectID: id,
		Target: r.Context.Target, LogicalTurnID: r.Context.LogicalTurnID}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", r.Context.Target.LifeID, &lane); err != nil {
		return result, err
	}
	result.Intent.CancellationEpoch = lane.CancellationEpoch
	if err := s.judgeExecutionCurrent(ctx, s.db, result); err != nil {
		return result, err
	}
	var reserved int64
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce(sum(CASE WHEN json_extract(data,'$.UsageKnown') THEN json_extract(data,'$.Audit.Reply.cost_micros') ELSE json_extract(data,'$.Request.max_cost_micros') END),0)
 FROM projections WHERE kind='judge_execution' AND json_extract(data,'$.Intent.target.life_id')=?`, string(lane.LifeID)).Scan(&reserved); err != nil {
		return result, err
	}
	if reserved < 0 || reserved > lane.BudgetRemaining.SpendMicros || r.MaxCostMicros > lane.BudgetRemaining.SpendMicros-reserved {
		return result, fault(api.CodeBudget, "judge egress reservations exhaust the remaining life budget")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "judge_execution", id, 1, result); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "judge_request_id", r.ID, 1, id); err != nil {
		return result, err
	}
	if err := s.judgeEgress(ctx, tx, result, "sent", nil); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	result.Acquired = true
	s.notifyChanged()
	return result, nil
}

func (s *Service) judgeExecutionCurrent(ctx context.Context, db queryer, e api.JudgeExecution) error {
	r := e.Request
	var lane api.Lane
	var policy api.EffectivePolicy
	var grants api.GrantSet
	var turn api.TurnSnapshot
	if err := storedProjection(ctx, db, "lane", e.Intent.Target.LifeID, &lane); err != nil {
		return err
	}
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return err
	}
	if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
		return err
	}
	if err := storedProjection(ctx, db, "turn", e.Intent.LogicalTurnID, &turn); err != nil {
		return err
	}
	config, err := api.ResolveJudgeConfig(policy.Judge)
	if err != nil {
		return err
	}
	if lane.Cleaned || lane.Run != e.Intent.Target.Run || lane.LogicalTurnID != e.Intent.LogicalTurnID || lane.CancellationEpoch != e.Intent.CancellationEpoch ||
		lane.GrantSetID != r.Context.GrantSetID || lane.Level != r.Context.Role.Level || lane.Role != r.Context.Role.Role || lane.Workspace.LogicalCWD != r.Context.CWD ||
		policy.Generation != r.Context.PolicyGeneration || config != r.Config || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) || grants.SHA256 != r.Context.GrantsSHA256 ||
		turn.Target != e.Intent.Target || turn.LogicalTurnID != e.Intent.LogicalTurnID || turn.Task != lane.Task {
		return fault(api.CodeConflict, "judge execution life, policy, task or grants changed")
	}
	metadata, task, err := objectRow(ctx, db, turn.Task.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != turn.Task || !bytes.Equal(task, r.Task) {
		return fault(api.CodeIntegrity, "judge execution task differs from retained turn bytes")
	}
	return nil
}

func (s *Service) judgeExecutionClaim(ctx context.Context, db queryer, scope api.Scope, submitted api.JudgeExecution) (api.JudgeExecution, error) {
	var actual api.JudgeExecution
	if !submitted.Acquired || scope.Config != s.deps.Config || scope.Connection != nil || scope.Actor.Kind != "service" || scope.Actor != submitted.Intent.Actor || scope.Request.Method != "" {
		return actual, fault(api.CodeForbidden, "judge execution requires its bound internal worker")
	}
	if err := storedProjection(ctx, db, "judge_execution", submitted.ID, &actual); err != nil {
		return actual, err
	}
	pin, err := judgeExecutionPin(actual.Request)
	if err != nil {
		return actual, err
	}
	if pin != actual.Pin {
		return actual, fault(api.CodeIntegrity, "judge execution request differs from its stable byte pin")
	}
	input := submitted
	input.Acquired = false
	if !sameValue(input, actual) || actual.Outcome != "pending" || actual.Audit != nil || !future(actual.Deadline, s.deps.Clock.Now()) && ctx.Value(judgeRecoveryKey{}) != s {
		return actual, fault(api.CodeConflict, "judge execution claim is stale, foreign or already consumed")
	}
	if err := s.judgeExecutionCurrent(ctx, db, actual); err != nil {
		return actual, err
	}
	return actual, nil
}

func (s *Service) ValidateJudgeExecution(ctx context.Context, scope api.Scope, execution api.JudgeExecution) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return err
	}
	_, err := s.judgeExecutionClaim(ctx, s.db, scope, execution)
	return err
}

func (s *Service) CompleteJudgeExecution(ctx context.Context, scope api.Scope, execution api.JudgeExecution, audit api.JudgeAudit) (api.JudgeAudit, error) {
	scope.ReadView = nil
	if stored, replayed, err := s.judgeCompletionReplay(ctx, scope, execution, audit); err != nil || replayed {
		return stored, err
	}
	if err := s.ValidateJudgeExecution(ctx, scope, execution); err != nil {
		return api.JudgeAudit{}, err
	}
	payload, err := json.Marshal(audit.Reply)
	if err != nil {
		return api.JudgeAudit{}, err
	}
	lane, err := s.Lane(ctx, scope, execution.Intent.Target)
	if err != nil {
		return api.JudgeAudit{}, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: execution.ID, Config: scope.Config, Kind: "judge.completed", Actor: scope.Actor,
		RequestedBy: execution.Intent.RequestedBy, LifeID: lane.LifeID, Run: lane.Run, LogicalTurnID: lane.LogicalTurnID,
		ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq,
		Origin: "service", RequestedAt: audit.StartedAt, ObservedAt: audit.CompletedAt, Payload: payload}
	_, err = s.Transact(ctx, api.Transaction{Scope: scope, Internal: &execution.Intent, Writes: api.StateWrites{JudgeAudits: []api.JudgeAudit{audit}},
		Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}}})
	if err != nil {
		return api.JudgeAudit{}, err
	}
	return s.JudgeAudit(ctx, scope, audit.ID)
}

func (s *Service) judgeCompletionReplay(ctx context.Context, scope api.Scope, execution api.JudgeExecution, audit api.JudgeAudit) (api.JudgeAudit, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.JudgeAudit{}, false, err
	}
	if scope.Config != s.deps.Config || scope.Actor != execution.Intent.Actor || scope.Connection != nil || scope.Actor.Kind != "service" || scope.Request.Method != "" {
		return api.JudgeAudit{}, false, fault(api.CodeForbidden, "judge completion replay requires its original internal worker")
	}
	var actual api.JudgeExecution
	if err := storedProjection(ctx, s.db, "judge_execution", execution.ID, &actual); err != nil {
		return api.JudgeAudit{}, false, err
	}
	if actual.Outcome != "completed" {
		return api.JudgeAudit{}, false, nil
	}
	original := actual
	original.Acquired, original.Audit, original.Outcome, original.UsageKnown = false, nil, "pending", false
	submitted := execution
	submitted.Acquired = false
	if !sameValue(original, submitted) || actual.Audit == nil || !sameValue(*actual.Audit, audit) {
		return api.JudgeAudit{}, false, fault(api.CodeIdempotencyConflict, "judge completion replay changed its original claim or measured audit")
	}
	var lane api.Lane
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "lane", actual.Intent.Target.LifeID, &lane); err != nil {
		return api.JudgeAudit{}, false, err
	}
	if err := storedProjection(ctx, s.db, "grants", lane.GrantSetID, &grants); err != nil {
		return api.JudgeAudit{}, false, err
	}
	if lane.Cleaned || lane.CancellationEpoch != actual.Intent.CancellationEpoch || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return api.JudgeAudit{}, false, fault(api.CodeForbidden, "judge completion replay authority was revoked or collected")
	}
	var retained api.JudgeAudit
	if err := storedProjection(ctx, s.db, "judge_audit", audit.ID, &retained); err != nil {
		return api.JudgeAudit{}, false, err
	}
	if !sameValue(retained, audit) {
		return api.JudgeAudit{}, false, fault(api.CodeIntegrity, "judge completion replay differs from its committed projection")
	}
	return retained, true, nil
}

func (s *Service) writeJudgeAudit(ctx context.Context, tx *sql.Tx, input api.Transaction, audit api.JudgeAudit) error {
	if input.Internal == nil || input.Internal.Kind != api.InternalJudgeEvaluate || len(input.Writes.JudgeAudits) != 1 || len(input.Events) != 1 {
		return fault(api.CodeForbidden, "judge audit requires one claimed execution and matching event")
	}
	var execution api.JudgeExecution
	if err := storedProjection(ctx, tx, "judge_execution", input.Internal.EffectID, &execution); err != nil {
		return err
	}
	if !sameValue(execution.Intent, *input.Internal) {
		return fault(api.CodeForbidden, "judge audit changed its retained execution cause")
	}
	execution.Acquired = true
	if _, err := s.judgeExecutionClaim(ctx, tx, input.Scope, execution); err != nil {
		return err
	}
	request := execution.Request
	if audit.ID != request.ID || audit.Reply.ID != request.ID || audit.Reply.Request == nil || *audit.Reply.Request != audit.Request {
		return fault(api.CodeIntegrity, "judge audit receipt differs from retained execution")
	}
	metadata, body, err := objectRow(ctx, tx, audit.Request.ID)
	if err != nil {
		return err
	}
	expected, _, err := wire.Payload(request)
	if err != nil {
		return err
	}
	if metadata.Ref != audit.Request || metadata.SourceOperationID != execution.Intent.CauseOperationID || metadata.ACL.LifeID != execution.Intent.Target.LifeID || !bytes.Equal(body, expected) {
		return fault(api.CodeIntegrity, "judge audit request bytes or causal retention differ")
	}
	var raw []byte
	if audit.Reply.Raw != nil {
		metadata, raw, err = objectRow(ctx, tx, audit.Reply.Raw.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != *audit.Reply.Raw || metadata.SourceOperationID != execution.Intent.CauseOperationID || metadata.ACL.LifeID != execution.Intent.Target.LifeID {
			return fault(api.CodeIntegrity, "judge audit response bytes or retention differ")
		}
	}
	if err := wire.AuditReply(audit.Reply, request, audit.Fit, raw); err != nil {
		return err
	}
	started, err := time.Parse(time.RFC3339Nano, string(audit.StartedAt))
	completed, endErr := time.Parse(time.RFC3339Nano, string(audit.CompletedAt))
	reserved, _ := time.Parse(time.RFC3339Nano, string(execution.ReservedAt))
	deadline, _ := time.Parse(time.RFC3339Nano, string(execution.Deadline))
	if err != nil || endErr != nil || started.Before(reserved) || completed.Before(started) || completed.After(deadline) || completed.After(s.deps.Clock.Now()) {
		return fault(api.CodeIntegrity, "judge audit times exceed the original claim")
	}
	inputTokens, outputTokens, known := wire.MeasuredUsage(raw, request)
	if known {
		if s.deps.JudgeCost == nil {
			return fault(api.CodePrerequisite, "judge audit has no approved measured price")
		}
		cost, err := s.deps.JudgeCost(request.Config, inputTokens, outputTokens)
		if err != nil {
			return err
		}
		if cost != audit.Reply.CostMicros || cost < 0 || cost > request.MaxCostMicros {
			return fault(api.CodeIntegrity, "judge audit cost differs from measured usage and approved price")
		}
	}
	if audit.Reply.Status == "scored" && !known {
		return fault(api.CodeIntegrity, "scored judge audit has unknown usage")
	}
	if input.Events[0].Kind != "judge.completed" || !sameValue(input.Events[0].Payload, audit.Reply) {
		return fault(api.CodeIntegrity, "judge completion event differs from its measured audit")
	}
	execution.Acquired, execution.Outcome, execution.Audit, execution.UsageKnown = false, "completed", &audit, known
	if err := s.judgeEgress(ctx, tx, execution, "outcome", &audit.Reply); err != nil {
		return err
	}
	if err := put(ctx, tx, "judge_execution", execution.ID, 2, execution); err != nil {
		return err
	}
	return putGenerated(ctx, tx, "judge_audit", audit.ID, 1, audit)
}
