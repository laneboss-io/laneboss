package store

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

func (s *Service) verifyGuidanceJudgments(ctx context.Context, tx *sql.Tx, claim api.GuidanceReservation, result api.Guidance) error {
	invalid := func(message string) error { return fault(api.CodeIntegrity, message) }
	if len(result.JudgmentIDs) == 0 || result.AsOf != claim.ReservedAt || result.Status != "scored" && result.Status != "unavailable" {
		return invalid("guidance score lacks its retained judgment batches or selection time")
	}
	if result.JudgmentID != "" && (len(result.JudgmentIDs) != 1 || result.JudgmentID != result.JudgmentIDs[0]) {
		return invalid("guidance aggregate is not its actual retained batch")
	}
	policy, err := s.policyAt(ctx, tx, claim.PolicyGeneration)
	if err != nil {
		return err
	}
	config, err := api.ResolveJudgeConfig(policy.Judge)
	if err != nil {
		return err
	}
	var snapshot decisionSnapshot
	if err := storedProjection(ctx, tx, "decision_snapshot", claim.CandidateSnapshotID, &snapshot); err != nil {
		return err
	}
	if snapshot.Target != claim.Target || snapshot.Policy != claim.PolicyGeneration {
		return invalid("guidance candidate snapshot differs from its original turn claim")
	}
	candidates := make(map[api.ID]api.DecisionCandidate, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if !candidate.Binding {
			candidates[candidate.ID] = candidate
		}
	}
	seen := map[api.ID]bool{}
	covered := map[api.ID]bool{}
	answers := []api.Judgment{}
	remaining := claim.MaxCostMicros
	for _, id := range result.JudgmentIDs {
		if seen[id] {
			return invalid("guidance reused a judgment batch")
		}
		seen[id] = true
		var audit api.JudgeAudit
		if err := storedProjection(ctx, tx, "judge_audit", id, &audit); err != nil {
			return err
		}
		var execution api.JudgeExecution
		key := judgeExecutionID(api.Scope{Config: claim.Config, Actor: claim.RequestedBy}, id)
		if err := storedProjection(ctx, tx, "judge_execution", key, &execution); err != nil {
			return err
		}
		r := execution.Request
		pin, err := judgeExecutionPin(r)
		if err != nil {
			return err
		}
		if execution.Pin != pin || execution.Outcome != "completed" || execution.Audit == nil || !sameValue(*execution.Audit, audit) ||
			execution.Intent.RequestedBy != claim.RequestedBy || execution.Intent.CauseOperationID != claim.OwnerOperationID || execution.Intent.CauseRequestID != claim.OwnerRequestID ||
			execution.Intent.Target != claim.Target || execution.Intent.LogicalTurnID != claim.LogicalTurnID || execution.Intent.CancellationEpoch != claim.CancellationEpoch ||
			r.Purpose != "guidance" || r.Config != config || r.Context.PolicyGeneration != claim.PolicyGeneration || r.Context.Target != claim.Target || r.Context.LogicalTurnID != claim.LogicalTurnID ||
			r.MaxCostMicros > remaining || r.MaxCostMicros <= 0 || audit.Reply.CostMicros < 0 || audit.Reply.CostMicros > r.MaxCostMicros {
			return invalid("guidance judgment belongs to a foreign input, turn, owner or total budget")
		}
		start, startErr := time.Parse(time.RFC3339Nano, string(execution.ReservedAt))
		reserved, _ := time.Parse(time.RFC3339Nano, string(claim.ReservedAt))
		deadline, deadlineErr := time.Parse(time.RFC3339Nano, string(execution.Deadline))
		end, _ := time.Parse(time.RFC3339Nano, string(claim.Deadline))
		if startErr != nil || deadlineErr != nil || start.Before(reserved) || deadline.After(end) {
			return invalid("guidance batch reset its original total deadline")
		}
		metadata, task, err := objectRow(ctx, tx, claim.Task.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != claim.Task || !bytes.Equal(task, r.Task) {
			return invalid("guidance batch used a different retained task")
		}
		metadata, requestBytes, err := objectRow(ctx, tx, audit.Request.ID)
		if err != nil {
			return err
		}
		expected, _, err := wire.Payload(r)
		if err != nil {
			return err
		}
		if metadata.Ref != audit.Request || !bytes.Equal(requestBytes, expected) {
			return invalid("guidance audit did not retain its complete batch input")
		}
		var raw []byte
		if audit.Reply.Raw != nil {
			metadata, raw, err = objectRow(ctx, tx, audit.Reply.Raw.ID)
			if err != nil {
				return err
			}
			if metadata.Ref != *audit.Reply.Raw {
				return invalid("guidance batch response differs from its measured audit")
			}
		}
		if err := wire.AuditReply(audit.Reply, r, audit.Fit, raw); err != nil {
			return err
		}
		for _, candidate := range r.Decisions {
			actual, ok := candidates[candidate.ID]
			if !ok || covered[candidate.ID] || !reflect.DeepEqual(actual, candidate) {
				return invalid("guidance batch changed, duplicated or invented a candidate")
			}
			covered[candidate.ID] = true
		}
		remaining -= audit.Reply.CostMicros
		answers = append(answers, audit.Reply.Results...)
		if result.Status == "scored" && (audit.Reply.Status != "scored" || !execution.UsageKnown) {
			return invalid("scored guidance includes an unavailable or unknown-cost batch")
		}
	}
	if result.Status == "unavailable" {
		if !reflect.DeepEqual(result.Items, claim.BindingItems) || result.WeightedScore != nil || result.Notice == "" {
			return invalid("unavailable guidance claimed historical scores")
		}
		return nil
	}
	if len(covered) != len(candidates) {
		return invalid("scored guidance omitted authoritative candidates")
	}
	asOf, err := time.Parse(time.RFC3339Nano, string(claim.ReservedAt))
	if err != nil {
		return err
	}
	ranked, err := guidance.RankMeasuredSnapshot(asOf, policy, snapshot.Candidates, api.JudgeReply{ID: result.JudgmentIDs[0], Status: "scored", Results: answers})
	if err != nil {
		return err
	}
	if ranked.Status != "scored" || !reflect.DeepEqual(ranked.Items, result.Items) || !reflect.DeepEqual(ranked.WeightedScore, result.WeightedScore) || ranked.Notice != result.Notice {
		return invalid("guidance ranking differs from measured probabilities, task, age or approved relevance")
	}
	return nil
}
