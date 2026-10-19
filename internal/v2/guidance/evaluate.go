package guidance

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// evaluateCandidates keeps the original private entry point for its callers.
// All candidate counts use the same complete batching, budget and audit path.
func (s *Service) evaluateCandidates(ctx context.Context, scope api.Scope, request api.JudgeRequest, policy api.EffectivePolicy) (api.Guidance, error) {
	return s.evaluateBatches(ctx, scope, request, policy)
}

// judgeBatch is shared by single-batch and complete multi-batch selection.
func (s *Service) judgeBatch(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.JudgeReply, error) {
	config := request.Config
	request.DeadlineMS = remainingMS(ctx)
	fit, err := s.deps.Judge.FitForScope(ctx, scope, request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if err := contextError(ctx); err != nil {
		return api.JudgeReply{}, err
	}
	if !fit.Proved || fit.InputBytes <= 0 || fit.InputBytes > config.MaxBytes ||
		fit.InputTokens <= 0 || fit.InputTokens >= config.ContextTokens ||
		fit.ContextTokens != config.ContextTokens || fit.TokenizerSHA256 != config.TokenizerSHA256 {
		return api.JudgeReply{}, &api.Error{Code: api.CodeUnscored, Owner: "lb-v2-guidance",
			Message: "complete guidance input fit was not proved", Instead: "Repair the pinned complete-input fit; do not truncate or infer a zero score."}
	}
	request.DeadlineMS = remainingMS(ctx)
	reply, err := s.deps.Judge.EvaluateForScope(ctx, scope, request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if err := contextError(ctx); err != nil {
		return api.JudgeReply{}, err
	}
	if reply.SelectedModel != config.Model || reply.DeploymentSHA256 != config.DeploymentSHA256 ||
		reply.LatencyMS < 0 || reply.LatencyMS > maxInteger || reply.CostMicros < 0 || reply.CostMicros > request.MaxCostMicros {
		return api.JudgeReply{}, &api.Error{Code: api.CodeUnscored, Owner: "lb-v2-guidance",
			Message: "guidance reply differs from its approved model, deployment or measured budget",
			Instead: "Retain the actual scoped judge audit; do not rank an unproved provider result."}
	}
	return reply, nil
}

func remainingMS(ctx context.Context) int64 {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	milliseconds := int64(remaining / time.Millisecond)
	if remaining%time.Millisecond != 0 {
		milliseconds++
	}
	return milliseconds
}

func unavailableJudge(baseline api.Guidance, err error) (api.Guidance, error) {
	var typed *api.Error
	if !errors.As(err, &typed) {
		return api.Guidance{}, err
	}
	switch typed.Code {
	case api.CodeUnavailable, api.CodeUnscored, api.CodeBudget, api.CodeDeadline:
		baseline.Status, baseline.WeightedScore = "unavailable", nil
		bindings := []api.GuidanceItem{}
		for _, item := range baseline.Items {
			if item.Binding {
				bindings = append(bindings, item)
			}
		}
		baseline.Items = bindings
		baseline.Notice = "Historical guidance unavailable: judgment did not complete within its bounds. Binding context is retained."
		return baseline, nil
	default:
		// In particular, unfinished dependencies, integrity failures and
		// authority errors must remain typed errors, not scored empty data.
		return api.Guidance{}, err
	}
}
