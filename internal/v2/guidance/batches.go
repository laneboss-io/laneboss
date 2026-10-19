package guidance

import (
	"context"
	"strconv"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// evaluateBatches is the service-internal stage for an already won turn claim.
// It preserves full task/candidate coverage, one deadline and every actual
// scoped judge receipt. It cannot reserve a turn or manufacture claim ownership.
func (s *Service) evaluateBatches(ctx context.Context, scope api.Scope, request api.JudgeRequest, policy api.EffectivePolicy) (api.Guidance, error) {
	return s.evaluateBatchesAt(ctx, scope, request, policy, time.Time{})
}

func (s *Service) evaluateBatchesAt(ctx context.Context, scope api.Scope, request api.JudgeRequest, policy api.EffectivePolicy, asOf time.Time) (api.Guidance, error) {
	ctx, entryCancel := context.WithTimeout(ctx, 5*time.Second)
	defer entryCancel()
	if err := contextError(ctx); err != nil {
		return api.Guidance{}, err
	}
	var err error
	scope, err = authorizeJudge(ctx, scope, request)
	if err != nil {
		return api.Guidance{}, err
	}
	config, err := api.ResolveJudgeForScope(scope, request, policy)
	if err != nil {
		return api.Guidance{}, err
	}
	if request.Purpose != "guidance" || !validID(request.ID) || !validID(request.Context.LogicalTurnID) || request.Command != nil || len(request.Rules) != 0 ||
		config.MaxQuestions < 1 || config.MaxQuestions > 12 || config.MaxBytes < 1 || config.MaxBytes > api.MaxJudgeBytes ||
		config.ContextTokens < 1 || !validDigest(config.TokenizerSHA256) || request.MaxCostMicros <= 0 || request.MaxCostMicros > maxInteger ||
		config.GuidanceDeadlineMS < 0 || config.GuidanceDeadlineMS > maxInteger {
		return api.Guidance{}, invalid("invalid service guidance batch bounds or input")
	}
	budget := 5 * time.Second
	if config.GuidanceDeadlineMS > 0 && config.GuidanceDeadlineMS < 5000 {
		budget = time.Duration(config.GuidanceDeadlineMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	now := s.deps.Clock.Now()
	if !asOf.IsZero() {
		now = asOf
	}
	baseline, err := rankWithCutoff(now, policy.GuidanceHalfLifeSeconds, policy.GuidanceMinRelevance, request.Decisions, api.JudgeReply{})
	if err != nil {
		return api.Guidance{}, err
	}
	baseline.LogicalTurnID = request.Context.LogicalTurnID
	if baseline.Status == "empty" {
		return baseline, nil
	}
	if err := contextError(ctx); err != nil {
		return unavailableJudge(baseline, err)
	}
	history := []api.DecisionCandidate{}
	for _, item := range request.Decisions {
		if !item.Binding {
			history = append(history, item)
		}
	}
	all := []api.Judgment{}
	ids := []api.ID{}
	seen := make(map[api.ID]bool)
	remainingCost := request.MaxCostMicros
	for offset := 0; offset < len(history); offset += config.MaxQuestions {
		if remainingCost <= 0 {
			baseline.JudgmentIDs = ids
			return unavailableJudge(baseline, &api.Error{Code: api.CodeBudget})
		}
		batch := request
		batch.ID = api.ID(string(digestBytes([]byte(string(request.ID) + ":" + strconv.Itoa(offset))))[:32])
		batch.Config = config
		batch.MaxCostMicros = remainingCost
		batch.Decisions = history[offset:min(offset+config.MaxQuestions, len(history))]
		reply, err := s.judgeBatch(ctx, scope, batch)
		if err != nil {
			baseline.JudgmentIDs = ids
			return unavailableJudge(baseline, err)
		}
		provenance := reply.BatchIDs
		if len(provenance) == 0 {
			provenance = []api.ID{reply.ID}
		}
		duplicate := seen[reply.ID]
		batchSeen := make(map[api.ID]bool)
		for _, id := range provenance {
			if !validID(id) || seen[id] || batchSeen[id] {
				duplicate = true
			} else {
				ids = append(ids, id)
			}
			batchSeen[id] = true
		}
		checked, checkErr := rankWithCutoff(now, policy.GuidanceHalfLifeSeconds, policy.GuidanceMinRelevance, batch.Decisions, reply)
		if checkErr != nil {
			return api.Guidance{}, checkErr
		}
		if checked.Status != "scored" || duplicate {
			baseline.JudgmentIDs = ids
			baseline.Notice = "Historical guidance unavailable: incomplete batch coverage or reused receipt. Binding context is retained."
			return baseline, nil
		}
		seen[reply.ID] = true
		for _, id := range provenance {
			seen[id] = true
		}
		remainingCost -= reply.CostMicros
		all = append(all, reply.Results...)
	}
	// This temporary union is ranking input only, never a provider/audit reply.
	// Only the actual individual receipt IDs are exposed as provenance.
	result, err := rankWithCutoff(now, policy.GuidanceHalfLifeSeconds, policy.GuidanceMinRelevance,
		request.Decisions, api.JudgeReply{ID: ids[0], Status: "scored", Results: all})
	if err != nil {
		return api.Guidance{}, err
	}
	result.LogicalTurnID, result.JudgmentIDs = request.Context.LogicalTurnID, ids
	if len(ids) > 1 {
		result.JudgmentID = ""
	}
	return result, nil
}
