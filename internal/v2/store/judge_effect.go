package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Judge workers belong to the once-only synchronous JudgeExecution, rather
// than the reclaimable outbox. This read authenticates the persisted child
// claim against that original execution on every native binding check.
func (s *Service) judgeNativeEffect(ctx context.Context, db queryer, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	var stage judgeNative
	if err := storedProjection(ctx, db, "judge_native", id, &stage); err != nil {
		return api.EffectRecord{}, err
	}
	e := stage.Execution
	e.Acquired = true
	if _, err := s.judgeExecutionClaim(ctx, db, scope, e); err != nil {
		return api.EffectRecord{}, err
	}
	claim := stage.Claim
	if claim.Record.Effect.ID != e.ID || claim.ClaimID != e.ClaimID || claim.ExpiresAt != e.Deadline ||
		claim.Record.ClaimantID != e.Intent.Actor.ID || claim.Record.Effect.Worker == nil || !sameValue(*claim.Record.Effect.Worker, stage.Plan) {
		return api.EffectRecord{}, fault(api.CodeIntegrity, "judge native effect differs from its original once-only claim")
	}
	return claim.Record, nil
}
