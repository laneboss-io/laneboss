package store

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

func hasCode(err error, code api.ErrorCode) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed.Code == code
}

// Only the original still-current claimant can classify a permanent domain
// fence. Stale/foreign claims never gain terminal authority through this port.
func (s *Service) OwnedFenceFailure(ctx context.Context, scope api.Scope, lease api.EffectLease) (*api.Error, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return nil, err
	}
	current, err := effectRow(ctx, s.db, lease.Record.Effect.ID)
	if err != nil {
		return nil, err
	}
	if current.Outcome != nil || !sameValue(current, lease.Record) || current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return nil, nil
	}
	var expected api.LifeRef
	var generation api.Generation
	var epoch api.Generation
	if current.Effect.Worker != nil && current.Effect.Worker.Kind == "archive" {
		var r archiveRecord
		if err := storedProjection(ctx, s.db, "archive_job", current.Effect.OperationID, &r); err != nil {
			return nil, err
		}
		if err := s.archiveFence(ctx, s.db, r); err != nil {
			if (hasCode(err, api.CodeConflict) || hasCode(err, api.CodeForbidden)) && future(lease.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodePrerequisite, "original archive authority or life fence permanently moved; preserve its sources and resolve this original operation"), nil
			}
			return nil, err
		}
		expected, generation, epoch = r.Job.Intent.Request.Target, r.Job.Intent.Request.ExpectedGeneration, r.Job.Intent.CancellationEpoch
	} else if current.Effect.Clean != nil {
		expected, generation, epoch = current.Effect.Clean.Target, current.Effect.Clean.ExpectedGeneration, current.Effect.Context.CancellationEpoch
		if _, err := s.cleanClaim(ctx, s.db, scope, lease); err != nil {
			if (hasCode(err, api.CodeConflict) || hasCode(err, api.CodeForbidden)) && future(lease.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodePrerequisite, "original cleanup authority or life fence permanently moved; preserve its workspace and journals"), nil
			}
			return nil, err
		}
		var r collectionRecord
		if err := storedProjection(ctx, s.db, "collection", current.Effect.ID, &r); err == nil {
			job := api.CleanupJob{Intent: r.Intent, Claim: lease}
			if err := s.checkCollectionGraph(ctx, job, r); hasCode(err, api.CodeConflict) {
				return fault(api.CodePrerequisite, "cleanup ownership graph permanently moved; preserve original journals and request a fresh cleanup after reconciliation"), nil
			} else if hasCode(err, api.CodeBudget) || hasCode(err, api.CodeInvalid) {
				var measured *api.Error
				errors.As(err, &measured)
				return measured, nil
			} else if err != nil {
				return nil, err
			}
		} else if !absent(err) {
			return nil, err
		}
	} else {
		return nil, nil
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", expected.LifeID, &lane); err != nil {
		return nil, err
	}
	if lane.Run != expected.Run || lane.Generation != generation || lane.CancellationEpoch != epoch || lane.Cleaned {
		return fault(api.CodePrerequisite, "original archive or cleanup life fence permanently moved; preserve the workspace and inspect this failed original operation"), nil
	}
	return nil, nil
}
