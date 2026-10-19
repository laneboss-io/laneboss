package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Recovery can acquire the unchanged owned effect after its domain epoch moved.
// All execution ports still check their original domain fence. This claim can
// observe/retire and record failure; it cannot authorize replacement execution.
func (s *Service) ClaimOwnedRecovery(ctx context.Context, scope api.Scope, request api.EffectClaimRequest) (api.EffectLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return api.EffectLease{}, err
	}
	if request.ClaimantID != scope.Actor.ID || !future(request.Deadline, s.deps.Clock.Now()) {
		return api.EffectLease{}, fault(api.CodeForbidden, "owned recovery claimant or deadline changed")
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return api.EffectLease{}, err
	}
	r, err := effectRow(ctx, s.db, request.EffectID)
	if err != nil {
		return api.EffectLease{}, err
	}
	if r.Generation != request.ExpectedGeneration || r.Outcome != nil || r.ClaimID != "" && future(r.ClaimExpiresAt, s.deps.Clock.Now()) || r.Effect.Clean == nil && (r.Effect.Worker == nil || r.Effect.Worker.Kind != "archive") {
		return api.EffectLease{}, fault(api.CodeConflict, "owned recovery has a completed, foreign or current claim")
	}
	id, err := wire.NewID()
	if err != nil {
		return api.EffectLease{}, err
	}
	r.State, r.ClaimID, r.ClaimantID, r.ClaimExpiresAt = api.EffectClaimed, id, scope.Actor.ID, request.Deadline
	r.Generation++
	data, err := encodeEffectState(r)
	if err != nil {
		return api.EffectLease{}, err
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE effect_states SET data=? WHERE id=?", data, string(r.Effect.ID)); err != nil {
		return api.EffectLease{}, err
	}
	return api.EffectLease{Record: r, ClaimID: id, ExpiresAt: request.Deadline}, nil
}
