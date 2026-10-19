package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) validateRemovalClaim(job api.CleanupJob, r collectionRecord, journal api.WorkspaceRemoval, fresh *api.WorkspaceReadback) error {
	if r.RemovalClaim == nil || journal.ClaimID != r.RemovalClaim.ClaimID {
		return fault(api.CodeIntegrity, "workspace journal has no retained claim that performed removal")
	}
	if r.RemovalJournal != nil && !sameValue(*r.RemovalJournal, journal) {
		return fault(api.CodeIntegrity, "workspace removal journal changed after retention")
	}
	if err := api.ValidateWorkspaceRemovalReplay(job, journal, *r.RemovalClaim, journal.After.ObservedAt, s.deps.Clock.Now()); err != nil {
		return err
	}
	if fresh != nil {
		current := journal
		current.After = *fresh
		return api.ValidateWorkspaceRemovalReplay(job, current, *r.RemovalClaim, journal.After.ObservedAt, s.deps.Clock.Now())
	}
	return nil
}

func (r collectionReads) ReadCleanupRemovalClaim(ctx context.Context, job api.CleanupJob, journal api.WorkspaceRemoval) (api.EffectLease, error) {
	s := r.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := r.current(ctx, job)
	if err != nil {
		return api.EffectLease{}, err
	}
	if saved.RemovalJournal == nil {
		return api.EffectLease{}, fault(api.CodeIntegrity, "cleanup has no protected retained removal journal")
	}
	if err := s.validateRemovalClaim(job, saved, journal, nil); err != nil {
		return api.EffectLease{}, err
	}
	return *saved.RemovalClaim, nil
}
