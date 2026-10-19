package lifecycle

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) CollectGrantWorkers(ctx context.Context, scope api.Scope, lease api.EffectLease, receipt api.ReleaseReceipt) error {
	store, ok := s.deps.Store.(interface {
		RevokeCollectedGrantWorkers(context.Context, api.Scope, api.EffectLease, api.ReleaseReceipt) ([]api.ID, error)
		RecordCollectedWorkerInvalidation(context.Context, api.Scope, api.EffectLease, api.ID, api.TransportInvalidationReceipt) error
	})
	if !ok {
		return problem(api.CodePrerequisite, "grant worker collection owner is missing", "Restore the private store collection port.")
	}
	workers, err := store.RevokeCollectedGrantWorkers(ctx, scope, lease, receipt)
	if err != nil {
		return err
	}
	for _, id := range workers {
		if err := s.deps.Identity.RevokeLaunch(ctx, id); err != nil {
			return err
		}
		reader, ok := s.deps.Identity.(interface {
			InvalidationReceipt(context.Context, api.ID) (api.TransportInvalidationReceipt, error)
		})
		if !ok {
			return problem(api.CodePrerequisite, "capture worker transport has no measured read-back", "Bind the installed identity transport owner.")
		}
		closed, err := reader.InvalidationReceipt(ctx, id)
		if err != nil {
			return err
		}
		if err := store.RecordCollectedWorkerInvalidation(ctx, scope, lease, id, closed); err != nil {
			return err
		}
	}
	return nil
}
