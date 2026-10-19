package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) currentLifecycleRequester(ctx context.Context, db queryer, actor api.Actor) error {
	if actor.Kind != "lane" {
		return nil
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='launch' AND json_extract(data,'$.actor.id')=?", string(actor.ID)).Scan(&raw); err != nil {
		return err
	}
	var launch api.LaunchRecord
	if err := decodeStored(raw, &launch); err != nil {
		return err
	}
	if launch.Actor != actor || launch.Revoked || launch.Config != s.deps.Config {
		return fault(api.CodeForbidden, "original lifecycle requester was revoked or replaced")
	}
	var endpoint api.EndpointProjection
	if err := storedProjection(ctx, db, "endpoint", launch.ID, &endpoint); err != nil {
		return err
	}
	if endpoint.Revoked || endpoint.Binding.EndpointGeneration != launch.EndpointGeneration {
		return fault(api.CodeForbidden, "original lifecycle requester endpoint changed")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, db, "grants", launch.GrantSetID, &grants); err != nil {
		return err
	}
	if grants.Revoked || grants.LifeID != actor.LifeID || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeForbidden, "original lifecycle requester grants expired or were revoked")
	}
	return nil
}

// OwnsDeferredMutation names the durable archive route after its public waiter
// ends. The dispatcher must not seal an unrelated error reply over that route.
func (s *Service) OwnsDeferredMutation(ctx context.Context, scope api.Scope, key api.RequestKey, operation api.ID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return false, err
	}
	if scope.Config != s.deps.Config {
		return false, fault(api.CodeForbidden, "deferred mutation belongs to another configuration")
	}
	if key.Method == "org.change.apply" {
		receipt, err := s.lookupReceipt(ctx, s.db, scope, key)
		if absent(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return receipt.Deferred != nil && receipt.Reply == nil && receipt.Operation.ID == operation, nil
	}
	var r archiveRecord
	err := storedProjection(ctx, s.db, "archive_job", operation, &r)
	if absent(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return r.Commit == nil && r.Scope.Actor == scope.Actor && requestKey(r.Request) == key && r.Job.Intent.OperationID == operation, nil
}
