package store

import (
	"context"
	"database/sql"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) stampRevocations(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID) error {
	for _, submitted := range input.Events {
		if submitted.Kind != "identity.revoked" {
			continue
		}
		if input.Internal == nil || input.Scope.Actor.Kind != "service" {
			return fault(api.CodeForbidden, "revocation requires its retained service control cause")
		}
		var record api.LaunchRecord
		if err := wire.Decode(submitted.Payload, &record); err != nil {
			return err
		}
		event, err := authorityEvent(ctx, tx, operation, "identity.revoked", record.ID)
		if err != nil {
			return err
		}
		canonical, err := canonicalValue(record)
		if err != nil {
			return err
		}
		cause := *input.Internal
		if cause.Kind == api.InternalHelperStop && record.Kind == "worker" {
			capability, ok := ctx.Value(grantWorkerKey{}).(grantWorkerCollection)
			if !ok || capability.Store != s {
				return fault(api.CodeForbidden, "worker revocation requires its measured collection capability")
			}
			owner, err := s.captureDrainClaim(ctx, tx, input.Scope, capability.Lease)
			if err != nil {
				return err
			}
			if owner.Release == nil || capability.Lease.Record.Effect.ID != cause.EffectID || record.Target != owner.Cause.Target {
				return fault(api.CodeForbidden, "worker revocation changed its retained helper collection")
			}
			if err := measuredOutcome(capability.Lease.Record.Effect, api.EffectOutcome{Status: "succeeded", Release: &capability.Receipt}); err != nil {
				return err
			}
		}
		if cause.Kind == api.InternalLifecycleEffect {
			claim, err := s.launchClaim(ctx, tx, input.Scope, cause)
			if err != nil {
				return err
			}
			if claim.Effect.Stop == nil || claim.Effect.Context == nil {
				return fault(api.CodeForbidden, "identity revocation requires the original live stop")
			}
		}
		cause.CauseOperationID, cause.CauseRequestID = event.OperationID, event.RequestID
		result := api.LaunchRevocation{Record: record, RecordSHA256: api.Digest(hash(canonical)), Cause: cause, EventID: event.ID, CommittedSeq: event.Seq}
		if err := api.ValidateLaunchRevocation(result); err != nil {
			return err
		}
		if err := put(ctx, tx, "launch_revocation", record.ID, 1, result); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) RevocationEndpoint(ctx context.Context, scope api.Scope, id api.ID) (api.EndpointProjection, error) {
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		return api.EndpointProjection{}, fault(api.CodeForbidden, "revocation endpoint requires its private service scope")
	}
	return scopedProjection[api.EndpointProjection](ctx, s, scope, "endpoint", id)
}

func (s *Service) LaunchRevocation(ctx context.Context, id api.ID) (api.LaunchRevocation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result api.LaunchRevocation
	if err := s.available(); err != nil {
		return result, err
	}
	if err := storedProjection(ctx, s.db, "launch_revocation", id, &result); err != nil {
		return result, err
	}
	if err := api.ValidateLaunchRevocation(result); err != nil {
		return api.LaunchRevocation{}, err
	}
	var current api.LaunchRecord
	if err := storedProjection(ctx, s.db, "launch", id, &current); err != nil {
		return result, err
	}
	if !sameValue(current, result.Record) {
		return api.LaunchRevocation{}, fault(api.CodeIntegrity, "revocation differs from the current retained identity")
	}
	event, err := authorityEvent(ctx, s.db, result.Cause.CauseOperationID, "identity.revoked", id)
	if err != nil {
		return result, err
	}
	if event.ID != result.EventID || event.Seq != result.CommittedSeq || event.RequestedBy != result.Cause.RequestedBy || event.RequestID != result.Cause.CauseRequestID {
		return api.LaunchRevocation{}, fault(api.CodeIntegrity, "revocation lost its original committed cause")
	}
	return result, nil
}
