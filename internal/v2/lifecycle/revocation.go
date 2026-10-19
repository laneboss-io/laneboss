package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

// The endpoint is a protected store projection, never supplied by a stop
// request or reconstructed from a socket label. The shared API's endpoint read
// is an explicit remaining service integration, alongside outbox invocation.
type revocationEndpointStore interface {
	RevocationEndpoint(context.Context, api.Scope, api.ID) (api.EndpointProjection, error)
}

// RevokeLaunch is a private stage of the original committed Stop effect. It
// commits the causal identity/endpoint decision before identity invalidates
// transport. It neither stops a process nor completes/collects that effect.
func (s *Service) RevokeLaunch(ctx context.Context, scope api.Scope, lease api.EffectLease) error {
	if err := s.ready(); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if scope.Actor.Kind != "service" || scope.Request.Method != "" || scope.Request.Proof != nil || !validID(scope.Actor.ID) ||
		!validID(lease.Record.Effect.ID) || !validID(lease.ClaimID) {
		return problem(api.CodeForbidden, "launch revocation requires the installed stop executor", "Use the current original Stop outbox claim.")
	}
	current, err := s.deps.Store.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return failure(err)
	}
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if effectRecord(current) != nil || !api.EffectLeaseClaimed(lease) || !reflect.DeepEqual(current, lease.Record) || current.State != api.EffectClaimed || current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID ||
		current.ClaimExpiresAt != lease.ExpiresAt || expiryErr != nil || !s.deps.Clock.Now().Before(expires) || current.Outcome != nil || current.Effect.Context == nil || current.Effect.Stop == nil {
		return problem(api.CodeConflict, "launch revocation claim is not current", "Reconcile the same retained Stop effect; do not create a replacement decision.")
	}
	cause := *current.Effect.Context
	if cause.Kind != api.InternalLifecycleEffect || cause.Config != scope.Config || cause.EffectID != current.Effect.ID ||
		cause.CauseOperationID != current.Effect.OperationID || cause.Target != current.Effect.Stop.Target {
		return integrity("launch revocation changed its original stop cause")
	}
	unlock, err := s.lockLife(ctx, cause.Target.LifeID)
	if err != nil {
		return err
	}
	defer func() { unlock() }()
	lane, err := s.lane(ctx, scope, cause.Target, true)
	if err != nil {
		return err
	}
	if lane.CancellationEpoch != cause.CancellationEpoch {
		return problem(api.CodeConflict, "stop revocation fence was superseded", "Retain the original revocation and reconcile the current life.")
	}
	revoked, lookupErr := s.deps.Store.LaunchRevocation(ctx, lane.LaunchID)
	if lookupErr != nil && !notFound(lookupErr) {
		return failure(lookupErr)
	}
	if notFound(lookupErr) {
		if lane.State != "stopping" && lane.State != "abandoned" {
			return problem(api.CodeConflict, "new revocation requires the committed stopping state", "Reconcile the original stop decision.")
		}
		binding, err := s.deps.Store.LaunchBinding(ctx, lane.LaunchID)
		if err != nil {
			return failure(err)
		}
		record, err := s.deps.Store.Launch(ctx, lane.LaunchID)
		if err != nil {
			return failure(err)
		}
		if !reflect.DeepEqual(binding.Record, record) || record.Revoked || record.ID != lane.LaunchID || record.Config != scope.Config || record.Target != cause.Target ||
			record.ContainmentID != current.Effect.Stop.ContainmentID || record.ProcessGeneration != current.Effect.Stop.Generation {
			return integrity("stop revocation has no matching retained launch binding")
		}
		endpoints, ok := s.deps.Store.(revocationEndpointStore)
		if !ok || absent(endpoints) {
			return api.NotImplemented("lb-v2-service", "protected revocation endpoint projection")
		}
		endpoint, err := endpoints.RevocationEndpoint(ctx, scope, record.ID)
		if err != nil {
			return failure(err)
		}
		if api.ValidateBinding(endpoint.Binding, scope.Config, release.Version) != nil || endpoint.Revoked || !validGeneration(endpoint.Generation) || endpoint.Generation >= api.Generation(maxInteger) ||
			endpoint.Binding.Config != record.Config || endpoint.Binding.Class != api.EndpointLane || endpoint.Binding.LaunchID != record.ID || endpoint.Binding.Target == nil ||
			*endpoint.Binding.Target != record.Target || endpoint.Binding.EndpointGeneration != record.EndpointGeneration {
			return integrity("stop revocation endpoint differs from its actual launch")
		}
		binding.Record.Revoked = true
		endpoint.Revoked = true
		endpoint.Generation++
		event, err := s.event(scope, lane, "identity.revoked", binding.Record, scope.Actor)
		if err != nil {
			return err
		}
		event.OperationID, event.RequestID, event.RequestedBy = cause.CauseOperationID, cause.CauseRequestID, cause.RequestedBy
		emitter := cause
		emitter.Actor = scope.Actor
		_, err = s.deps.Store.Transact(api.WithEffectLease(ctx, lease), api.Transaction{Scope: scope, Internal: &emitter, Events: []api.Event{event},
			Writes:  api.StateWrites{Endpoints: []api.EndpointProjection{endpoint}},
			Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation}, {Kind: api.CompareEndpoint, ID: record.ID, Generation: endpoint.Generation - 1}},
			Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: cause.CancellationEpoch}}}})
		if err != nil {
			return failure(err)
		}
		revoked, err = s.deps.Store.LaunchRevocation(ctx, record.ID)
		if err != nil {
			return failure(err)
		}
	}
	if err := api.ValidateLaunchRevocation(revoked); err != nil {
		return failure(err)
	}
	expectedCause := cause
	expectedCause.Actor = revoked.Cause.Actor // The first actual claimant authored the retained event.
	if revoked.Record.ID != lane.LaunchID || revoked.Cause.Actor.Kind != "service" || !reflect.DeepEqual(revoked.Cause, expectedCause) {
		return integrity("retained revocation lost its original cause")
	}
	actual, err := s.deps.Store.Launch(ctx, lane.LaunchID)
	if err != nil {
		return failure(err)
	}
	if !reflect.DeepEqual(actual, revoked.Record) {
		return integrity("revocation read-back differs from its actual revoked launch")
	}
	// The identity implementation validates the actual close-completion receipt.
	// A typed failure leaves the original committed Stop stage pending for retry.
	unlock()
	unlock = func() {}
	if err := s.deps.Identity.RevokeLaunch(ctx, revoked.Record.ID); err != nil {
		return failure(err)
	}
	if recorder, ok := s.deps.Store.(interface {
		RecordGrantTransportInvalidation(context.Context, api.Scope, api.EffectLease, api.TransportInvalidationReceipt) error
	}); ok {
		reader, ok := s.deps.Identity.(interface {
			InvalidationReceipt(context.Context, api.ID) (api.TransportInvalidationReceipt, error)
		})
		if !ok {
			return problem(api.CodePrerequisite, "identity has no measured transport read-back", "Bind the installed identity transport owner before completing revocation.")
		}
		receipt, err := reader.InvalidationReceipt(ctx, revoked.Record.ID)
		if err != nil {
			return failure(err)
		}
		return recorder.RecordGrantTransportInvalidation(ctx, scope, lease, receipt)
	}
	return nil
}

func revokedDigest(record api.LaunchRecord) (api.Digest, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return "", integrity("cannot encode revoked launch")
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		return "", failure(err)
	}
	return digestOfBytes(canonical), nil
}
