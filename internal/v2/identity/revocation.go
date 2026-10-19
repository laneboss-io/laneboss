package identity

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) BindConnections(connections api.ConnectionInvalidator) error {
	if nilDependency(connections) {
		return refusal(api.CodePrerequisite, "transport invalidator is required")
	}
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()
	if !nilDependency(s.connections) {
		return refusal(api.CodeConflict, "transport invalidator is already bound")
	}
	s.connections = connections
	return nil
}

func (s *Service) invalidateCommittedLaunch(ctx context.Context, launchID api.ID) error {
	current, err := s.deps.Store.Launch(ctx, launchID)
	if err != nil {
		return err
	}
	revocation, err := s.deps.Store.LaunchRevocation(ctx, launchID)
	if err != nil {
		return err
	}
	if err := api.ValidateLaunchRevocation(revocation); err != nil {
		return err
	}
	if revocation.Record.ID != launchID || !reflect.DeepEqual(current, revocation.Record) {
		return refusal(api.CodeIntegrity, "revocation differs from the current committed launch")
	}
	scope := api.Scope{Config: current.Config, Actor: revocation.Cause.Actor,
		EndpointGeneration: current.EndpointGeneration, PolicyGeneration: current.PolicyGeneration}
	page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{LifeID: current.Target.LifeID, Run: current.Target.Run, Since: revocation.CommittedSeq - 1})
	if err != nil {
		return err
	}
	matched := false
	for _, event := range page.Events {
		if event.Seq != revocation.CommittedSeq {
			continue
		}
		var record api.LaunchRecord
		if event.ID != revocation.EventID || event.Schema != api.SchemaVersion || event.Kind != "identity.revoked" ||
			event.Config != current.Config || event.LifeID != current.Target.LifeID || event.Run != current.Target.Run ||
			event.Actor != revocation.Cause.Actor || event.RequestedBy != revocation.Cause.RequestedBy ||
			event.OperationID != revocation.Cause.CauseOperationID || event.RequestID != revocation.Cause.CauseRequestID ||
			api.DecodeObject(event.Payload, &record) != nil || !reflect.DeepEqual(record, current) {
			return refusal(api.CodeIntegrity, "revocation event differs from its retained cause")
		}
		matched = true
	}
	if !matched {
		return refusal(api.CodeIntegrity, "committed revocation event is missing")
	}
	s.connectionMu.RLock()
	connections := s.connections
	s.connectionMu.RUnlock()
	if nilDependency(connections) {
		return api.NotImplemented("lb-v2-service", "bound transport connection invalidator")
	}
	receipt, err := connections.InvalidateLaunch(ctx, revocation)
	if err != nil {
		return err
	}
	if err := api.ValidateTransportInvalidation(revocation, receipt); err != nil {
		return err
	}
	completed, err := utcTime(receipt.CompletedAt)
	if err != nil || completed.After(s.deps.Clock.Now()) {
		return refusal(api.CodeIntegrity, "transport invalidation completion time is invalid")
	}
	retained, err := s.deps.Store.LaunchRevocation(ctx, launchID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(retained, revocation) {
		return refusal(api.CodeConflict, "revocation cause changed during transport invalidation")
	}
	live, err := s.deps.Store.Launch(ctx, launchID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(live, revocation.Record) {
		return refusal(api.CodeConflict, "launch changed during transport invalidation")
	}
	s.connectionMu.Lock()
	if s.invalidations == nil {
		s.invalidations = make(map[api.ID]api.TransportInvalidationReceipt)
	}
	s.invalidations[launchID] = copyInvalidation(receipt)
	s.connectionMu.Unlock()
	return nil
}

func copyInvalidation(value api.TransportInvalidationReceipt) api.TransportInvalidationReceipt {
	if value.RemainingConnections != nil {
		n := *value.RemainingConnections
		value.RemainingConnections = &n
	}
	if value.RemainingDeliveries != nil {
		n := *value.RemainingDeliveries
		value.RemainingDeliveries = &n
	}
	return value
}

// Private lifecycle read-back. The ID-only public authenticator signature is
// unchanged; absence of a validated transport result never becomes completion.
func (s *Service) InvalidationReceipt(ctx context.Context, id api.ID) (api.TransportInvalidationReceipt, error) {
	s.connectionMu.RLock()
	receipt, ok := s.invalidations[id]
	receipt = copyInvalidation(receipt)
	s.connectionMu.RUnlock()
	if !ok {
		return api.TransportInvalidationReceipt{}, refusal(api.CodePrerequisite, "transport invalidation has no validated completion receipt")
	}
	actual, err := s.deps.Store.LaunchRevocation(ctx, id)
	if err != nil {
		return api.TransportInvalidationReceipt{}, err
	}
	if err := api.ValidateTransportInvalidation(actual, receipt); err != nil {
		return api.TransportInvalidationReceipt{}, err
	}
	return receipt, nil
}
