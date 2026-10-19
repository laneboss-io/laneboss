package secrets

import (
	"context"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// UsageJobControl is an installed, nonserializing outbox adapter. StartUsage
// returns the actual worker input connection/frame; RunUsage returns its actual
// result-append frame. It must launch/reconcile the same separately confined
// usage job. It cannot execute the query as the event-service UID. These ports
// add no public method or replacement worker authentication protocol.
type UsageJobControl interface {
	StartUsage(context.Context, api.Scope, api.UsageWindowRequest) (api.Scope, error)
	RunUsage(context.Context, api.ID) (UsageCommandResult, error)
}

type UsageInput = api.UsageCredentialInput

type UsageCommandResult struct {
	Scope      api.Scope     `json:"-"`
	Raw        []byte        `json:"raw"`
	ExitCode   int           `json:"exit_code"`
	ObservedAt api.Timestamp `json:"observed_at"`
}

func (s *Service) mappedWorker(ctx context.Context, scope api.Scope, operation api.WorkerOperation) (api.WorkerPrincipal, error) {
	if err := wire.Context(ctx); err != nil {
		return api.WorkerPrincipal{}, err
	}
	if scope.Config != s.deps.Config || scope.Actor.Kind != "worker" || scope.Actor.Level != 0 || scope.Actor.Role != "" || wire.Nil(scope.Connection) || wire.Nil(scope.Frame) {
		return api.WorkerPrincipal{}, wire.Error(api.CodeUnauthenticated, "credential operation requires its native worker connection and frame")
	}
	binding := scope.Connection.Binding()
	if binding.Class != api.EndpointWorker || binding.Config != s.deps.Config || binding.LaunchID != scope.LaunchID || binding.EndpointGeneration != scope.EndpointGeneration || !wire.ID(string(scope.Connection.ID())) {
		return api.WorkerPrincipal{}, wire.Error(api.CodeForbidden, "credential worker differs from its installed endpoint")
	}
	peer := scope.Connection.Peer()
	if wire.Nil(peer) {
		return api.WorkerPrincipal{}, wire.Error(api.CodeUnauthenticated, "credential worker has no verified native peer")
	}
	if err := peer.Alive(ctx); err != nil {
		return api.WorkerPrincipal{}, err
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return api.WorkerPrincipal{}, err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return api.WorkerPrincipal{}, err
	}
	principal, err := s.deps.Store.WorkerBinding(ctx, binding, facts)
	if err != nil {
		return api.WorkerPrincipal{}, err
	}
	if err := api.ValidateWorkerPrincipal(principal, binding, facts, operation, s.deps.Clock.Now()); err != nil {
		return api.WorkerPrincipal{}, err
	}
	if principal.Record.Actor != scope.Actor || principal.Record.ID != scope.LaunchID {
		return api.WorkerPrincipal{}, wire.Error(api.CodeForbidden, "credential worker scope was relabelled from another principal")
	}
	return principal, nil
}

// InjectMappedWorker is the authenticated worker-only metadata lookup. Pre-spec
// InjectWorker remains service-internal preparation; an active worker cannot
// pass a copied consumed lease to that pre-spec method as authentication.
func (s *Service) InjectMappedWorker(ctx context.Context, scope api.Scope) (api.Injection, error) {
	p, err := s.mappedWorker(ctx, scope, api.WorkerCredentialInject)
	if err != nil {
		return api.Injection{}, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return api.Injection{}, err
	}
	var result api.Injection
	err = backend.WithBroker(ctx, func(j bstate.Journal) error {
		var marker bstate.Slot
		if err := j.Read("slot", credentialID("worker-selection", p.Lease.ID), &marker); err != nil {
			return err
		}
		if marker.Injection == nil || marker.Injection.Target != p.Lease.Target {
			return wire.Error(api.CodeIntegrity, "mapped worker has no retained credential selection")
		}
		result = *marker.Injection
		return nil
	})
	if err != nil {
		return api.Injection{}, err
	}
	current, err := s.currentWorkerGrants(ctx, p.Lease)
	if err != nil {
		return api.Injection{}, err
	}
	if current.ID != p.Lease.GrantSetID || current.LifeID != p.Lease.Target.LifeID || current.Revoked || current.SHA256 != p.Record.GrantsSHA256 || !future(current.ExpiresAt, s.deps.Clock.Now()) {
		return api.Injection{}, wire.Error(api.CodeForbidden, "mapped worker credential grants changed or expired")
	}
	for _, id := range result.SlotIDs {
		var slot bstate.Slot
		if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", id, &slot) }); err != nil {
			return api.Injection{}, err
		}
		clear(slot.Material)
		clear(slot.Returned)
		if slot.Kind != "worker" || slot.Released || slot.WorkerLeaseID != p.Lease.ID || slot.LaunchID != p.Record.ID || !slices.Contains(current.Secrets, slot.Grant) {
			return api.Injection{}, wire.Error(api.CodeForbidden, "mapped worker requested a foreign or unselected credential")
		}
		if _, _, err := s.slotBinding(ctx, slot); err != nil {
			return api.Injection{}, err
		}
		if err := backend.WithBroker(ctx, func(j bstate.Journal) error {
			material, err := j.Fetch(ctx, slot.Grant)
			clear(material.Bytes)
			return err
		}); err != nil {
			return api.Injection{}, err
		}
	}
	fresh, err := s.mappedWorker(ctx, scope, api.WorkerCredentialInject)
	if err != nil {
		return api.Injection{}, err
	}
	if !reflect.DeepEqual(fresh, p) {
		return api.Injection{}, wire.Error(api.CodeConflict, "mapped worker claim changed during credential access")
	}
	return result, nil
}

// MappedWorkerMaterial is the active-worker delivery port. The helper's
// pre-execution material methods remain service-private; an active connection
// must instead authenticate the current native mapping and closed operation.
func (s *Service) MappedWorkerMaterial(ctx context.Context, scope api.Scope, id api.ID) (api.SecretMaterial, error) {
	injection, err := s.InjectMappedWorker(ctx, scope)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if !slices.Contains(injection.SlotIDs, id) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "mapped worker material is outside its exact retained selection")
	}
	before, err := s.mappedWorker(ctx, scope, api.WorkerCredentialInject)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, scope.LaunchID)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if !reflect.DeepEqual(binding.Record, before.Record) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "mapped worker material differs from its retained launch principal")
	}
	material, err := s.SlotMaterial(ctx, scope.LaunchID, id)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	after, err := s.mappedWorker(ctx, scope, api.WorkerCredentialInject)
	if err != nil {
		clear(material.Bytes)
		return api.SecretMaterial{}, err
	}
	if !reflect.DeepEqual(before, after) {
		clear(material.Bytes)
		return api.SecretMaterial{}, wire.Error(api.CodeConflict, "mapped worker changed during material delivery")
	}
	return material, nil
}
