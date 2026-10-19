package admin

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) ResolveRuntime(ctx context.Context, handoff api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	if err := validateCause(handoff.Cause, s.deps.Config, api.InternalHelperRegister); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if handoff.Spec.Kind != "agent" || handoff.Spec.Runner == nil || handoff.Spec.Worker != nil {
		return api.ResolvedRuntime{}, failure(api.CodeUnsupported, "fixed worker runtime needs its separate leased job descriptor handoff")
	}
	authority, err := s.registrationLaunchAuthority(ctx, handoff)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if authority.Record.Plan == nil || authority.Record.Handoff == nil || !samePreparedHandoffStable(*authority.Record.Handoff, handoff) {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime resolution has no exact retained plan and handoff")
	}
	if err := api.ValidateAgentLaunchSpec(handoff.Spec, *authority.Record.Plan); err != nil {
		return api.ResolvedRuntime{}, err
	}
	_, manifest, err := s.loadLaunchEnrollment(ctx)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if err := enrolledExecutable(manifest, handoff.Spec.Runner.Executable); err != nil {
		return api.ResolvedRuntime{}, err
	}
	sources, err := s.runtimeLaunchSources(ctx, authority)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if !reflect.DeepEqual(sources, authority.Record.Plan.Inputs.Sources) {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime sources changed after the plan was sealed")
	}
	storage, err := s.runtimeLaunchStorage(ctx, authority, handoff.Spec.UIDLeaseID)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if storage.Home != authority.Record.Plan.Data.Home || storage.WorkspaceID != handoff.Spec.Workspace.ID {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime private storage differs from its actual allocation")
	}
	if _, err := s.RegisterSpec(ctx, handoff); err != nil {
		return api.ResolvedRuntime{}, err
	}
	s.probeMu.RLock()
	probe := s.probe
	s.probeMu.RUnlock()
	if probe == nil {
		return api.ResolvedRuntime{}, failure(api.CodePrerequisite, "selected native launcher probe is not bound")
	}
	capabilities, err := probe.Probe(ctx)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if capabilities.Backend != handoff.Spec.Backend || !capabilities.Available {
		return api.ResolvedRuntime{}, failure(api.CodePrerequisite, "selected native launch primitives are unavailable")
	}
	if err := s.fenceLaunch(ctx, authority); err != nil {
		return api.ResolvedRuntime{}, err
	}
	var result api.ResolvedRuntime
	if err := s.call(ctx, "resolve_runtime", handoff, &result); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if !reflect.DeepEqual(result.Manifest, manifest) || result.SpecReceipt.SpecID != handoff.Spec.ID || result.SpecReceipt.SpecSHA256 != handoff.SpecSHA256 ||
		result.SpecReceipt.LeaseID != handoff.Spec.UIDLeaseID || result.SpecReceipt.RuntimeManifest != handoff.Spec.RuntimeManifest ||
		result.Home != handoff.Spec.Runner.Home || result.Workspace != handoff.Spec.Workspace ||
		result.Network.GrantSetID != handoff.Spec.Grants.ID || result.Network.Generation != handoff.Spec.PolicyGeneration ||
		!validID(result.Network.ID) || !validID(result.Network.NamespaceID) || result.Network.ExpiresAt != handoff.Spec.Grants.ExpiresAt {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "helper runtime differs from retained spec and namespace allocation")
	}
	installed, err := workerServiceBinding(s.binding)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	return laneRuntimeProjection(installed, handoff.Spec, authority.Record.Plan.Lease, result)
}

// Registration consumes the immutable handoff authored by its planning effect.
// Keep the caller's actual attempt selector separate from that retained cause;
// launchAuthority still reloads and verifies the complete durable claim.
func (s *Service) registrationLaunchAuthority(ctx context.Context, handoff api.PreparedSpecHandoff) (launchAuthority, error) {
	if planning, ok := api.PlanningLeaseFromContext(ctx); ok && api.EffectLeaseClaimed(planning) {
		return s.launchAuthority(ctx, handoff.Spec.PlanID, handoff.Spec.Grants.ID, &handoff.Cause,
			api.PlanningClaim(handoff.Spec.PlanID, planning))
	}
	if attempt, ok := api.EffectLeaseFromContext(ctx); ok && attempt.Record.Effect.PlanLaunch != nil {
		return s.launchAuthority(ctx, handoff.Spec.PlanID, handoff.Spec.Grants.ID, &handoff.Cause,
			api.PlanningClaim(handoff.Spec.PlanID, attempt))
	}
	return s.launchAuthority(ctx, handoff.Spec.PlanID, handoff.Spec.Grants.ID, &handoff.Cause)
}

func (s *Service) runtimeLaunchStorage(ctx context.Context, authority launchAuthority, lease api.ID) (api.LaunchStorage, error) {
	r := authority.Record.Reservation
	return s.launchStorageWithAuthority(ctx, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: lease}, authority)
}

// The helper's namespace lease is private ownership evidence, already checked
// above. A nonempty grant set carries that live, owner-enrolled lease through
// the projection; an offline launch carries an explicitly empty lease.
func laneRuntimeProjection(installed api.InstalledBinding, spec api.LaunchSpec, lease api.HelperLease, result api.ResolvedRuntime) (api.ResolvedRuntime, error) {
	if len(result.Manifest.Bindings) != 0 ||
		result.Manifest.Artifact.SHA256 != installed.ArtifactSHA256 || result.Manifest.Bootstrap.SHA256 != installed.ArtifactSHA256 {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "lane runtime projection differs from its enrolled artifact")
	}
	if len(spec.Grants.Network) == 0 {
		// The helper keeps its private denied namespace for native ownership,
		// but the lane projection must never publish it as egress authority.
		result.Network = api.NetworkLease{EndpointIDs: []api.ID{}}
	} else {
		if result.Network.ID == "" || result.Network.NamespaceID == "" || result.Network.GrantSetID != spec.Grants.ID ||
			result.Network.Generation != spec.PolicyGeneration || result.Network.ExpiresAt != spec.Grants.ExpiresAt ||
			len(result.Network.EndpointIDs) != len(spec.Grants.Network) {
			return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "lane runtime omitted its enrolled egress lease")
		}
		policy, err := json.Marshal(spec.Grants.Network)
		if err != nil || result.Network.PolicySHA256 != digestBytes(policy) {
			return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "lane runtime egress policy pin differs from its grants")
		}
		for index, grant := range spec.Grants.Network {
			if result.Network.EndpointIDs[index] != grant.EndpointID {
				return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "lane runtime egress endpoint differs from its grant")
			}
		}
	}
	binding, err := wire.LaneEndpointBinding(installed, spec, lease)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	result.Manifest.Bindings = []api.InstalledBinding{binding}
	return result, nil
}
