package secrets

import (
	"context"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// PreparedSlotMaterial is the protected nonexecuting helper delivery port.
// It is deliberately absent from the public registry and generic object store.
// The installed adapter must keep these bytes inside its private credential
// projection. SlotMaterial remains the separate post-binding lookup.
func (s *Service) PreparedSlotMaterial(ctx context.Context, spec api.LaunchSpec, id api.ID) (api.SecretMaterial, error) {
	if spec.Kind == "worker" {
		return s.PrepareWorkerMaterial(ctx, spec, id)
	}
	if err := wire.Context(ctx); err != nil {
		return api.SecretMaterial{}, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return api.SecretMaterial{}, err
	}
	var slot bstate.Slot
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", id, &slot) }); err != nil {
		return api.SecretMaterial{}, err
	}
	defer clear(slot.Material)
	defer clear(slot.Returned)
	if slot.Released || slot.Config != s.deps.Config || slot.Target != spec.Target || slot.LaunchID != spec.LaunchID || slot.ReservationID != spec.PlanID || !slices.Contains(spec.Injection.SlotIDs, slot.ID) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "prepared material differs from its exact reserved launch")
	}
	claim, err := api.ReloadPlanningClaim(ctx, s.deps.Store, s.deps.ServiceScope, slot.ReservationID, slot.PlanningClaim.EffectID, s.deps.Clock.Now())
	if err != nil {
		return api.SecretMaterial{}, err
	}
	current, err := s.currentGrants(ctx, slot.Target, launchSelection{Claim: claim, HelperLeaseID: slot.HelperLeaseID})
	if err != nil {
		return api.SecretMaterial{}, err
	}
	launch, err := s.credentialLaunch(ctx, slot.Target, current, launchSelection{Claim: claim, HelperLeaseID: slot.HelperLeaseID})
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if launch.record.Plan == nil || launch.record.Handoff == nil || launch.record.Phase != "spec_retained" || !slotIsPrivate(slot, launch) || slot.GrantSHA256 != current.SHA256 {
		return api.SecretMaterial{}, wire.Error(api.CodeConflict, "prepared material lacks its complete retained nonexecuting spec")
	}
	if err := api.ValidateAgentLaunchSpec(spec, *launch.record.Plan); err != nil {
		return api.SecretMaterial{}, err
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if err := api.ValidateCapturePolicy(launch.record.Plan.Capture, policy); err != nil {
		return api.SecretMaterial{}, err
	}
	if slot.Kind == "profile" {
		if !future(slot.Credential.ExpiresAt, s.deps.Clock.Now()) || launch.record.Plan.Runner.Slot != slot.Credential {
			return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "prepared profile material is stale or not selected")
		}
	} else if slot.Kind != "task" || !slices.Contains(current.Secrets, slot.Grant) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "prepared task material is not delegated")
	} else if err := validateGrant(slot.Grant, s.deps.Clock.Now()); err != nil {
		return api.SecretMaterial{}, err
	}
	if wire.Nil(s.deps.Control) || wire.Nil(s.deps.Helper) {
		return api.SecretMaterial{}, wire.Error(api.CodePrerequisite, "prepared material requires installed launch control and helper")
	}
	handoff, err := s.deps.Control.Handoff(ctx, spec)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if !reflect.DeepEqual(handoff, *launch.record.Handoff) || !reflect.DeepEqual(handoff.Spec, spec) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "prepared material handoff differs from its retained original")
	}
	data, err := s.protectedObject(ctx, handoff.Original, slot.OperationID, launch.record.Reservation.Target.LifeID)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	var original api.LaunchSpec
	if err := api.DecodeObject(data, &original); err != nil {
		return api.SecretMaterial{}, err
	}
	if !reflect.DeepEqual(original, spec) {
		return api.SecretMaterial{}, wire.Error(api.CodeIntegrity, "prepared material original spec bytes differ")
	}
	resolved, err := s.deps.Helper.ResolveRuntime(ctx, handoff)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if err := s.agentRuntime(ctx, spec.RuntimeManifest, resolved.Manifest, launch.record.Plan.Runner.Executable); err != nil {
		return api.SecretMaterial{}, err
	}
	if resolved.SpecReceipt.SpecID != spec.ID || resolved.SpecReceipt.Config != s.deps.Config || resolved.SpecReceipt.Target != spec.Target || resolved.SpecReceipt.LeaseID != slot.HelperLeaseID ||
		resolved.SpecReceipt.SpecSHA256 != handoff.SpecSHA256 || resolved.SpecReceipt.RuntimeManifest != spec.RuntimeManifest || resolved.SpecReceipt.OperationID != slot.OperationID ||
		resolved.Home != launch.storage.Home.Home || resolved.Workspace != spec.Workspace {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "prepared material runtime differs from retained ownership")
	}
	var material api.SecretMaterial
	err = backend.WithBroker(ctx, func(j bstate.Journal) error {
		if err := s.recheckCredentialLaunch(ctx, launch); err != nil {
			return err
		}
		var latest bstate.Slot
		if err := j.Read("slot", id, &latest); err != nil {
			return err
		}
		defer clear(latest.Material)
		defer clear(latest.Returned)
		if latest.Released || latest.Fingerprint != slot.Fingerprint {
			return wire.Error(api.CodeConflict, "prepared credential slot changed during delivery")
		}
		if err := s.deliveryPolicy(ctx, j, latest); err != nil {
			return err
		}
		if latest.Kind == "task" {
			// Task slots share their retained agent's selected profile. Check
			// that actual slot and owner in this same final journal scope.
			var selected bstate.Slot
			defer func() { clear(selected.Material); clear(selected.Returned) }()
			issued := launch.record.Plan.Runner.Slot
			if err := j.Read("slot", issued.ID, &selected); err != nil {
				return err
			}
			if selected.Kind != "profile" || selected.Released || selected.ID != issued.ID || selected.Credential != issued || selected.ProfileID != issued.ProfileID || selected.Config != latest.Config || selected.Target != latest.Target || selected.LaunchID != latest.LaunchID || selected.ReservationID != latest.ReservationID {
				return wire.Error(api.CodeForbidden, "prepared task material lost its selected profile binding")
			}
			if err := s.deliveryPolicy(ctx, j, selected); err != nil {
				return err
			}
		}
		source, err := j.Fetch(ctx, latest.Grant)
		if err != nil {
			return err
		}
		clear(source.Bytes)
		material.Bytes = append([]byte(nil), latest.Material...)
		return nil
	})
	if err != nil {
		clear(material.Bytes)
		return api.SecretMaterial{}, err
	}
	return material, nil
}
