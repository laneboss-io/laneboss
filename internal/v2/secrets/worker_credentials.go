package secrets

import (
	"context"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Worker slots precede the final LaunchSpec. The current fixed Worker effect
// selects the retained lease/input/runtime. PrepareWorkerMaterial checks the
// complete retained spec separately before any bytes leave this journal.
func (s *Service) currentWorkerGrants(ctx context.Context, lease api.WorkerLease) (api.GrantSet, error) {
	if err := wire.Context(ctx); err != nil {
		return api.GrantSet{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, lease.GrantSetID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if wire.Nil(s.deps.Grants) {
		return api.GrantSet{}, wire.Error(api.CodePrerequisite, "worker credentials require their installed grant resolver")
	}
	current, err := s.deps.Grants.Revalidate(ctx, grants)
	if err != nil {
		return api.GrantSet{}, err
	}
	if !reflect.DeepEqual(current, grants) || current.ID != lease.GrantSetID || current.LifeID != lease.Target.LifeID || current.Generation == 0 || current.Revoked || !wire.Digest(current.SHA256) || !future(current.ExpiresAt, s.deps.Clock.Now()) {
		return api.GrantSet{}, wire.Error(api.CodeForbidden, "worker credential grants are changed revoked or outside the retained job")
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return api.GrantSet{}, err
	}
	if current.PolicyGeneration == 0 || current.PolicyGeneration != policy.Generation || !wire.Digest(policy.SHA256) {
		return api.GrantSet{}, wire.Error(api.CodeConflict, "worker credential policy changed before material delivery")
	}
	return current, nil
}

func (s *Service) workerSelection(ctx context.Context, lease api.WorkerLease) (api.EffectRecord, api.RuntimeManifest, error) {
	current, err := s.deps.Store.Effect(ctx, s.deps.ServiceScope, lease.EffectID)
	if err != nil {
		return current, api.RuntimeManifest{}, err
	}
	e := current.Effect
	if current.State != api.EffectClaimed || current.Outcome != nil || current.Generation == 0 || !wire.ID(string(current.ClaimID)) || !wire.ID(string(current.ClaimantID)) || !future(current.ClaimExpiresAt, s.deps.Clock.Now()) ||
		e.Context == nil || e.ID != lease.EffectID || e.OperationID != lease.OperationID || e.Context.Target != lease.Target || e.Context.Config != s.deps.Config ||
		e.Context.Actor.Kind != "service" || !wire.ID(string(e.Context.Actor.ID)) || !wire.ID(string(e.Context.CauseRequestID)) || e.Context.EffectID != e.ID || e.Context.CauseOperationID != lease.OperationID || e.Worker == nil && e.Channel == nil {
		return current, api.RuntimeManifest{}, wire.Error(api.CodeConflict, "worker credential claim has no current fixed job")
	}
	plan, err := s.frozenWorkerPlan(ctx, current, lease)
	if err != nil {
		return current, api.RuntimeManifest{}, err
	}
	if plan.Schema != "laneboss.worker-plan.v2" || plan.Kind != lease.Kind || plan.Input != lease.Input || plan.GrantSetID != lease.GrantSetID ||
		!wire.ID(string(plan.Executable.ID)) || !wire.Digest(plan.Executable.SHA256) || plan.Executable.Version == "" || plan.Argv == nil || len(plan.Argv) == 0 {
		return current, api.RuntimeManifest{}, wire.Error(api.CodeForbidden, "worker credential selection differs from the fixed enrolled job")
	}
	data, err := s.protectedObjectFor(ctx, lease.RuntimeManifest, "", true)
	if err != nil {
		return current, api.RuntimeManifest{}, err
	}
	var manifest api.RuntimeManifest
	if err := api.DecodeObject(data, &manifest); err != nil {
		return current, manifest, err
	}
	if manifest.Schema != "laneboss.runtime.v2" || manifest.Generation == 0 || manifest.Bootstrap != plan.Executable {
		return current, manifest, wire.Error(api.CodeForbidden, "worker executable differs from its protected runtime enrollment")
	}
	if _, err := s.protectedObject(ctx, lease.Input, lease.OperationID); err != nil {
		return current, manifest, err
	}
	return current, manifest, nil
}

func (s *Service) frozenWorkerPlan(ctx context.Context, current api.EffectRecord, lease api.WorkerLease) (api.WorkerPlan, error) {
	if current.Effect.Worker != nil {
		return *current.Effect.Worker, nil
	}
	job := current.Effect.Channel
	if job == nil || lease.Kind != "channel" || job.Lease.ID != lease.ID || job.Lease.Input != lease.Input || job.Lease.GrantSetID != lease.GrantSetID {
		return api.WorkerPlan{}, wire.Error(api.CodeConflict, "channel credential selection lost its original job")
	}
	if err := api.ValidateChannelJob(*job); err != nil {
		return api.WorkerPlan{}, err
	}
	source, ok := s.deps.Store.(api.ChannelPlanSource)
	if !ok {
		return api.WorkerPlan{}, api.NotImplemented("lb-v2-service", "frozen channel native plan")
	}
	return source.ChannelPlan(ctx, s.deps.ServiceScope, api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt})
}

func (s *Service) prepareWorkerInjection(ctx context.Context, lease api.WorkerLease, requested []api.WorkerCredential, grants api.GrantSet) (api.Injection, error) {
	effect, manifest, err := s.workerSelection(ctx, lease)
	if err != nil {
		return api.Injection{}, err
	}
	plan, err := s.frozenWorkerPlan(ctx, effect, lease)
	if err != nil {
		return api.Injection{}, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return api.Injection{}, err
	}
	result := api.Injection{Target: lease.Target, SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}
	selection, err := valueDigest(struct {
		Lease     api.WorkerLease
		Plan      api.WorkerPlan
		Manifest  api.RuntimeManifest
		Grants    api.GrantSet
		Requested []api.WorkerCredential
	}{lease, plan, manifest, grants, requested})
	if err != nil {
		return api.Injection{}, err
	}
	markerID := credentialID("worker-selection", lease.ID)
	err = s.withPreparedBind(ctx, backend, markerID, func() bstate.Slot { return s.bindMarker(markerID, selection, &result) }, func(journal bstate.Journal) error {
		if err := s.recheckWorkerSelection(ctx, lease, effect, grants); err != nil {
			return err
		}
		var marker bstate.Slot
		if err := journal.Read("slot", markerID, &marker); err == nil {
			if marker.Fingerprint != selection {
				return wire.Error(api.CodeConflict, "worker injection retry changed its selected inputs")
			}
		} else if !hasCode(err, api.CodeNotFound) {
			return err
		} else if err := journal.Write("slot", markerID, bstate.Slot{Schema: "laneboss.credential-slot.v2", Config: s.deps.Config, ID: markerID, Kind: "selection", Fingerprint: selection, Material: []byte{}, Returned: []byte{}}); err != nil {
			return err
		}
		for _, selected := range requested {
			var grant api.SecretGrant
			for _, candidate := range grants.Secrets {
				if candidate.Name == selected.Name && candidate.Version == selected.Version && candidate.SourceHandle == selected.SourceHandle && candidate.Delivery == selected.Delivery && candidate.Target == selected.Target {
					grant = candidate
					break
				}
			}
			if grant.ID == "" {
				return wire.Error(api.CodeForbidden, "worker credential has no exact current source grant")
			}
			id := credentialID("worker", lease.ID, grant.ID)
			fingerprint, err := valueDigest(struct {
				Selection api.Digest
				Grant     api.SecretGrant
			}{selection, grant})
			if err != nil {
				return err
			}
			var slot bstate.Slot
			if err := journal.Read("slot", id, &slot); err == nil {
				defer clear(slot.Material)
				defer clear(slot.Returned)
				if slot.Released || slot.Fingerprint != fingerprint || slot.WorkerLeaseID != lease.ID {
					return wire.Error(api.CodeConflict, "worker credential retry changed its retained inputs")
				}
				source, err := journal.Fetch(ctx, slot.Grant)
				clear(source.Bytes)
				if err != nil {
					return err
				}
			} else if !hasCode(err, api.CodeNotFound) {
				return err
			} else {
				material, err := journal.Fetch(ctx, grant)
				if err != nil {
					return err
				}
				defer clear(material.Bytes)
				slot = bstate.Slot{Schema: "laneboss.credential-slot.v2", Config: s.deps.Config, ID: id, Kind: "worker", Target: lease.Target,
					WorkerLeaseID: lease.ID, WorkerLease: &lease, WorkerPlan: &plan, OperationID: lease.OperationID, RequestID: effect.Effect.Context.CauseRequestID, RequestedBy: effect.Effect.Context.RequestedBy,
					GrantSetID: grants.ID, GrantSHA256: grants.SHA256, PolicyGeneration: grants.PolicyGeneration, Fingerprint: fingerprint, Grant: grant, Material: material.Bytes, Returned: []byte{}}
				if err := journal.Write("slot", id, slot); err != nil {
					return err
				}
			}
			result.SlotIDs = append(result.SlotIDs, id)
			result.GrantIDs = append(result.GrantIDs, grant.ID)
			result.SourceVersions = append(result.SourceVersions, grant.Version)
			if grant.Delivery == "env" {
				result.TaskSecretNames = append(result.TaskSecretNames, grant.Target)
			} else {
				result.TaskSecretFileNames = append(result.TaskSecretFileNames, grant.Target)
			}
		}
		if err := s.recheckWorkerSelection(ctx, lease, effect, grants); err != nil {
			return err
		}
		if marker.Injection != nil {
			if !reflect.DeepEqual(*marker.Injection, result) {
				return wire.Error(api.CodeConflict, "worker injection result changed on retry")
			}
			return nil
		}
		marker = bstate.Slot{Schema: "laneboss.credential-slot.v2", Config: s.deps.Config, ID: markerID, Kind: "selection", Fingerprint: selection, Injection: &result, Material: []byte{}, Returned: []byte{}}
		return journal.Write("slot", markerID, marker)
	})
	if err != nil {
		return api.Injection{}, err
	}
	return result, nil
}

func (s *Service) recheckWorkerSelection(ctx context.Context, lease api.WorkerLease, effect api.EffectRecord, grants api.GrantSet) error {
	current, err := s.deps.Store.WorkerLease(ctx, s.deps.ServiceScope, lease.ID)
	if err != nil {
		return err
	}
	if current != lease {
		return wire.Error(api.CodeConflict, "worker lease changed before protected credential preparation")
	}
	fresh, _, err := s.workerSelection(ctx, lease)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(fresh, effect) {
		return wire.Error(api.CodeConflict, "worker credential effect claim changed")
	}
	currentGrants, err := s.currentWorkerGrants(ctx, lease)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(currentGrants, grants) {
		return wire.Error(api.CodeConflict, "worker credential grants changed during preparation")
	}
	return nil
}

func (s *Service) retainedWorkerSpec(ctx context.Context, handoff api.PreparedSpecHandoff, slot bstate.Slot, resolve bool) error {
	return s.retainedWorkerSpecJournal(ctx, handoff, slot, resolve, nil)
}

func (s *Service) retainedWorkerSpecJournal(ctx context.Context, handoff api.PreparedSpecHandoff, slot bstate.Slot, resolve bool, held bstate.Journal) error {
	spec := handoff.Spec
	if slot.WorkerLease == nil || slot.WorkerPlan == nil || spec.Kind != "worker" || spec.Worker == nil || spec.Runner != nil ||
		!reflect.DeepEqual(*spec.Worker, *slot.WorkerPlan) || spec.Target != slot.Target || spec.Grants.ID != slot.GrantSetID || spec.Grants.SHA256 != slot.GrantSHA256 || spec.PolicyGeneration != slot.PolicyGeneration ||
		spec.RuntimeManifest != slot.WorkerLease.RuntimeManifest || !wire.ID(string(spec.ID)) || !wire.ID(string(spec.LaunchID)) || !wire.ID(string(spec.UIDLeaseID)) ||
		!wire.ID(string(spec.Workspace.ID)) || spec.Backend != "linux-bwrap-landlock" && spec.Backend != "darwin-seatbelt" ||
		!slices.Contains(spec.Injection.SlotIDs, slot.ID) || spec.Injection.Target != slot.Target || spec.Workspace.ID == slot.ID ||
		handoff.Config != s.deps.Config || handoff.OperationID != slot.OperationID || handoff.RequestID != slot.RequestID || handoff.Original.Class != "launch_spec" ||
		handoff.Cause.Kind != api.InternalHelperRegister || handoff.Cause.Config != s.deps.Config || handoff.Cause.Actor.Kind != "service" || !wire.ID(string(handoff.Cause.Actor.ID)) ||
		handoff.Cause.CauseOperationID != slot.OperationID || handoff.Cause.CauseRequestID != slot.RequestID || handoff.Cause.Target != slot.Target || handoff.Cause.RequestedBy != slot.RequestedBy || !wire.ID(string(handoff.Cause.EffectID)) {
		return wire.Error(api.CodeForbidden, "worker material differs from the retained fixed job selection")
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	var marker bstate.Slot
	read := func(j bstate.Journal) error {
		return j.Read("slot", credentialID("worker-selection", slot.WorkerLeaseID), &marker)
	}
	if held != nil {
		err = read(held)
	} else {
		err = backend.WithBroker(ctx, read)
	}
	if err != nil {
		return err
	}
	if marker.Injection == nil || !reflect.DeepEqual(*marker.Injection, spec.Injection) {
		return wire.Error(api.CodeForbidden, "worker material injection differs from its exact prepared selection")
	}
	data, err := s.protectedObject(ctx, handoff.Original, slot.OperationID)
	if err != nil {
		return err
	}
	var retained api.LaunchSpec
	if err := api.DecodeObject(data, &retained); err != nil {
		return err
	}
	digest, err := valueDigest(spec)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(retained, spec) || digest != handoff.SpecSHA256 || digest != handoff.Original.SHA256 {
		return wire.Error(api.CodeIntegrity, "worker credential spec bytes changed")
	}
	if !resolve {
		return nil
	}
	if wire.Nil(s.deps.Helper) {
		return wire.Error(api.CodePrerequisite, "worker credentials require the installed runtime resolver")
	}
	resolved, err := s.deps.Helper.ResolveRuntime(ctx, handoff)
	if err != nil {
		return err
	}
	if resolved.SpecReceipt.SpecID != spec.ID || resolved.SpecReceipt.Config != s.deps.Config || resolved.SpecReceipt.OperationID != slot.OperationID || resolved.SpecReceipt.Target != slot.Target || resolved.SpecReceipt.LeaseID != spec.UIDLeaseID ||
		resolved.SpecReceipt.SpecSHA256 != digest || resolved.SpecReceipt.RuntimeManifest != spec.RuntimeManifest || resolved.Manifest.Bootstrap != spec.Worker.Executable || resolved.Workspace != spec.Workspace ||
		resolved.Home.WorkspaceID != spec.Workspace.ID || resolved.Home.ID == slot.ID || resolved.Home.HistoryID == slot.ID {
		return wire.Error(api.CodeForbidden, "worker runtime resolution differs from protected job ownership")
	}
	return nil
}

// PrepareWorkerMaterial is a service-private helper delivery port, not an RPC.
// The installed launch-control source authorizes the complete retained handoff
// and the helper resolves its runtime before this port returns any bytes.
func (s *Service) PrepareWorkerMaterial(ctx context.Context, spec api.LaunchSpec, id api.ID) (api.SecretMaterial, error) {
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
	if slot.Kind != "worker" || slot.Released || slot.WorkerLease == nil || !future(slot.Grant.ExpiresAt, s.deps.Clock.Now()) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "worker material requires its live prepared slot")
	}
	effect, _, err := s.workerSelection(ctx, *slot.WorkerLease)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	grants, err := s.currentWorkerGrants(ctx, *slot.WorkerLease)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if grants.ID != slot.GrantSetID || grants.SHA256 != slot.GrantSHA256 || !reflect.DeepEqual(grants, spec.Grants) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "worker material grants changed")
	}
	if wire.Nil(s.deps.Control) {
		return api.SecretMaterial{}, wire.Error(api.CodePrerequisite, "worker credentials require installed launch control")
	}
	handoff, err := s.deps.Control.Handoff(ctx, spec)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if !reflect.DeepEqual(handoff.Spec, spec) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "worker material handoff differs from the retained spec")
	}
	if err := s.retainedWorkerSpec(ctx, handoff, slot, true); err != nil {
		return api.SecretMaterial{}, err
	}
	var material api.SecretMaterial
	err = backend.WithBroker(ctx, func(j bstate.Journal) error {
		if err := s.recheckWorkerSelection(ctx, *slot.WorkerLease, effect, grants); err != nil {
			return err
		}
		var current bstate.Slot
		if err := j.Read("slot", id, &current); err != nil {
			return err
		}
		defer clear(current.Material)
		defer clear(current.Returned)
		if current.Released || current.Fingerprint != slot.Fingerprint || current.Handoff != nil && !reflect.DeepEqual(*current.Handoff, handoff) {
			return wire.Error(api.CodeConflict, "worker material retry changed its retained launch handoff")
		}
		if err := s.deliveryPolicy(ctx, j, current); err != nil {
			return err
		}
		source, err := j.Fetch(ctx, current.Grant)
		if err != nil {
			return err
		}
		clear(source.Bytes)
		material.Bytes = append([]byte(nil), current.Material...)
		if current.Handoff != nil {
			return nil
		}
		current.Handoff, current.LaunchID, current.HelperLeaseID, current.Backend = &handoff, spec.LaunchID, spec.UIDLeaseID, spec.Backend
		return j.Write("slot", id, current)
	})
	if err != nil {
		clear(material.Bytes)
		return api.SecretMaterial{}, err
	}
	return material, nil
}

func (s *Service) workerSlotBinding(ctx context.Context, slot bstate.Slot, binding api.LaunchBindingRequest) error {
	if slot.Handoff == nil || slot.WorkerLease == nil {
		return wire.Error(api.CodeIntegrity, "worker credential cleanup has no retained launch spec")
	}
	spec := slot.Handoff.Spec
	// Cleanup rechecks immutable bytes, not a new live execution claim.
	if err := s.retainedWorkerSpec(ctx, *slot.Handoff, slot, false); err != nil {
		return err
	}
	if binding.Record.Kind != "worker" || binding.Record.Revoked || binding.Record.Actor.Kind != "worker" || binding.Record.Actor.Level != 0 || binding.Record.Actor.Role != "" || !wire.ID(string(binding.Record.Actor.ID)) || binding.Record.HostUID == 0 || binding.Record.ID != slot.LaunchID || binding.Record.Config != s.deps.Config || binding.Record.Target != slot.Target || binding.Record.UIDLeaseID != slot.HelperLeaseID ||
		binding.Record.GrantSetID != slot.GrantSetID || binding.Record.GrantsSHA256 != slot.GrantSHA256 || binding.Record.PolicyGeneration != slot.PolicyGeneration ||
		binding.Record.ContainmentID != binding.Prepared.ContainmentID || binding.Prepared.Target != slot.Target || binding.Record.ProcessGeneration != binding.Prepared.ProcessGeneration ||
		binding.Identity.LaunchID != slot.LaunchID || binding.Identity.CommittedSeq == 0 || !wire.ID(string(binding.Identity.EventID)) || binding.Prepared.SpecSHA256 != slot.Handoff.SpecSHA256 ||
		binding.Record.EndpointGeneration != spec.EndpointGeneration || binding.Prepared.EndpointGeneration != spec.EndpointGeneration {
		return wire.Error(api.CodeForbidden, "worker credential cleanup differs from its retained job binding")
	}
	digest, err := valueDigest(binding.Record)
	if err != nil {
		return err
	}
	if digest != binding.Identity.RecordSHA256 {
		return wire.Error(api.CodeIntegrity, "worker credential identity digest differs")
	}
	return nil
}
