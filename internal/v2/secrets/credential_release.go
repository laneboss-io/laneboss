package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func (s *Service) slotBinding(ctx context.Context, slot bstate.Slot) (api.LaunchBindingRequest, api.LaunchPlan, error) {
	var plan api.LaunchPlan
	binding, err := s.deps.Store.LaunchBinding(ctx, slot.LaunchID)
	if err != nil {
		return binding, plan, err
	}
	if slot.Kind == "worker" {
		return binding, plan, s.workerSlotBinding(ctx, slot, binding)
	}
	if binding.Recovery == nil {
		return binding, plan, wire.Error(api.CodeIntegrity, "credential cleanup has no retained launch recovery binding")
	}
	record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, binding.Recovery.PlanID)
	if err != nil {
		return binding, plan, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return binding, plan, err
	}
	if record.Plan == nil || record.Handoff == nil {
		return binding, plan, wire.Error(api.CodeIntegrity, "credential cleanup has no complete retained launch plan")
	}
	plan = *record.Plan
	if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {
		return binding, plan, err
	}
	if binding.Record.ID != slot.LaunchID || binding.Record.Target != slot.Target || binding.Record.UIDLeaseID != slot.HelperLeaseID || binding.Record.Config != slot.Config ||
		plan.Reservation.ID != slot.ReservationID || plan.Reservation.OperationID != slot.OperationID || plan.Inputs.Grants.ID != slot.GrantSetID || plan.Inputs.Grants.SHA256 != slot.GrantSHA256 ||
		!slices.Contains(plan.Injection.SlotIDs, slot.ID) || slot.ID == plan.Data.Home.RootID || slot.ID == plan.Data.Home.Home.ID || slot.ID == plan.Data.Home.Home.HistoryID {
		return binding, plan, wire.Error(api.CodeForbidden, "credential slot differs from its retained launch binding")
	}
	return binding, plan, nil
}

// The same journal transaction must check the latest projection and write its
// release tombstone. The earlier helper measurement cannot reserve this field.
func (s *Service) releaseProjectionLocked(ctx context.Context, journal bstate.Journal, before, current bstate.Slot) error {
	if current.ProjectionID != before.ProjectionID {
		return wire.Error(api.CodeConflict, "credential projection changed during measured cleanup")
	}
	return s.projectionReleasedLocked(ctx, journal, current)
}

func (s *Service) measuredRelease(ctx context.Context, slot bstate.Slot, claim api.ProcessObservation) error {
	if err := s.projectionReleased(ctx, slot); err != nil {
		return err
	}
	binding, _, err := s.slotBinding(ctx, slot)
	if err != nil {
		return err
	}
	if claim.Handle.Target != slot.Target || claim.Handle.ContainmentID != binding.Record.ContainmentID || claim.Handle.Generation != binding.Record.ProcessGeneration {
		return wire.Error(api.CodeContainmentUnknown, "credential cleanup observation differs from the retained process generation")
	}
	if retained, err := s.retainedRelease(ctx, slot, claim); err != nil {
		return err
	} else if retained {
		return nil
	}
	if wire.Nil(s.deps.Helper) || wire.Nil(s.deps.Control) {
		return wire.Error(api.CodePrerequisite, "credential cleanup requires installed helper and launch control source")
	}
	actual, err := s.deps.Helper.ObserveGate(ctx, api.HelperObserveRequest{LeaseID: slot.HelperLeaseID, Handle: claim.Handle})
	if err != nil {
		return err
	}
	if err := quiescent(ctx, actual, slot.Target); err != nil {
		return err
	}
	if actual.Handle != claim.Handle || actual.State != claim.State || !reflect.DeepEqual(actual.ExitCode, claim.ExitCode) || !reflect.DeepEqual(actual.Signal, claim.Signal) || !reflect.DeepEqual(actual.Survivors, claim.Survivors) {
		return wire.Error(api.CodeContainmentUnknown, "credential cleanup claim disagrees with the independently observed containment")
	}
	request, err := s.deps.Control.Release(ctx, slot.HelperLeaseID, actual)
	if err != nil {
		return err
	}
	if request.LeaseID != slot.HelperLeaseID || request.Observation.Handle != actual.Handle || request.Cause.Kind != api.InternalHelperRelease || request.Cause.Config != s.deps.Config ||
		request.Cause.Target != slot.Target || request.Cause.Actor.Kind != "service" || !wire.ID(string(request.Cause.Actor.ID)) || !wire.ID(string(request.Cause.CauseOperationID)) || !wire.ID(string(request.Cause.EffectID)) {
		return wire.Error(api.CodeForbidden, "credential release differs from its current helper effect claim")
	}
	receipt, err := s.deps.Helper.Release(ctx, request)
	if err != nil {
		return err
	}
	if err := api.ValidateReleaseReceipt(receipt); err != nil {
		return err
	}
	if receipt.LeaseID != slot.HelperLeaseID || receipt.ContainmentID != binding.Record.ContainmentID || receipt.Backend != slot.Backend ||
		receipt.OperationID != request.Cause.CauseOperationID || receipt.EffectID != request.Cause.EffectID || receipt.Quiescence.Handle != actual.Handle ||
		!reflect.DeepEqual(receipt.Quiescence.ExitCode, actual.ExitCode) || !reflect.DeepEqual(receipt.Quiescence.Signal, actual.Signal) {
		return wire.Error(api.CodeContainmentUnknown, "helper release receipt differs from the retained credential containment")
	}
	if err := s.deps.Control.RecordRelease(ctx, request, receipt); err != nil {
		return err
	}
	// Read back the actual stored receipt; a successful dependency return alone
	// is not evidence of a committed helper measurement.
	query := api.EventTailRequest{LifeID: slot.Target.LifeID, Run: slot.Target.Run}
	for page := 0; page < 256; page++ {
		events, err := s.deps.Store.Events(ctx, s.deps.ServiceScope, query)
		if err != nil {
			return err
		}
		for _, event := range events.Events {
			if event.Kind != "helper.released" || event.OperationID != receipt.OperationID {
				continue
			}
			var measured api.ReleaseReceipt
			if err := api.DecodeObject(event.Payload, &measured); err != nil {
				return err
			}
			if reflect.DeepEqual(measured, receipt) && event.Seq > 0 && event.Config == s.deps.Config && event.Actor == request.Cause.Actor && event.RequestedBy == request.Cause.RequestedBy && event.RequestID == request.Cause.CauseRequestID && event.LifeID == slot.Target.LifeID && event.Run == slot.Target.Run {
				return nil
			}
		}
		if events.Complete {
			break
		}
		if events.Cursor == "" || events.Cursor == query.Cursor {
			return wire.Error(api.CodeIntegrity, "helper release event cursor did not advance")
		}
		query.Cursor = events.Cursor
	}
	return wire.Error(api.CodeIntegrity, "credential cleanup has no committed helper-measured release receipt")
}

func validateRefresh(profile bstate.Profile, original, updated []byte, now time.Time) error {
	if profile.Mode != "file_login" || len(updated) == 0 || len(updated) > wire.MaxMaterial {
		return wire.Error(api.CodeForbidden, "only an issued file-login slot can return bounded refresh material")
	}
	var before, after map[string]json.RawMessage
	one, err := api.CanonicalJSON(original)
	if err != nil {
		return err
	}
	two, err := api.CanonicalJSON(updated)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(one, &before); err != nil || len(before) == 0 {
		return wire.Error(api.CodeInvalid, "enrolled file login must be a nonempty JSON object")
	}
	if err := json.Unmarshal(two, &after); err != nil || len(after) == 0 {
		return wire.Error(api.CodeInvalid, "refreshed file login must be a nonempty JSON object")
	}
	for key, prior := range before {
		current, ok := after[key]
		if !ok {
			return wire.Error(api.CodeForbidden, "refreshed login removed an enrolled field")
		}
		if slices.Contains(profile.RefreshFields, key) {
			continue
		}
		one, err := api.CanonicalJSON(prior)
		if err != nil {
			return err
		}
		two, err := api.CanonicalJSON(current)
		if err != nil {
			return err
		}
		if !bytes.Equal(one, two) {
			return wire.Error(api.CodeForbidden, "refreshed login changed a non-refresh identity field")
		}
	}
	for key, value := range after {
		if !slices.Contains(profile.RefreshFields, key) {
			if _, ok := before[key]; !ok {
				return wire.Error(api.CodeForbidden, "refreshed login added an unsupported field")
			}
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil || text == "" || len(text) > wire.MaxMaterial {
			return wire.Error(api.CodeForbidden, "refreshed login field has an unsupported representation")
		}
		if key == "expires_at" {
			expires, err := time.Parse(time.RFC3339Nano, text)
			if err != nil || !strings.HasSuffix(text, "Z") || !now.Before(expires) {
				return wire.Error(api.CodeForbidden, "refreshed login expiry is invalid or already elapsed")
			}
		}
	}
	return nil
}

func (s *Service) releaseCredential(ctx context.Context, request api.CredentialSlot, observation api.ProcessObservation) error {
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	var slot bstate.Slot
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", request.ID, &slot) }); err != nil {
		return err
	}
	defer clear(slot.Material)
	defer clear(slot.Returned)
	if slot.Kind != "profile" || slot.Credential != request || slot.Config != s.deps.Config || slot.Target != observation.Handle.Target {
		return wire.Error(api.CodeForbidden, "credential release differs from an issued run-scoped slot")
	}
	if _, _, err := s.slotBinding(ctx, slot); err != nil {
		return err
	}
	if err := s.measuredRelease(ctx, slot, observation); err != nil {
		return err
	}
	return backend.WithBroker(ctx, func(j bstate.Journal) error {
		b := &stagedJournal{Journal: j}
		defer b.clear()
		if err := s.releaseSlotLocked(ctx, b, slot); err != nil {
			return err
		}
		return b.flush("")
	})
}
func (s *Service) releaseSlotLocked(ctx context.Context, journal bstate.Journal, slot bstate.Slot) error {
	var current bstate.Slot
	if err := journal.Read("slot", slot.ID, &current); err != nil {
		return err
	}
	defer clear(current.Material)
	defer clear(current.Returned)
	if err := s.releaseProjectionLocked(ctx, journal, slot, current); err != nil {
		return err
	}
	if current.Fingerprint != slot.Fingerprint || current.Credential != slot.Credential {
		return wire.Error(api.CodeConflict, "credential slot changed during measured cleanup")
	}
	if current.Released {
		if current.Credential.Mode == "file_login" {
			var owner bstate.Login
			if err := journal.Read("login", current.LoginID, &owner); err != nil {
				return err
			}
			defer clear(owner.Material)
			if owner.SlotID == current.ID {
				owner.SlotID = ""
				owner.PendingRelease = ""
				return journal.Write("login", owner.ID, owner)
			}
		}
		return nil
	}
	if current.Credential.Mode == "file_login" {
		var profile bstate.Profile
		if err := journal.Read("profile", current.ProfileID, &profile); err != nil {
			return err
		}
		if profile.Generation != current.ProfileGeneration || profile.LoginID != current.LoginID {
			return wire.Error(api.CodeConflict, "login enrollment changed during its refresh lease")
		}
		var owner bstate.Login
		if err := journal.Read("login", current.LoginID, &owner); err != nil {
			return err
		}
		defer func() { clear(owner.Material) }()
		if owner.ID != current.LoginID || owner.SlotID != current.ID {
			return wire.Error(api.CodeConflict, "refresh lease has another canonical-login owner")
		}
		owner.PendingRelease = current.ID
		if err := journal.Write("login", owner.ID, owner); err != nil {
			return err
		}
		if len(current.Returned) > 0 {
			if err := validateRefresh(profile, current.Material, current.Returned, s.deps.Clock.Now()); err != nil {
				return err
			}
			if owner.RefreshSlotID == current.ID {
				if !bytes.Equal(owner.Material, current.Returned) {
					return wire.Error(api.CodeConflict, "canonical refresh replay changed its returned bytes")
				}
			} else {
				clear(owner.Material)
				owner.Material = append([]byte(nil), current.Returned...)
				owner.Generation++
				owner.RefreshSlotID = current.ID
				// Canonical refresh is encrypted broker state. It must not
				// create an uncommitted public secret mutation/version.
				if err := journal.Write("login", current.LoginID, owner); err != nil {
					return err
				}
			}
		}
		// The tombstone precedes freeing ownership. A restart can finish
		// freeing this exact owner, never hand out a second live copy.
		clear(current.Material)
		clear(current.Returned)
		current.Material, current.Returned = []byte{}, []byte{}
		current.Released = true
		if err := journal.Write("slot", current.ID, current); err != nil {
			return err
		}
		owner.SlotID = ""
		owner.PendingRelease = ""
		return journal.Write("login", current.LoginID, owner)
	}
	clear(current.Material)
	clear(current.Returned)
	current.Material, current.Returned = []byte{}, []byte{}
	current.Released = true
	return journal.Write("slot", current.ID, current)
}

func (s *Service) releaseInjection(ctx context.Context, injection api.Injection, observation api.ProcessObservation) error {
	if len(injection.SlotIDs) == 0 || len(injection.SlotIDs) > 257 {
		return wire.Error(api.CodeInvalid, "injection cleanup requires its complete bounded slot selection")
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	slots := []bstate.Slot{}
	defer func() { clearProjectionSlots(slots) }()
	seen := map[api.ID]bool{}
	for _, id := range injection.SlotIDs {
		if !wire.ID(string(id)) || seen[id] {
			return wire.Error(api.CodeInvalid, "injection cleanup contains invalid or duplicate slots")
		}
		seen[id] = true
		var slot bstate.Slot
		if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", id, &slot) }); err != nil {
			return err
		}
		slots = append(slots, slot)
		if slot.Target != injection.Target || slot.Config != s.deps.Config {
			return wire.Error(api.CodeForbidden, "injection cleanup contains a foreign slot")
		}
		_, plan, err := s.slotBinding(ctx, slot)
		if err != nil {
			return err
		}
		expected := plan.Injection
		if slot.Kind == "worker" {
			if slot.Handoff == nil {
				return wire.Error(api.CodeIntegrity, "worker injection lost its retained spec")
			}
			expected = slot.Handoff.Spec.Injection
		}
		if !reflect.DeepEqual(expected, injection) {
			return wire.Error(api.CodeForbidden, "injection cleanup differs from the exact retained selection")
		}
	}
	// No tombstone or canonical release is staged until every measurement passes.
	for _, slot := range slots {
		if err := s.measuredRelease(ctx, slot, observation); err != nil {
			return err
		}
	}
	return backend.WithBroker(ctx, func(j bstate.Journal) error {
		staged := &stagedJournal{Journal: j}
		defer staged.clear()
		for _, slot := range slots {
			if err := s.releaseSlotLocked(ctx, staged, slot); err != nil {
				return err
			}
		}
		return staged.flush("")
	})
}

func (s *Service) retainedRelease(ctx context.Context, slot bstate.Slot, claim api.ProcessObservation) (bool, error) {
	query := api.EventTailRequest{LifeID: slot.Target.LifeID, Run: slot.Target.Run}
	for page := 0; page < 256; page++ {
		events, err := s.deps.Store.Events(ctx, s.deps.ServiceScope, query)
		if err != nil {
			return false, err
		}
		for _, event := range events.Events {
			if event.Kind != "helper.released" || event.Config != slot.Config || event.LifeID != slot.Target.LifeID || event.Run != slot.Target.Run || event.Actor.Kind != "service" {
				continue
			}
			var receipt api.ReleaseReceipt
			if err := api.DecodeObject(event.Payload, &receipt); err != nil {
				return false, err
			}
			if receipt.LeaseID != slot.HelperLeaseID {
				continue
			}
			if err := api.ValidateReleaseReceipt(receipt); err != nil {
				return false, err
			}
			if event.Seq > 0 && wire.ID(string(event.RequestID)) && wire.ID(string(event.Actor.ID)) && wire.ID(string(event.RequestedBy.ID)) && receipt.OperationID == event.OperationID && receipt.ContainmentID == claim.Handle.ContainmentID && receipt.Quiescence.Handle == claim.Handle && receipt.Backend == slot.Backend &&
				reflect.DeepEqual(receipt.Quiescence.ExitCode, claim.ExitCode) && reflect.DeepEqual(receipt.Quiescence.Signal, claim.Signal) && reflect.DeepEqual(receipt.Quiescence.Survivors, claim.Survivors) {
				return true, nil
			}
		}
		if events.Complete {
			return false, nil
		}
		if events.Cursor == "" || events.Cursor == query.Cursor {
			return false, wire.Error(api.CodeIntegrity, "retained release cursor did not advance")
		}
		query.Cursor = events.Cursor
	}
	return false, wire.Error(api.CodeBudget, "retained helper release lookup exceeds its bound")
}

// SlotMaterial is a service-private material port for the fixed credential
// worker/helper adapter. No RPC, path, arbitrary executable or descriptor is
// accepted. The retained binding and exact selected slot are reloaded here.
func (s *Service) SlotMaterial(ctx context.Context, launchID, id api.ID) (api.SecretMaterial, error) {
	backend, err := s.brokerBackend()
	if err != nil {
		return api.SecretMaterial{}, err
	}
	var slot bstate.Slot
	err = backend.WithBroker(ctx, func(journal bstate.Journal) error { return journal.Read("slot", id, &slot) })
	if err != nil {
		return api.SecretMaterial{}, err
	}
	defer clear(slot.Material)
	defer clear(slot.Returned)
	if slot.Released || slot.LaunchID != launchID {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "credential material is absent for this retained launch")
	}
	_, retainedPlan, err := s.slotBinding(ctx, slot)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	var current api.GrantSet
	if slot.Kind == "worker" {
		if slot.WorkerLease == nil {
			return api.SecretMaterial{}, wire.Error(api.CodeIntegrity, "worker material lost its retained lease")
		}
		current, err = s.currentWorkerGrants(ctx, *slot.WorkerLease)
	} else {
		current, err = s.currentGrants(ctx, slot.Target)
	}
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if current.ID != slot.GrantSetID || current.SHA256 != slot.GrantSHA256 {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "credential material grant binding is no longer current")
	}
	if slot.Kind == "profile" {
		if !future(slot.Credential.ExpiresAt, s.deps.Clock.Now()) {
			return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "credential slot expired before material delivery")
		}
		found := false
		for _, grant := range current.Profiles {
			if grant.ID == slot.Credential.ProfileGrantID && grant.ProfileID == slot.ProfileID {
				if err := validateProfile(grant, s.deps.Clock.Now()); err != nil {
					return api.SecretMaterial{}, err
				}
				found = true
			}
		}
		if !found {
			return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "profile slot is no longer delegated")
		}
	} else {
		if err := validateGrant(slot.Grant, s.deps.Clock.Now()); err != nil {
			return api.SecretMaterial{}, err
		}
		if !slices.Contains(current.Secrets, slot.Grant) {
			return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "task slot is no longer delegated")
		}
	}
	var material api.SecretMaterial
	err = backend.WithBroker(ctx, func(j bstate.Journal) error {
		var latest bstate.Slot
		if err := j.Read("slot", id, &latest); err != nil {
			return err
		}
		defer clear(latest.Material)
		defer clear(latest.Returned)
		if latest.Released || latest.Fingerprint != slot.Fingerprint || latest.LaunchID != launchID {
			return wire.Error(api.CodeConflict, "bound credential slot changed during material delivery")
		}
		var fresh api.GrantSet
		if slot.Kind == "worker" {
			fresh, err = s.currentWorkerGrants(ctx, *slot.WorkerLease)
		} else {
			fresh, err = s.currentGrants(ctx, slot.Target)
		}
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(fresh, current) {
			return wire.Error(api.CodeConflict, "credential grants changed before bound material delivery")
		}
		deliverySlot := latest
		if latest.Kind == "task" {
			deliverySlot.ProfileID = retainedPlan.Runner.Slot.ProfileID
		}
		if err := s.deliveryPolicy(ctx, j, deliverySlot); err != nil {
			return err
		}
		if err := validateGrant(latest.Grant, s.deps.Clock.Now()); err != nil {
			return err
		}
		if latest.Kind != "profile" && !slices.Contains(fresh.Secrets, latest.Grant) {
			return wire.Error(api.CodeForbidden, "credential source is no longer delegated")
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

func (s *Service) ReturnSlot(ctx context.Context, launchID, id api.ID, material api.SecretMaterial) error {
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	var slot bstate.Slot
	if err := backend.WithBroker(ctx, func(journal bstate.Journal) error { return journal.Read("slot", id, &slot) }); err != nil {
		return err
	}
	defer clear(slot.Material)
	defer clear(slot.Returned)
	if slot.Released || slot.LaunchID != launchID || slot.Credential.Mode != "file_login" {
		return wire.Error(api.CodeForbidden, "refresh return requires the original live file-login slot")
	}
	if _, _, err := s.slotBinding(ctx, slot); err != nil {
		return err
	}
	return backend.WithBroker(ctx, func(journal bstate.Journal) error {
		var current bstate.Slot
		if err := journal.Read("slot", id, &current); err != nil {
			return err
		}
		defer clear(current.Material)
		defer clear(current.Returned)
		if current.Released || current.Fingerprint != slot.Fingerprint {
			return wire.Error(api.CodeConflict, "refresh return slot binding changed")
		}
		var profile bstate.Profile
		if err := journal.Read("profile", current.ProfileID, &profile); err != nil {
			return err
		}
		if profile.Generation != current.ProfileGeneration || profile.LoginID != current.LoginID {
			return wire.Error(api.CodeConflict, "refresh return enrollment changed during its lease")
		}
		var owner bstate.Login
		if err := journal.Read("login", current.LoginID, &owner); err != nil {
			return err
		}
		defer clear(owner.Material)
		if owner.ID != current.LoginID || owner.SlotID != current.ID {
			return wire.Error(api.CodeConflict, "refresh return has another canonical owner")
		}
		if err := validateRefresh(profile, current.Material, material.Bytes, s.deps.Clock.Now()); err != nil {
			return err
		}
		current.Returned = append([]byte(nil), material.Bytes...)
		defer clear(current.Returned)
		return journal.Write("slot", id, current)
	})
}
