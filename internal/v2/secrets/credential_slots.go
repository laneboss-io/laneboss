package secrets

import (
	"context"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func slotID(launch credentialLaunch, kind string, id api.ID) api.ID {
	if kind == "task" {
		return api.AgentTaskSlotID(launch.record.Reservation.ID, id)
	}
	return credentialID(kind, launch.record.Reservation.ID, id)
}
func slotFingerprint(launch credentialLaunch, value any) (api.Digest, error) {
	return valueDigest(struct {
		Reservation api.LaunchReservation
		Inputs      api.LaunchInputs
		Storage     api.LaunchStorage
		Value       any
	}{launch.record.Reservation, *launch.record.Inputs, launch.storage, value})
}
func newSlot(launch credentialLaunch, kind string, id api.ID, fingerprint api.Digest) bstate.Slot {
	r := launch.record.Reservation
	return bstate.Slot{Schema: "laneboss.credential-slot.v2", Config: r.Config, ID: id, Kind: kind, Target: r.Target, ReservationID: r.ID, LaunchID: r.LaunchID, HelperLeaseID: launch.helperLeaseID, PlanningClaim: api.StablePlanningPin(r.ID, launch.effect.Effect.ID), Backend: launch.record.Inputs.Sources.Runtime.Backend,
		OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, GrantSetID: r.GrantSetID, GrantSHA256: launch.record.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, Fingerprint: fingerprint, Material: []byte{}, Returned: []byte{}}
}
func slotIsPrivate(slot bstate.Slot, launch credentialLaunch) bool {
	home := launch.storage.Home
	return slot.ID != home.RootID && slot.ID != home.Home.ID && slot.ID != home.Home.HistoryID && slot.ID != launch.storage.WorkspaceID &&
		slot.HelperLeaseID == launch.helperLeaseID && slot.Target == launch.record.Reservation.Target && slot.Config == launch.record.Reservation.Config
}

// VerifyRunnerSlot is the existing per-run enrollment guard's private broker
// read. It creates no slot, material projection, refresh owner or native proof.
func (s *Service) VerifyRunnerSlot(ctx context.Context, claim api.LaunchClaim, request api.RunnerRequest) (api.LaunchStorage, error) {
	var empty api.LaunchStorage
	if err := wire.Context(ctx); err != nil {
		return empty, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return empty, err
	}
	var saved bstate.Slot
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", request.Slot.ID, &saved) }); err != nil {
		return empty, err
	}
	defer clear(saved.Material)
	defer clear(saved.Returned)
	if saved.Schema != "laneboss.credential-slot.v2" || saved.Config != s.deps.Config || saved.Kind != "profile" || saved.Released || saved.Credential != request.Slot || saved.Target != request.Target || !future(saved.Credential.ExpiresAt, s.deps.Clock.Now()) || saved.ReservationID != claim.ReservationID || saved.PlanningClaim != api.StablePlanningPin(claim.ReservationID, claim.EffectID) {
		return empty, wire.Error(api.CodeForbidden, "runner slot has no exact live broker enrollment")
	}
	selection := launchSelection{Claim: claim, HelperLeaseID: saved.HelperLeaseID}
	current, err := s.selectedGrants(ctx, request.Target, selection)
	if err != nil {
		return empty, err
	}
	launch, err := s.credentialLaunch(ctx, request.Target, current, selection)
	if err != nil {
		return empty, err
	}
	r := launch.record.Reservation
	if saved.LaunchID != r.LaunchID || saved.OperationID != r.OperationID || saved.RequestID != r.RequestID || saved.RequestedBy != r.RequestedBy || saved.GrantSetID != r.GrantSetID || saved.GrantSHA256 != current.SHA256 || saved.PolicyGeneration != r.PolicyGeneration || !slotIsPrivate(saved, launch) || launch.storage.Home.Home != request.Home || launch.model != request.Model || launch.record.Inputs.Sources.Runtime.Executable != request.Executable {
		return empty, wire.Error(api.CodeConflict, "runner slot differs from the original run or private home")
	}
	var selected *api.ProfileGrant
	for n := range current.Profiles {
		if current.Profiles[n].ID == launch.profile {
			selected = &current.Profiles[n]
		}
	}
	if selected == nil || selected.ID != request.Slot.ProfileGrantID || selected.ProfileID != saved.ProfileID {
		return empty, wire.Error(api.CodeForbidden, "runner slot profile is no longer delegated")
	}
	profile, err := s.loadProfile(ctx, *selected)
	if err != nil {
		return empty, err
	}
	// The slot carries publicSlotMode(profile) ("codex-api" or "claudock-helper" for a helper profile), not the
	// profile's raw mode; comparing the raw mode refused every helper profile (boxes 39-42).
	if profile.Generation != saved.ProfileGeneration || profile.LoginID != saved.LoginID || publicSlotMode(profile) != request.Slot.Mode || profile.Runtime != request.Executable || !slices.Contains(profile.Models, request.Model) {
		return empty, wire.Error(api.CodeConflict, "runner slot protected profile enrollment changed")
	}
	fingerprint, err := slotFingerprint(launch, struct {
		Grant   api.ProfileGrant
		Profile bstate.Profile
	}{*selected, profile})
	if err != nil {
		return empty, err
	}
	if fingerprint != saved.Fingerprint {
		return empty, wire.Error(api.CodeConflict, "runner slot fingerprint changed")
	}
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error {
		var actual bstate.Slot
		if err := j.Read("slot", saved.ID, &actual); err != nil {
			return err
		}
		defer clear(actual.Material)
		defer clear(actual.Returned)
		if !reflect.DeepEqual(actual, saved) {
			return wire.Error(api.CodeConflict, "runner slot changed during enrollment read")
		}
		var latest bstate.Profile
		if err := j.Read("profile", profile.ID, &latest); err != nil {
			return err
		}
		if !reflect.DeepEqual(latest, profile) {
			return wire.Error(api.CodeConflict, "runner profile changed during enrollment read")
		}
		if saved.Credential.Mode == "codex-file" || saved.Credential.Mode == "file_login" {
			var owner bstate.Login
			if err := j.Read("login", saved.LoginID, &owner); err != nil {
				clear(owner.Material)
				return err
			}
			clear(owner.Material)
			if owner.Quarantined || owner.PendingRelease != "" || owner.SlotID != saved.ID || owner.Source == nil || *owner.Source != saved.Grant {
				return wire.Error(api.CodeForbidden, "runner canonical login owner is collecting or changed")
			}
		}
		material, err := j.Fetch(ctx, saved.Grant)
		clear(material.Bytes)
		if err != nil {
			return err
		}
		return s.recheckCredentialLaunch(ctx, launch)
	}); err != nil {
		return empty, err
	}
	return launch.storage, nil
}

func (s *Service) acquireProfile(ctx context.Context, target api.LifeRef, grant api.ProfileGrant, current api.GrantSet, selection launchSelection) (api.CredentialSlot, error) {
	backend, err := s.brokerBackend()
	if err != nil {
		return api.CredentialSlot{}, err
	}
	for {
		if err := wire.Context(ctx); err != nil {
			return api.CredentialSlot{}, err
		}
		launch, err := s.credentialLaunch(ctx, target, current, selection)
		if err != nil {
			return api.CredentialSlot{}, err
		}
		if launch.profile != grant.ID {
			return api.CredentialSlot{}, wire.Error(api.CodeForbidden, "credential profile was not selected by the retained launch request")
		}
		profile, err := s.loadProfile(ctx, grant)
		if err != nil {
			return api.CredentialSlot{}, err
		}
		policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
		if err != nil {
			return api.CredentialSlot{}, err
		}
		if slices.Contains(policy.ProfileExclusions, profile.ID) {
			return api.CredentialSlot{}, wire.Error(api.CodeForbidden, "credential launch selects an excluded profile")
		}
		if profile.Runtime != launch.record.Inputs.Sources.Runtime.Executable || !slices.Contains(profile.Models, launch.model) {
			return api.CredentialSlot{}, wire.Error(api.CodeForbidden, "credential profile does not support the enrolled runtime or exact model")
		}
		room, err := s.acquisitionRoom(ctx, launch, grant, profile)
		if err != nil {
			return api.CredentialSlot{}, err
		}
		if !room.Available {
			return api.CredentialSlot{}, wire.Error(api.CodeUnavailable, "selected enrolled profile has no authenticated room")
		}
		id := slotID(launch, "profile", grant.ID)
		fingerprint, err := slotFingerprint(launch, struct {
			Grant   api.ProfileGrant
			Profile bstate.Profile
		}{grant, profile})
		if err != nil {
			return api.CredentialSlot{}, err
		}
		var result api.CredentialSlot
		busy := false
		markerID := credentialID("profile-bind", id)
		err = s.withPreparedBind(ctx, backend, markerID, func() bstate.Slot {
			var done *api.Injection
			if result.ID != "" {
				done = &api.Injection{Target: target, SlotIDs: []api.ID{result.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}
			}
			return s.bindMarker(markerID, fingerprint, done)
		}, func(journal bstate.Journal) error {
			if err := s.recheckCredentialLaunch(ctx, launch); err != nil {
				return err
			}
			var latest bstate.Profile
			if err := journal.Read("profile", profile.ID, &latest); err != nil {
				return err
			}
			if !reflect.DeepEqual(latest, profile) {
				return wire.Error(api.CodeConflict, "profile enrollment changed before slot acquisition")
			}
			var retained bstate.Slot
			if err := journal.Read("slot", id, &retained); err == nil {
				defer clear(retained.Material)
				defer clear(retained.Returned)
				if retained.Released || retained.Fingerprint != fingerprint || retained.Credential.ProfileGrantID != grant.ID || !slotIsPrivate(retained, launch) {
					return wire.Error(api.CodeConflict, "credential slot retry differs from its retained binding")
				}
				if !future(retained.Credential.ExpiresAt, s.deps.Clock.Now()) {
					return wire.Error(api.CodeForbidden, "credential slot retry expired")
				}
				if retained.Credential.Mode == "file_login" || retained.Credential.Mode == "codex-file" {
					var owner bstate.Login
					if err := journal.Read("login", retained.LoginID, &owner); err != nil {
						clear(owner.Material)
						return err
					}
					clear(owner.Material)
					if owner.Quarantined || owner.PendingRelease != "" || owner.SlotID != retained.ID {
						return wire.Error(api.CodeForbidden, "credential retry canonical owner is quarantined or collecting")
					}
				}
				source, err := journal.Fetch(ctx, retained.Grant)
				clear(source.Bytes)
				if err != nil {
					return err
				}
				result = retained.Credential
				return nil
			} else if !hasCode(err, api.CodeNotFound) {
				return err
			}
			source := profile.Source
			var canonical []byte
			defer func() { clear(canonical) }()
			if profile.Mode == "file_login" || profile.Mode == "codex-file" {
				var owner bstate.Login
				if err := journal.Read("login", profile.LoginID, &owner); err == nil {
					if owner.ID != profile.LoginID || owner.Driver != profile.Driver || owner.Provider != profile.Provider || owner.Source == nil || owner.Source.Name != profile.Source.Name {
						return wire.Error(api.CodeIntegrity, "refresh ownership differs from its canonical login")
					}
					if owner.Quarantined || owner.PendingRelease != "" {
						return wire.Error(api.CodeForbidden, "canonical credential is quarantined pending protected rotation")
					}
					if owner.ProjectionID != "" {
						var projection bstate.Projection
						if err := journal.Read("projection", owner.ProjectionID, &projection); err != nil {
							return err
						}
						record, err := s.deps.Store.CredentialProjection(ctx, s.deps.Config, projection.Authority.Request.Prepared.ID)
						if err != nil {
							return err
						}
						if record.Authority.ID != owner.ProjectionID || record.State != "withdrawn" || record.Withdrawal == nil {
							busy = true
							return nil
						}
						owner.ProjectionID = ""
					}
					source = *owner.Source
					canonical = owner.Material
					if err := validateGrant(source, s.deps.Clock.Now()); err != nil {
						return err
					}
					if owner.SlotID != "" && owner.SlotID != id {
						var prior bstate.Slot
						if err := journal.Read("slot", owner.SlotID, &prior); err != nil {
							if hasCode(err, api.CodeNotFound) {
								busy = true
								return nil
							}
							return err
						}
						defer clear(prior.Material)
						defer clear(prior.Returned)
						if !prior.Released {
							busy = true
							return nil
						}
						if _, _, err := s.slotBinding(ctx, prior); err != nil {
							return err
						}
					}
				} else {
					return err
				}
				// Ownership precedes the material copy. An interrupted owner is
				// reconciled only by this exact reservation, never by expiry.
				owner.SlotID = id
				if err := journal.Write("login", profile.LoginID, owner); err != nil {
					return err
				}
			}
			material, err := journal.Fetch(ctx, source)
			if err != nil {
				return err
			}
			defer clear(material.Bytes)
			if len(canonical) > 0 {
				clear(material.Bytes)
				material.Bytes = append([]byte(nil), canonical...)
				defer clear(material.Bytes)
			}
			if len(material.Bytes) == 0 || len(material.Bytes) > wire.MaxMaterial {
				return wire.Error(api.CodeIntegrity, "enrolled credential material has invalid bounds")
			}
			expires := room.ExpiresAt
			for _, bound := range []api.Timestamp{grant.ExpiresAt, profile.ExpiresAt, profile.Source.ExpiresAt} {
				if timestampBefore(bound, expires) {
					expires = bound
				}
			}
			result = api.CredentialSlot{ID: id, ProfileGrantID: grant.ID, ProfileID: profile.ID, Mode: publicSlotMode(profile), LeaseID: credentialID("refresh-lease", id), ExpiresAt: expires}
			retained = newSlot(launch, "profile", id, fingerprint)
			retained.Credential, retained.ProfileID, retained.ProfileGeneration, retained.LoginID = result, profile.ID, profile.Generation, profile.LoginID
			retained.Grant = source
			retained.Material = material.Bytes
			if !slotIsPrivate(retained, launch) {
				return wire.Error(api.CodeForbidden, "retained history or home cannot be a credential slot")
			}
			if err := journal.Write("slot", id, retained); err != nil {
				return err
			}
			return s.recheckCredentialLaunch(ctx, launch)
		})
		if err != nil {
			return api.CredentialSlot{}, err
		}
		if !busy {
			return result, nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return api.CredentialSlot{}, wire.Context(ctx)
		case <-timer.C:
		}
	}
}

// helper is private opaque retrieval; public slots use their driver's mode.
// Neither case claims a native file-login or headless-token representation.
func publicSlotMode(profile bstate.Profile) string {
	if profile.Mode == "helper" {
		switch profile.Driver {
		case api.DriverClaudock:
			return "claudock-helper"
		case api.DriverCodex:
			return "codex-api"
		}
	}
	return profile.Mode
}

func (s *Service) prepareInjection(ctx context.Context, target api.LifeRef, grants []api.SecretGrant, current api.GrantSet, selector launchSelection) (api.Injection, error) {
	launch, err := s.credentialLaunch(ctx, target, current, selector)
	if err != nil {
		return api.Injection{}, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return api.Injection{}, err
	}
	result := api.Injection{Target: target, SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}
	selection, err := slotFingerprint(launch, grants)
	if err != nil {
		return api.Injection{}, err
	}
	markerID := slotID(launch, "selection", launch.profile)
	err = s.withPreparedBind(ctx, backend, markerID, func() bstate.Slot { return s.bindMarker(markerID, selection, &result) }, func(journal bstate.Journal) error {
		if err := s.recheckCredentialLaunch(ctx, launch); err != nil {
			return err
		}
		profileID := slotID(launch, "profile", launch.profile)
		var profile bstate.Slot
		if err := journal.Read("slot", profileID, &profile); err != nil {
			return err
		}
		defer clear(profile.Material)
		defer clear(profile.Returned)
		if profile.Kind != "profile" || profile.Released || profile.Credential.ProfileGrantID != launch.profile || profile.GrantSHA256 != current.SHA256 || !slotIsPrivate(profile, launch) || !future(profile.Credential.ExpiresAt, s.deps.Clock.Now()) {
			return wire.Error(api.CodeForbidden, "injection lacks its exact current reserved-life profile slot")
		}
		profileSource, err := journal.Fetch(ctx, profile.Grant)
		clear(profileSource.Bytes)
		if err != nil {
			return err
		}
		result.SlotIDs = append(result.SlotIDs, profileID)
		var marker bstate.Slot
		if err := journal.Read("slot", markerID, &marker); err == nil {
			if marker.Fingerprint != selection {
				return wire.Error(api.CodeConflict, "injection retry changed its selected inputs")
			}
		} else if !hasCode(err, api.CodeNotFound) {
			return err
		} else if err := journal.Write("slot", markerID, newSlot(launch, "selection", markerID, selection)); err != nil {
			return err
		}
		for _, grant := range grants {
			id := slotID(launch, "task", grant.ID)
			fingerprint, err := slotFingerprint(launch, grant)
			if err != nil {
				return err
			}
			var retained bstate.Slot
			if err := journal.Read("slot", id, &retained); err == nil {
				defer clear(retained.Material)
				defer clear(retained.Returned)
				if retained.Released || retained.Fingerprint != fingerprint || retained.Grant != grant || !slotIsPrivate(retained, launch) {
					return wire.Error(api.CodeConflict, "injection retry differs from its retained material binding")
				}
				source, err := journal.Fetch(ctx, retained.Grant)
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
				retained = newSlot(launch, "task", id, fingerprint)
				retained.Grant, retained.Material = grant, material.Bytes
				if !slotIsPrivate(retained, launch) {
					return wire.Error(api.CodeForbidden, "retained history or home cannot be a task credential slot")
				}
				if err := journal.Write("slot", id, retained); err != nil {
					return err
				}
			}
			result.SlotIDs = append(result.SlotIDs, id)
			result.GrantIDs = append(result.GrantIDs, grant.ID)
			result.SourceVersions = append(result.SourceVersions, grant.Version)
			// Delivery inventories contain destinations in request order; the
			// source remains identified separately by grant ID and version.
			if grant.Delivery == "env" {
				result.TaskSecretNames = append(result.TaskSecretNames, grant.Target)
			} else {
				result.TaskSecretFileNames = append(result.TaskSecretFileNames, grant.Target)
			}
		}
		return s.recheckCredentialLaunch(ctx, launch)
	})
	if err != nil {
		return api.Injection{}, err
	}
	return result, nil
}
