package secrets

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func (s *Service) brokerBackend() (bstate.Backend, error) {
	backend, ok := s.deps.Backend.(bstate.Backend)
	if !ok || wire.Nil(backend) {
		return nil, wire.Error(api.CodePrerequisite, "credential broker requires its protected encrypted journal")
	}
	return backend, nil
}

func (s *Service) validateEnrollment(profile bstate.Profile) error {
	if profile.Usage != nil {
		u := profile.Usage
		if profile.Driver != api.DriverClaudock || !usageName(u.VendorProfile) || u.AdapterVersion == "" || len(u.AdapterVersion) > 128 || !wire.ID(string(u.Executable.ID)) || !wire.Digest(u.Executable.SHA256) || u.Executable.Version == "" || !workerBlob(u.RuntimeManifest) || u.RuntimeManifest.Class != "manifest" {
			return wire.Error(api.CodeInvalid, "protected usage enrollment has invalid vendor or runtime pins")
		}
	}
	if profile.Schema != "laneboss.credential-profile.v2" || profile.Config != s.deps.Config || !wire.ID(string(profile.ID)) || !wire.ID(string(profile.LoginID)) || profile.Generation == 0 ||
		profile.Driver != api.DriverClaudock && profile.Driver != api.DriverCodex || !wire.Name(profile.Provider) || !wire.ID(string(profile.Runtime.ID)) || !wire.Digest(profile.Runtime.SHA256) || profile.Runtime.Version == "" ||
		profile.Models == nil || len(profile.Models) == 0 || len(profile.Models) > 256 || profile.VendorVersions == nil || len(profile.VendorVersions) == 0 || len(profile.VendorVersions) > 64 || profile.RefreshFields == nil ||
		!future(profile.ExpiresAt, s.deps.Clock.Now()) || profile.Evidence.Class != "credential_evidence" || !wire.ID(string(profile.Evidence.ID)) || !wire.Digest(profile.Evidence.SHA256) {
		return wire.Error(api.CodeInvalid, "protected profile enrollment has invalid identity runtime evidence or bounds")
	}
	if profile.Mode != "headless_token" && profile.Mode != "helper" && profile.Mode != "file_login" && profile.Mode != "codex-file" && profile.Mode != "claudock-headless" && profile.Mode != "claude-api-key" {
		return wire.Error(api.CodeUnsupported, "protected profile credential mode is unsupported")
	}
	if profile.Mode == "codex-file" && (profile.Driver != api.DriverCodex || !wire.Digest(profile.AccountSHA256)) ||
		(profile.Mode == "claudock-headless" || profile.Mode == "claude-api-key") && profile.Driver != api.DriverClaudock {
		return wire.Error(api.CodeInvalid, "protected native credential mode differs from its enrolled driver or account")
	}
	for _, model := range profile.Models {
		if model == "" || len(model) > 256 {
			return wire.Error(api.CodeInvalid, "protected profile model enrollment is invalid")
		}
	}
	for _, version := range profile.VendorVersions {
		if version == "" || len(version) > 128 {
			return wire.Error(api.CodeInvalid, "protected profile vendor version enrollment is invalid")
		}
	}
	seen := map[string]bool{}
	for _, field := range profile.RefreshFields {
		if field != "access_token" && field != "refresh_token" && field != "expires_at" || seen[field] {
			return wire.Error(api.CodeInvalid, "profile refresh enrollment contains unsupported fields")
		}
		seen[field] = true
	}
	return validateGrant(profile.Source, s.deps.Clock.Now())
}

// InstallProfile is a protected installer operation, like native.Unlock. It is
// not registered as an RPC and accepts no credential value or filesystem path.
// The installed administrator/worker owns enrollment and evidence production.
func (s *Service) InstallProfile(ctx context.Context, profile bstate.Profile) error {
	if err := s.validateEnrollment(profile); err != nil {
		return err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	if _, err := s.profileObservation(ctx, profile); err != nil {
		return err
	}
	return backend.WithBroker(ctx, func(journal bstate.Journal) error {
		var prior bstate.Profile
		err := journal.Read("profile", profile.ID, &prior)
		if err == nil {
			if reflect.DeepEqual(prior, profile) {
				return nil
			}
			if profile.Generation != prior.Generation+1 || prior.LoginID != profile.LoginID || prior.Driver != profile.Driver || prior.Provider != profile.Provider {
				return wire.Error(api.CodeConflict, "profile enrollment changed its canonical login or generation")
			}
		} else if !hasCode(err, api.CodeNotFound) {
			return err
		}
		if profile.Mode == "file_login" || profile.Mode == "codex-file" {
			var login bstate.Login
			if err := journal.Read("login", profile.LoginID, &login); err == nil {
				defer clear(login.Material)
				if login.ID != profile.LoginID || login.Driver != profile.Driver || login.Provider != profile.Provider || login.AccountSHA256 != profile.AccountSHA256 || login.Source == nil || *login.Source != profile.Source {
					return wire.Error(api.CodeConflict, "profile alias differs from its canonical protected login source")
				}
			} else if !hasCode(err, api.CodeNotFound) {
				return err
			} else if err := journal.Write("login", profile.LoginID, bstate.Login{AccountSHA256: profile.AccountSHA256, Generation: 1, ID: profile.LoginID, SlotID: "", Driver: profile.Driver, Provider: profile.Provider, Source: &profile.Source}); err != nil {
				return err
			}
		}
		return journal.Write("profile", profile.ID, profile)
	})
}

func (s *Service) loadProfile(ctx context.Context, grant api.ProfileGrant) (bstate.Profile, error) {
	backend, err := s.brokerBackend()
	if err != nil {
		return bstate.Profile{}, err
	}
	var profile bstate.Profile
	err = backend.WithBroker(ctx, func(journal bstate.Journal) error { return journal.Read("profile", grant.ProfileID, &profile) })
	if err != nil {
		return profile, err
	}
	if err := s.validateEnrollment(profile); err != nil {
		return profile, err
	}
	if profile.ID != grant.ProfileID || profile.Driver != grant.Driver || profile.Provider != grant.Provider || profile.Paid != grant.Paid {
		return profile, wire.Error(api.CodeForbidden, "profile selection differs from protected login enrollment")
	}
	return profile, nil
}

func (s *Service) profileObservation(ctx context.Context, profile bstate.Profile) (bstate.Observation, error) {
	var observation bstate.Observation
	data, err := s.protectedObject(ctx, profile.Evidence, "")
	if err != nil {
		return observation, err
	}
	if err := api.DecodeObject(data, &observation); err != nil {
		return observation, err
	}
	if observation.Schema != "laneboss.credential-evidence.v2" || observation.Config != s.deps.Config || observation.ProfileID != profile.ID || observation.LoginID != profile.LoginID ||
		observation.Generation != profile.Generation || observation.Driver != profile.Driver || observation.Provider != profile.Provider || !future(observation.ExpiresAt, s.deps.Clock.Now()) {
		return observation, wire.Error(api.CodeForbidden, "profile room evidence is stale or belongs to another enrolled login")
	}
	checked, err := time.Parse(time.RFC3339Nano, string(observation.CheckedAt))
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(observation.ExpiresAt))
	if err != nil || expiryErr != nil || !strings.HasSuffix(string(observation.CheckedAt), "Z") || checked.After(s.deps.Clock.Now()) || !checked.Before(expires) || expires.After(checked.Add(5*time.Minute)) {
		return observation, wire.Error(api.CodeIntegrity, "profile evidence exceeds its authenticated observation window")
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, profile.Evidence.ID)
	if err != nil {
		return observation, err
	}
	operation, err := s.deps.Store.Operation(ctx, s.deps.ServiceScope, meta.SourceOperationID)
	if err != nil {
		return observation, err
	}
	if operation.ID != meta.SourceOperationID || operation.Status != "succeeded" || operation.Error != nil {
		return observation, wire.Error(api.CodePrerequisite, "profile observation producer has not completed successfully")
	}
	return observation, nil
}

func (s *Service) roomForProfile(ctx context.Context, grant api.ProfileGrant, profile bstate.Profile) (api.Room, error) {
	observation, err := s.profileObservation(ctx, profile)
	if err != nil {
		return api.Room{}, err
	}
	expires := observation.ExpiresAt
	for _, bound := range []api.Timestamp{grant.ExpiresAt, profile.ExpiresAt} {
		if timestampBefore(bound, expires) {
			expires = bound
		}
	}
	reason := "authenticated_profile_room"
	if !observation.Available {
		reason = "authenticated_profile_no_room"
	}
	return api.Room{ProfileID: profile.ID, Available: observation.Available, CheckedAt: observation.CheckedAt, ExpiresAt: expires, Evidence: profile.Evidence, Reason: reason}, nil
}

func timestampBefore(a, b api.Timestamp) bool {
	one, err := time.Parse(time.RFC3339Nano, string(a))
	two, other := time.Parse(time.RFC3339Nano, string(b))
	return err == nil && other == nil && one.Before(two)
}

func (s *Service) profileEligibility(ctx context.Context, request api.ProfileEligibilityRequest, from, to api.ProfileGrant) (api.ProfileEligibility, error) {
	before, err := s.loadProfile(ctx, from)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	after, err := s.loadProfile(ctx, to)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	room, err := s.Room(ctx, to)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	compatible := slices.Contains(before.Models, request.Model) && slices.Contains(after.Models, request.Model) && slices.Contains(before.VendorVersions, request.Session.VendorVersion) &&
		slices.Contains(after.VendorVersions, request.Session.VendorVersion) && before.Runtime == after.Runtime
	lane, err := s.deps.Store.Lane(ctx, s.deps.ServiceScope, request.Target)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	if binding.Recovery == nil {
		return api.ProfileEligibility{}, wire.Error(api.CodeIntegrity, "profile eligibility lacks its retained launch binding")
	}
	record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, binding.Recovery.PlanID)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return api.ProfileEligibility{}, err
	}
	if record.Plan == nil || record.Handoff == nil {
		return api.ProfileEligibility{}, wire.Error(api.CodeIntegrity, "profile eligibility lacks its retained launch plan")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); err != nil {
		return api.ProfileEligibility{}, err
	}
	if record.Plan.Capture.Status != "registered" {
		return api.ProfileEligibility{}, wire.Error(api.CodePrerequisite, "profile continuation requires registered outside capture")
	}
	if binding.Record.Target != request.Target || record.Plan.Runner.Session != request.Session {
		return api.ProfileEligibility{}, wire.Error(api.CodeForbidden, "profile eligibility differs from bound private history")
	}
	// Eligibility is a read. The continuation owner retains this full typed
	// result under its real claim. It cites the existing protected producer
	// evidence; this component cannot borrow a completed helper effect to emit
	// a new object_retain transaction.
	id := credentialID("eligibility", request, before, after, binding.Identity)
	current, err := s.currentGrants(ctx, request.Target)
	if err != nil {
		return api.ProfileEligibility{}, err
	}
	if current.ID != request.GrantSetID || current.SHA256 != record.Plan.Inputs.Grants.SHA256 {
		return api.ProfileEligibility{}, wire.Error(api.CodeConflict, "profile eligibility grants changed during assessment")
	}
	for _, bound := range []api.Timestamp{from.ExpiresAt, before.ExpiresAt} {
		if timestampBefore(bound, room.ExpiresAt) {
			room.ExpiresAt = bound
		}
	}
	reason := "enrolled_model_and_history_compatible"
	if !compatible {
		reason = "enrolled_model_or_history_incompatible"
	}
	return api.ProfileEligibility{ID: id, Request: request, Compatible: compatible, Reason: reason, Evidence: room.Evidence, CheckedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), ExpiresAt: room.ExpiresAt}, nil
}
