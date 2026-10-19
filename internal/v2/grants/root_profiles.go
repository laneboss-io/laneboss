package grants

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// GrantsRoot has already verified the human proof and immutable manifest.
// Hold the existing encrypted journal lock through issuance so enrollment
// cannot change between metadata validation and the durable root transaction.
// No login, slot, refresh, material fetch or credential observation is involved.
func (s *Service) issueProfileRoot(ctx context.Context, scope api.Scope, input api.RootGrantManifest, budget api.Budget, guard api.TransactionGuard) (api.GrantSet, error) {
	var result api.GrantSet
	if nilInterface(s.deps.Profiles) {
		return result, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-grants",
			Message: "root profiles require the installed protected profile journal",
			Instead: "Bind the administrator/secrets broker backend; never infer enrollment from a selector."}
	}
	called := false
	err := s.deps.Profiles.WithBroker(ctx, func(journal bstate.Journal) (resultErr error) {
		if called || nilInterface(journal) {
			return integrity("root profile journal callback is missing or repeated")
		}
		called = true
		// A journal lock may have waited. Reopen current scope/policy before
		// reading a protected record, retaining the original authenticated frame.
		current, view, err := s.freshAuthority(ctx, scope)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
		if err := s.checkScope(ctx, current); err != nil {
			return err
		}
		policy, err := s.deps.Store.Policy(ctx, current)
		if err != nil {
			return err
		}
		if policy.Generation == 0 || policy.Generation != current.PolicyGeneration {
			return conflict("root profile policy generation changed")
		}
		for _, grant := range input.Profiles {
			if err := ctx.Err(); err != nil {
				return cancelled(err)
			}
			if slices.Contains(policy.ProfileExclusions, grant.ProfileID) {
				return refused("root profile is excluded by current policy")
			}
			var profile bstate.Profile
			if err := journal.Read("profile", grant.ProfileID, &profile); err != nil {
				return err // Keep the actual encrypted-store failure and owner.
			}
			if err := rootProfile(profile, grant, current.Config, s.deps.Clock.Now()); err != nil {
				return err
			}
		}
		result, err = s.issueRootSet(ctx, current, input, budget, guard)
		return err
	})
	if err != nil {
		return api.GrantSet{}, err
	}
	if !called || result.ID == "" {
		return api.GrantSet{}, integrity("profile resolution did not produce a durable root grant")
	}
	return result, nil
}

func rootProfile(profile bstate.Profile, grant api.ProfileGrant, config string, now time.Time) error {
	if profile.Schema != "laneboss.credential-profile.v2" || profile.Config != config || profile.ID != grant.ProfileID ||
		profile.Driver != grant.Driver || profile.Provider != grant.Provider || profile.Paid != grant.Paid {
		return refused("root profile differs from protected enrollment")
	}
	if grant.ID != "" || grant.ParentGrantID != "" || !manifest.ValidID(profile.ID) || !manifest.ValidID(profile.LoginID) || !wire.Name(profile.Provider) ||
		profile.Generation == 0 || uint64(profile.Generation) > manifest.MaxInteger ||
		!manifest.ValidID(profile.Runtime.ID) || !manifest.ValidDigest(profile.Runtime.SHA256) || profile.Runtime.Version == "" ||
		len(profile.Models) == 0 || len(profile.Models) > 256 || len(profile.VendorVersions) == 0 || len(profile.VendorVersions) > 64 || profile.RefreshFields == nil {
		return integrity("protected root profile metadata is malformed")
	}
	if profile.Usage != nil {
		u := profile.Usage
		// Match the secrets owner's enrollment grammar. This is metadata
		// validation, not an outside usage query or a credential lease.
		if profile.Driver != api.DriverClaudock || u.VendorProfile == "" || len(u.VendorProfile) > 256 ||
			!utf8.ValidString(u.VendorProfile) || strings.ContainsAny(u.VendorProfile, "\t\r\n\x00") ||
			u.AdapterVersion == "" || len(u.AdapterVersion) > 128 || !wire.ID(string(u.Executable.ID)) ||
			!wire.Digest(u.Executable.SHA256) || u.Executable.Version == "" || !rootProfileRef(u.RuntimeManifest, "manifest") {
			return integrity("protected root profile usage metadata is malformed")
		}
	}
	switch profile.Mode {
	case "headless_token", "helper", "file_login", "codex-file", "claudock-headless", "claude-api-key":
	default:
		return integrity("protected root profile mode is unsupported")
	}
	if profile.Mode == "codex-file" && (profile.Driver != api.DriverCodex || !manifest.ValidDigest(profile.AccountSHA256)) ||
		(profile.Mode == "claudock-headless" || profile.Mode == "claude-api-key") && profile.Driver != api.DriverClaudock {
		return integrity("protected root profile mode differs from its driver")
	}
	for i, values := range [][]string{profile.Models, profile.VendorVersions} {
		limit := 256
		if i == 1 {
			limit = 128
		}
		for _, value := range values {
			if value == "" || len(value) > limit {
				return integrity("protected root profile compatibility metadata is malformed")
			}
		}
	}
	seen := map[string]bool{}
	for _, field := range profile.RefreshFields {
		if field != "access_token" && field != "refresh_token" && field != "expires_at" || seen[field] {
			return integrity("protected root profile refresh metadata is malformed")
		}
		seen[field] = true
	}
	source := profile.Source
	if !manifest.ValidID(source.ID) || !manifest.ValidID(source.SourceHandle) || !wire.Name(source.Name) || !wire.Name(source.Version) ||
		source.ParentGrantID != "" && !manifest.ValidID(source.ParentGrantID) {
		return integrity("protected root profile source metadata is malformed")
	}
	if err := manifest.SecretTarget(source.Delivery, source.Target); err != nil {
		return integrity("protected root profile source target is malformed")
	}
	if !rootProfileRef(profile.Evidence, "credential_evidence") {
		return integrity("protected root profile evidence reference is malformed")
	}
	expiry, err := manifest.Expiry(grant.ExpiresAt, now)
	if err != nil {
		return err
	}
	for _, bound := range []api.Timestamp{profile.ExpiresAt, source.ExpiresAt} {
		ceiling, err := manifest.Expiry(bound, now)
		if err != nil {
			return err
		}
		if expiry.After(ceiling) {
			return refused("root profile expiry exceeds protected enrollment")
		}
	}
	return nil
}

// The evidence owner uses credential_evidence, outside the grants object's
// closed class list. Check the same bounded reference grammar and exact class
// directly; do not extend that unrelated list or fetch credential evidence.
func rootProfileRef(ref api.BlobRef, class string) bool {
	return wire.ID(string(ref.ID)) && wire.Digest(ref.SHA256) && ref.Bytes >= 0 &&
		ref.Bytes <= api.MaxObjectBytes && ref.Class == class
}
