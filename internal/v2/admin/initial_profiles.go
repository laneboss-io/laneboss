package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

// InitialProfileEnrollment is a private installed capability. The dedicated
// fixture build binds its pinned stand-in planner and the real secrets
// InstallProfile method. No RPC, harness writer or credential lease is added.
type InitialProfileEnrollment interface {
	PlanStandInProfiles(context.Context, InitialManifest, api.RootGrantManifest) ([]bstate.Profile, error)
	InstallProfile(context.Context, bstate.Profile) error
}

// InitialProfileAuthenticator is supplied only by the dedicated E2E fixture.
// It must retain and authenticate its actual encrypted source before reporting
// room. Executable enrollment alone continues to publish unavailable evidence.
type InitialProfileAuthenticator interface {
	AuthenticateStandInProfile(context.Context, bstate.Profile) (bool, error)
}

func initialProfilePlan(ctx context.Context, b initialBundle, now api.Timestamp) ([]bstate.Profile, []api.ObjectWrite, error) {
	if nilEnrollmentPort(b.enrollment) {
		return nil, nil, nil
	}
	profiles, err := b.enrollment.PlanStandInProfiles(ctx, b.manifest, b.profiles)
	if err != nil {
		return nil, nil, err
	}
	if len(profiles) != len(b.profiles.Profiles) || len(profiles) == 0 {
		return nil, nil, failure(api.CodeIntegrity, "initial stand-in profile enrollment omits a selector")
	}
	checked, err := time.Parse(time.RFC3339Nano, string(now))
	if err != nil || checked.UTC().Format(time.RFC3339Nano) != string(now) {
		return nil, nil, failure(api.CodeIntegrity, "initial profile observation time differs")
	}
	writes := make([]api.ObjectWrite, 0, len(profiles))
	seen := map[api.ID]bool{b.ref.ID: true, initialReceiptID(b.manifest.Config): true}
	for _, ref := range b.manifest.Objects {
		seen[ref.ID] = true
	}
	for index := range profiles {
		p := &profiles[index]
		grant := b.profiles.Profiles[index]
		if p.Config != b.manifest.Config || p.ID != grant.ProfileID || p.Driver != grant.Driver || p.Provider != grant.Provider || p.Paid || grant.Paid || p.ExpiresAt != grant.ExpiresAt || p.Evidence != (api.BlobRef{}) {
			return nil, nil, failure(api.CodeIntegrity, "initial stand-in profile differs from its exact selector")
		}
		expires, err := time.Parse(time.RFC3339Nano, string(p.ExpiresAt))
		if err != nil || !expires.After(checked) {
			return nil, nil, failure(api.CodeForbidden, "initial stand-in profile expired")
		}
		if expires.After(checked.Add(5 * time.Minute)) {
			expires = checked.Add(5 * time.Minute)
		}
		available := false
		if authenticator, ok := b.enrollment.(InitialProfileAuthenticator); ok {
			available, err = authenticator.AuthenticateStandInProfile(ctx, *p)
			if err != nil {
				return nil, nil, err
			}
		}
		observation := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: p.Config,
			ProfileID: p.ID, LoginID: p.LoginID, Generation: p.Generation, Driver: p.Driver,
			Provider: p.Provider, Available: available, CheckedAt: now,
			ExpiresAt: api.Timestamp(expires.UTC().Format(time.RFC3339Nano))}
		raw, err := json.Marshal(observation)
		if err != nil {
			return nil, nil, err
		}
		id := api.ID("initial-profile-" + string(digestBytes(raw))[:32])
		if seen[id] {
			return nil, nil, failure(api.CodeIntegrity, "initial profile evidence aliases another object")
		}
		seen[id] = true
		p.Evidence = api.BlobRef{ID: id, Class: "credential_evidence", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
		write := initialObject(p.Evidence, raw, p.Config, api.Actor{Kind: "service", ID: api.ID("initial-" + p.Config)})
		write.ACL.Audience = "service"
		writes = append(writes, write)
	}
	return profiles, writes, nil
}

func installInitialProfiles(ctx context.Context, b initialBundle, store api.StateStore, scope api.Scope, operation api.ID, published api.Timestamp, channel *enrollmentChannel) error {
	profiles, writes, err := initialProfilePlan(ctx, b, published)
	if err != nil {
		return err
	}
	for index, profile := range profiles {
		meta, err := store.ObjectMetadata(ctx, scope, profile.Evidence.ID)
		if err != nil {
			return err
		}
		if meta.Ref != profile.Evidence || !reflect.DeepEqual(meta.ACL, writes[index].ACL) || meta.Origin != "service" || meta.SourceOperationID != operation {
			return initialFailure("profile evidence metadata")
		}
		raw, err := initialReadBytes(ctx, store, scope, profile.Evidence)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, writes[index].Bytes) {
			return initialFailure("profile evidence bytes")
		}
		if err := CheckEnrollmentChannel(ctx, channel.endpoint); err != nil {
			return err
		}
		if err := b.enrollment.InstallProfile(ctx, profile); err != nil {
			return err
		}
	}
	return nil
}
