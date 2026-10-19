//go:build linux

package service

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// No human proof, credential projection or vendor request is authorized by
// this component regression. Unexpected calls fail at their owning port.
type planningCredentialBoundary struct{}

func (planningCredentialBoundary) Challenge(context.Context, api.Scope, api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return api.HumanChallenge{}, serviceError(api.CodeForbidden, "planning component cannot request a human challenge")
}
func (planningCredentialBoundary) Confirm(context.Context, api.Scope, api.HumanConfirmRequest) (api.ProofRef, error) {
	return api.ProofRef{}, serviceError(api.CodeForbidden, "planning component cannot confirm a human proof")
}
func (planningCredentialBoundary) CheckProof(context.Context, api.Scope, api.ProofRef, api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	return api.VerifiedHumanProof{}, serviceError(api.CodeForbidden, "planning component cannot consume a human proof")
}
func (planningCredentialBoundary) AuthorizeCredentialProjection(context.Context, api.VerifiedPeer, api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	return api.CredentialProjectionAuthority{}, serviceError(api.CodeForbidden, "planning component cannot project credentials")
}
func (planningCredentialBoundary) CheckLaunchCredentials(context.Context, api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, serviceError(api.CodeForbidden, "planning component cannot bind an executing agent")
}

type planningCredentialHelper struct {
	api.HelperControl
	p *successfulPlanPorts
}

func (h *planningCredentialHelper) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	return h.p.ResolveLaunchSources(ctx, request)
}
func (h *planningCredentialHelper) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	return h.p.ResolveLaunchStorage(ctx, request)
}

func planningBroker(t *testing.T, f *fx.Fixture, p *successfulPlanPorts) *secrets.Service {
	t.Helper()
	ctx := context.Background()
	keyID := fx.ID(t)
	backend, err := native.New(native.Dependencies{Directory: filepath.Join(testdir.New(t), "records"), KeyHandle: keyID, Config: f.Deps.Config, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal("cannot open actual encrypted component broker", err)
	}
	p.backend = backend
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	key := []byte(fx.ID(t))
	keyDigest := fx.Digest(key)
	key = []byte(keyDigest)[:32]
	if err := backend.Unlock(ctx, keyID, bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	clear(key)
	account := string(fx.ID(t))
	material := fx.JSON(t, map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{
		"account_id": account, "access_token": string(fx.ID(t)), "refresh_token": string(fx.ID(t))}})
	info, err := backend.Store(ctx, api.SecretInfo{Name: "component-login", Version: "one"}, api.SecretMaterial{Bytes: material})
	clear(material)
	if err != nil {
		t.Fatal("cannot retain synthetic credential material", err)
	}
	p.sourceInfo = info
	resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &dataworker.Service{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	dependencies := secrets.Dependencies{Backend: backend, Store: f.State, Human: planningCredentialBoundary{}, Clock: f.Deps.Clock,
		Config: f.Deps.Config, ServiceScope: f.Execution, Grants: resolver, Helper: &planningCredentialHelper{p: p}, ProjectionIdentity: planningCredentialBoundary{}}
	if p.configureBroker != nil {
		p.configureBroker(&dependencies)
	}
	broker, err := secrets.New(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	p.broker = broker
	grant := f.Ceiling.Profiles[0]
	now := f.Deps.Clock.Now().UTC()
	observation := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: f.Deps.Config, ProfileID: grant.ProfileID,
		LoginID: fx.ID(t), Generation: 1, Driver: grant.Driver, Provider: grant.Provider, Available: true,
		CheckedAt: api.Timestamp(now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(now.Add(4 * time.Minute).Format(time.RFC3339Nano))}
	raw := fx.JSON(t, observation)
	ref := api.BlobRef{ID: fx.ID(t), Class: "credential_evidence", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
		ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
		t.Fatal(err)
	}
	vendor := p.runtime.SessionExecutable
	if vendor.ID == "" {
		vendor = p.runtime.Executable
	}
	profile := bstate.Profile{Schema: "laneboss.credential-profile.v2", Config: f.Deps.Config, ID: grant.ProfileID, LoginID: observation.LoginID,
		Generation: 1, Driver: grant.Driver, Provider: grant.Provider, Paid: grant.Paid, Mode: "codex-file", AccountSHA256: fx.Digest([]byte(account)),
		Source:  api.SecretGrant{ID: fx.ID(t), Name: info.Name, Version: info.Version, SourceHandle: info.SourceHandle, Delivery: "file", Target: "auth.json", ExpiresAt: grant.ExpiresAt},
		Runtime: p.runtime.Executable, Models: []string{f.Start.Model}, VendorVersions: []string{vendor.Version}, RefreshFields: []string{},
		Evidence: ref, ExpiresAt: grant.ExpiresAt}
	if p.profileMode != "" {
		profile.Mode = p.profileMode
	}
	if err := broker.InstallProfile(ctx, profile); err != nil {
		t.Fatal("actual broker rejected synthetic protected profile", err)
	}
	return broker
}
