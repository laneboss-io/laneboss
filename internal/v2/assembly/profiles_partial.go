//go:build laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/service"
)

type initialFixtureProfiles struct {
	*secrets.Service
	installed Installation
	fixture   fixtureEnrollment
	real      *realRuntime
}

var _ admin.InitialProfileAuthenticator = (*initialFixtureProfiles)(nil)

func bindInitialProfiles(server *service.Server, installed Installation, credentials *secrets.Service) error {
	declared, err := loadFixture(installed)
	if err != nil || declared == nil {
		return err
	}
	if _, _, err := runnersForFixture(declared); err != nil {
		return err
	}
	real, err := loadRealRuntime(installed)
	if err != nil {
		return err
	}
	return server.BindInitialProfiles(&initialFixtureProfiles{Service: credentials, installed: installed, fixture: *declared, real: real})
}

func (s *initialFixtureProfiles) PlanStandInProfiles(ctx context.Context, initial admin.InitialManifest, root api.RootGrantManifest) ([]bstate.Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if initial.Config != s.installed.Config || initial.Config != s.fixture.Config || initial.Runtime != s.installed.RuntimeManifest ||
		!s.fixture.VendorStoodIn || len(root.Profiles) == 0 {
		return nil, installError("initial profiles differ from the installed stand-in runtime")
	}
	// Watchdog fixture enrollment: supported drivers and profile identity are
	// separate. Several delegated selectors may use the same pinned driver.
	profileIDs := map[api.ID]bool{}
	profiles := make([]bstate.Profile, 0, len(root.Profiles))
	for _, grant := range root.Profiles {
		if !slices.Contains(s.fixture.Drivers, grant.Driver) || !fixtureObjectID.MatchString(string(grant.ProfileID)) || profileIDs[grant.ProfileID] ||
			grant.Provider != "serve-fixture" || grant.Paid || grant.ID != "" || grant.ParentGrantID != "" {
			return nil, installError("initial stand-in profile selector differs")
		}
		profileIDs[grant.ProfileID] = true
		key := standInProfileKey(initial.Config, grant.ProfileID)
		profile := bstate.Profile{Schema: "laneboss.credential-profile.v2", Config: initial.Config,
			ID: grant.ProfileID, LoginID: api.ID("standin-login-" + key), Generation: 1,
			Driver: grant.Driver, Provider: grant.Provider, Mode: standInMode(grant.Driver), Runtime: s.fixture.Executable,
			Models: []string{s.fixture.Version}, VendorVersions: []string{s.fixture.Version}, RefreshFields: []string{},
			AccountSHA256: standInAccountSHA256(grant.Driver, initial.Config, grant.ProfileID),
			Source:        standInProfileSource(initial.Config, grant.ProfileID, grant.ExpiresAt),
			ExpiresAt:     grant.ExpiresAt}
		if s.real != nil && grant.Driver == api.DriverClaudock {
			// Public metadata only. No authenticator material is created for a
			// real vendor; the credential broker must report it unavailable.
			profile.Runtime = s.real.Wrapper
			profile.Models = []string{"claude-sonnet-4-6"}
			profile.VendorVersions = []string{claudock.ClaudeVersion}
			if s.fixture.CanaryAPIKey {
				profile.Mode = "claude-api-key"
			}
		}
		// Watchdog usage-enrollment hunk. This pins selectors and bytes only;
		// ReadUsageWindow must still execute/authenticate its native worker.
		if s.real == nil && grant.Driver == api.DriverClaudock {
			profile.Usage = &bstate.UsageProfile{VendorProfile: string(grant.ProfileID), AdapterVersion: fixtureAdapter,
				Executable: s.fixture.Executable, RuntimeManifest: s.installed.RuntimeManifest}
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// standInMode is the stand-in profile's credential mode: each driver uses its one mode with projection code
// (api.CredentialTargets, runner/claudock/README.md). A helper profile's slot (claudock-helper, codex-api) has none by
// design, so it stopped every installed launch at its credential projection (box 46; Codex in laneboss's preflight).
func standInMode(driver api.Driver) string {
	if driver == api.DriverClaudock {
		return "claudock-headless"
	}
	return "codex-file"
}

func standInProfileKey(config string, profile api.ID) string {
	sum := sha256.Sum256([]byte(config + "\x00" + string(profile)))
	return hex.EncodeToString(sum[:])[:32]
}

// standInAccount is the Codex stand-in login's account_id. A codex-file profile enrolls its digest (secrets/profiles.go)
// and projection and refresh check the source's account_id against it (secrets/projection.go, runner/codex
// NewCredential); both come from the protected enrollment, never from the stored bytes.
func standInAccount(config string, profile api.ID) string {
	return "standin-account-" + standInProfileKey(config, profile)
}

// standInAccountSHA256 is the enrolled account digest; only codex-file enrolls one.
func standInAccountSHA256(driver api.Driver, config string, profile api.ID) api.Digest {
	if standInMode(driver) != "codex-file" {
		return ""
	}
	sum := sha256.Sum256([]byte(standInAccount(config, profile)))
	return api.Digest(hex.EncodeToString(sum[:]))
}

// standInCodexLogin is the codex-file stand-in source: projection and refresh accept only a Codex subscription auth
// file for the enrolled account (secrets/projection.go), so both tokens carry the authenticator bytes (never a vendor
// token) and account_id is the stand-in account. It clears the authenticator bytes it wraps.
func standInCodexLogin(authenticator []byte, account string) ([]byte, error) {
	defer clear(authenticator)
	type tokens struct {
		Access  []byte `json:"access_token"`
		Refresh []byte `json:"refresh_token"`
		Account string `json:"account_id"`
	}
	return json.Marshal(struct {
		Mode   string `json:"auth_mode"`
		Tokens tokens `json:"tokens"`
	}{"chatgpt", tokens{authenticator, authenticator, account}})
}

func standInProfileSource(config string, profile api.ID, expires api.Timestamp) api.SecretGrant {
	key := standInProfileKey(config, profile)
	return api.SecretGrant{ID: api.ID("standin-source-" + key), SourceHandle: api.ID("standin-handle-" + key),
		Name: "serve-fixture-login-" + key, Version: "v1", Delivery: "file", Target: "serve-fixture.json", ExpiresAt: expires}
}

func (s *initialFixtureProfiles) AuthenticateStandInProfile(ctx context.Context, p bstate.Profile) (available bool, resultErr error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.real != nil && p.Driver == api.DriverClaudock {
		if s.fixture.CanaryAPIKey {
			return s.authenticateAPIKeyCanary(ctx, p)
		}
		if p.Runtime != s.real.Wrapper || p.Config != s.installed.Config || p.Mode != "claudock-headless" || p.Paid ||
			p.Provider != "serve-fixture" || p.Source != standInProfileSource(p.Config, p.ID, p.ExpiresAt) {
			return false, installError("real vendor profile differs from credential-free enrollment")
		}
		// There is deliberately no material and no authenticated observation.
		return false, nil
	}
	if !s.fixture.VendorStoodIn || p.Config != s.installed.Config || p.Config != s.fixture.Config ||
		p.Provider != "serve-fixture" || p.Paid || p.Mode != standInMode(p.Driver) || p.Generation != 1 ||
		p.AccountSHA256 != standInAccountSHA256(p.Driver, p.Config, p.ID) ||
		!slices.Contains(s.fixture.Drivers, p.Driver) || p.Runtime != s.fixture.Executable ||
		p.LoginID != api.ID("standin-login-"+standInProfileKey(p.Config, p.ID)) ||
		p.Source != standInProfileSource(p.Config, p.ID, p.ExpiresAt) {
		return false, installError("E2E authenticator profile differs from its protected fixture enrollment")
	}
	// This deliberately cannot authenticate at a vendor. Its only authority is
	// the protected, pinned fixture enrollment and its own encrypted readback.
	material, err := json.Marshal(struct {
		Program       string         `json:"program"`
		VendorStoodIn bool           `json:"vendor_stood_in"`
		Config        string         `json:"config"`
		ProfileID     api.ID         `json:"profile_id"`
		Driver        api.Driver     `json:"driver"`
		Challenge     string         `json:"challenge"`
		Runtime       api.Executable `json:"runtime"`
	}{"laneboss-e2e-authenticator", s.fixture.VendorStoodIn, p.Config, p.ID, p.Driver, s.fixture.Challenge, p.Runtime})
	if err != nil {
		return false, err
	}
	if p.Mode == "codex-file" {
		if material, err = standInCodexLogin(material, standInAccount(p.Config, p.ID)); err != nil {
			return false, err
		}
	}
	defer clear(material)
	// Reopen the same installed native backend, with the same protected key,
	// records directory, cross-process lock and AES-GCM path as the real broker.
	backend, err := installedSecrets(ctx, s.installed, wallClock{})
	if err != nil {
		return false, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, backend.Close())
		if resultErr != nil {
			available = false
		}
	}()
	want := api.SecretInfo{Name: p.Source.Name, Version: p.Source.Version, SourceHandle: p.Source.SourceHandle, KeyID: s.installed.SecretKeyHandle}
	stored, err := backend.Store(ctx, want, api.SecretMaterial{Bytes: material})
	if err != nil {
		return false, err
	}
	if stored != want {
		return false, installError("E2E authenticator encrypted source selector differs")
	}
	actual, err := backend.Fetch(ctx, p.Source)
	defer clear(actual.Bytes)
	if err != nil {
		return false, err
	}
	available = len(actual.Bytes) > 0 && bytes.Equal(actual.Bytes, material)
	if !available {
		return false, installError("E2E authenticator encrypted source readback differs")
	}
	return available, nil
}
