//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/runner/codex"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only helper storage/identity and the grants port are component inputs. The
// reservation, request, evidence, encrypted source/profile and slot are real.
type standInCredentialPorts struct {
	api.HelperControl
	api.GrantResolver
	api.HumanVerifier
	api.CredentialProjectionIdentity
	f       *fx.Fixture
	storage api.LaunchStorage
}

func (p *standInCredentialPorts) Resolve(ctx context.Context, _ api.Scope, request api.GrantResolveRequest) (api.GrantSet, error) {
	record, err := p.f.State.LaunchPlan(ctx, p.f.Execution, request.ReservationID)
	if err != nil {
		return api.GrantSet{}, err
	}
	return p.f.State.Grants(ctx, record.Reservation.GrantSetID)
}

func (p *standInCredentialPorts) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	effect, err := p.f.State.Effect(ctx, p.f.Execution, request.Claim.EffectID)
	if err != nil {
		return api.LaunchSources{}, err
	}
	if err := api.CheckPlanningClaim(effect, request.Claim, p.f.Deps.Config, p.f.Deps.Clock.Now()); err != nil {
		return api.LaunchSources{}, err
	}
	record, err := p.f.State.LaunchPlan(ctx, p.f.Execution, request.ReservationID)
	if err != nil {
		return api.LaunchSources{}, err
	}
	if record.Reservation.GrantSetID != request.GrantSetID || record.Inputs == nil {
		return api.LaunchSources{}, installError("component source selector differs")
	}
	return record.Inputs.Sources, nil
}

func (p *standInCredentialPorts) ResolveLaunchStorage(_ context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	if request.ReservationID != p.storage.ReservationID || request.GrantSetID != p.f.Reservation.GrantSetID || request.LeaseID != p.storage.LeaseID {
		return api.LaunchStorage{}, installError("component storage selector differs")
	}
	return p.storage, nil
}

func standInInstalledKey(t *testing.T, installed *Installation, parent string) {
	t.Helper()
	installed.ServiceUID = uint32(os.Geteuid())
	installed.SecretDirectory = filepath.Join(parent, "fixture-secrets")
	if err := os.Mkdir(installed.SecretDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(installed.SecretDirectory, "keys")
	if err := os.Mkdir(keys, 0700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	installed.SecretKeyHandle = api.ID("key-" + string(fx.Digest(key))[:32])
	if err := os.WriteFile(filepath.Join(keys, string(installed.SecretKeyHandle)+".key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	metadata := fx.JSON(t, map[string]string{"schema": "laneboss.native-key.v2", "handle": string(installed.SecretKeyHandle),
		"algorithm": "aes-256-gcm", "key_file": string(installed.SecretKeyHandle) + ".key"})
	if err := os.WriteFile(filepath.Join(keys, "enrollment.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestStandInCredentialAcquisition(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		for _, room := range []bool{true, false} {
			name := string(driver) + "/granted"
			if !room {
				name = string(driver) + "/no-room"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				runtime, installed, values := runtimeFixture(t)
				declared, err := fixtureFromRuntime(runtime, installed, func(o api.RuntimeObject) ([]byte, error) { return values[o.ID], nil })
				if err != nil {
					t.Fatal(err)
				}
				raw := fx.JSON(t, runtime)
				installed.RuntimeManifest = api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
				f := fx.New(t, installed.Config)
				standInInstalledKey(t, &installed, f.Deps.Directory)
				f.Ceiling.Profiles[0].Driver, f.Ceiling.Profiles[0].Provider = driver, "serve-fixture"
				f.Ceiling.SHA256 = fx.Digest(fx.JSON(t, f.Ceiling))
				f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
				f.Start.Driver, f.Start.Model = driver, declared.Version
				f.Start.Grants.Profiles[0].ExpiresAt = f.Start.Grants.Data[0].ExpiresAt
				f.Admit(t, "lane.start", f.Start)
				grant := f.Ceiling.Profiles[0]
				grant.ID, grant.ParentGrantID = "", ""
				other := grant
				other.ProfileID = fx.ID(t)
				other.Driver = api.DriverCodex
				if driver == api.DriverCodex {
					other.Driver = api.DriverClaudock
				}
				planner := &initialFixtureProfiles{installed: installed, fixture: *declared}
				profiles, err := planner.PlanStandInProfiles(ctx, admin.InitialManifest{Config: installed.Config, Runtime: installed.RuntimeManifest},
					api.RootGrantManifest{Profiles: []api.ProfileGrant{grant, other}})
				if err != nil {
					t.Fatal(err)
				}
				profile := profiles[0]
				available := false
				if authenticator, ok := any(planner).(interface {
					AuthenticateStandInProfile(context.Context, bstate.Profile) (bool, error)
				}); ok {
					available, err = authenticator.AuthenticateStandInProfile(ctx, profile)
					if err != nil {
						t.Fatal(err)
					}
				}
				now := f.Deps.Clock.Now().UTC()
				observation := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: profile.Config,
					ProfileID: profile.ID, LoginID: profile.LoginID, Generation: profile.Generation, Driver: profile.Driver,
					Provider: profile.Provider, Available: available && room, CheckedAt: api.Timestamp(now.Format(time.RFC3339Nano)),
					ExpiresAt: api.Timestamp(now.Add(4 * time.Minute).Format(time.RFC3339Nano))}
				// Component publication uses the supported owner-private evidence
				// form; the administrator publisher's service ACL is tested separately.
				data := fx.JSON(t, observation)
				profile.Evidence = api.BlobRef{ID: fx.ID(t), Class: "credential_evidence", Bytes: int64(len(data)), SHA256: fx.Digest(data)}
				cause := f.Intent(t, api.InternalOrgBootstrap)
				if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
					ObjectKey: profile.Evidence.ID, Class: profile.Evidence.Class, Bytes: data, SHA256: profile.Evidence.SHA256, Origin: "service",
					ACL: api.ObjectACL{Config: installed.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
					t.Fatal(err)
				}
				backend, err := installedSecrets(ctx, installed, f.Deps.Clock)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := backend.Close(); err != nil {
						t.Error(err)
					}
				})
				ports := &standInCredentialPorts{f: f}
				broker, err := secrets.New(secrets.Dependencies{Config: installed.Config, Store: f.State, ServiceScope: f.Execution,
					Backend: backend, Clock: f.Deps.Clock, Human: ports, ProjectionIdentity: ports, Grants: ports, Helper: ports})
				if err != nil {
					t.Fatal(err)
				}
				if err := broker.InstallProfile(ctx, profile); err != nil {
					t.Fatal(err)
				}
				f.Reserve(t)
				tx := f.SourceTransaction(t)
				inputs := tx.Writes.LaunchPlans[0].Inputs
				inputs.Sources.Runtime.Driver, inputs.Sources.Runtime.Executable = driver, declared.Executable
				inputs.Sources.Runtime.Manifest = f.Retain(t, "manifest", raw, f.Execution.Actor, "")
				if _, err := f.State.Transact(ctx, tx); err != nil {
					t.Fatal(err)
				}
				f.Record = tx.Writes.LaunchPlans[0]
				workspace := fx.ID(t)
				// The vendor directory admin's launch storage allocates for the driver (admin/launch_storage.go).
				vendor := map[api.Driver]string{api.DriverClaudock: ".claude", api.DriverCodex: ".codex"}[driver]
				ports.storage = api.LaunchStorage{ReservationID: f.Reservation.ID, Target: f.Reservation.Target, LeaseID: fx.ID(t), WorkspaceID: workspace,
					Home: api.PrivateHomeBinding{LifeID: f.Reservation.Target.LifeID, RootID: fx.ID(t), Generation: 1,
						Home: api.PrivateHome{ID: fx.ID(t), WorkspaceID: workspace, VendorDirectory: vendor, HistoryID: fx.ID(t)}}}
				issued := inputs.Grants.Profiles[0]
				claim := api.PlanningClaim(f.Reservation.ID, f.Claim)
				slot, err := broker.AcquireLaunch(ctx, api.LaunchProfileRequest{Target: f.Reservation.Target, Grant: issued,
					Claim: claim, HelperLeaseID: ports.storage.LeaseID})
				if !room {
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Code != api.CodeUnavailable || slot != (api.CredentialSlot{}) {
						t.Fatal("profile without room did not refuse unavailable", err)
					}
					return
				}
				if err != nil || slot.ID == "" || slot.ProfileID != issued.ProfileID || slot.ProfileGrantID != issued.ID {
					t.Fatal("stand-in profile did not acquire its real credential slot", err)
				}
				// Each stand-in slot carries its driver's one mode with projection code (api.CredentialTargets).
				if want := map[api.Driver]string{api.DriverClaudock: "claudock-headless", api.DriverCodex: "codex-file"}[driver]; slot.Mode != want {
					t.Errorf("stand-in slot mode is %q, want %q", slot.Mode, want)
				}
				verified, err := broker.VerifyRunnerSlot(ctx, claim, api.RunnerRequest{Target: f.Reservation.Target, Home: ports.storage.Home.Home,
					Slot: slot, Executable: declared.Executable, Model: declared.Version})
				if err != nil || verified != ports.storage {
					t.Error("runner slot read refused the acquired stand-in slot", err)
				}
				injection, err := broker.InjectLaunch(ctx, api.LaunchInjectionRequest{Claim: claim, HelperLeaseID: ports.storage.LeaseID,
					Target: f.Reservation.Target, Grants: []api.SecretGrant{}})
				if err != nil {
					t.Fatal(err)
				}
				spec := api.LaunchSpec{Kind: "agent", Grants: inputs.Grants, Injection: injection,
					Runner: &api.RunnerPlan{Driver: driver, Slot: slot, Home: ports.storage.Home.Home}}
				targets, err := api.CredentialTargets(api.CredentialProjectionRequest{Handoff: api.PreparedSpecHandoff{Spec: spec}}, f.Deps.Clock.Now())
				path := map[api.Driver]string{api.DriverClaudock: ".runnerhome-runtime/.runnerhome-token", api.DriverCodex: ".codex/auth.json"}[driver]
				if err != nil || len(targets) != 1 || targets[0].SlotID != slot.ID || targets[0].RelativePath != path {
					t.Error("acquired stand-in slot has no credential projection target", targets, err)
				}
				material, err := backend.Fetch(ctx, profile.Source)
				if err != nil {
					t.Fatal("granted credential has no encrypted source", err)
				}
				defer clear(material.Bytes)
				var retained bstate.Slot
				if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", slot.ID, &retained) }); err != nil {
					t.Fatal(err)
				}
				defer clear(retained.Material)
				if len(material.Bytes) == 0 || !bytes.Equal(retained.Material, material.Bytes) || retained.Credential != slot || retained.Grant != profile.Source || retained.Target != f.Reservation.Target {
					t.Fatal("granted slot lost actual source bytes or ownership")
				}
				// Projection checks the slot source with the driver's installed validator (secrets/projection.go): a codex-file
				// source is the enrolled account's Codex login, a claudock-headless source a headless token.
				authenticator := material.Bytes
				if driver == api.DriverCodex {
					// R2-2: the installed broker's Codex port (assembly.go) checks the projected slot bytes (secrets/projection.go:184)
					// and the file a normal release returns (:859, from admin/credlife_linux.go:439-447). The stand-in fixture never
					// writes its vendor directory, so that release returns the projected slot bytes.
					var installed secrets.CodexCredentialValidator = codex.CredentialValidator{}
					if err := installed.ValidateCodexCredential(profile.ID, profile.LoginID, profile.AccountSHA256, retained.Material); err != nil {
						t.Error("Codex stand-in slot bytes fail their pinned projection and release refresh validation", err)
					}
					var login struct {
						Tokens struct {
							Access []byte `json:"access_token"`
						} `json:"tokens"`
					}
					if err := json.Unmarshal(material.Bytes, &login); err != nil || len(login.Tokens.Access) == 0 {
						t.Fatal("Codex stand-in source does not carry the authenticator bytes in its login tokens", err)
					}
					authenticator = login.Tokens.Access
					defer clear(authenticator)
					// The validator is not loosened: the bare authenticator file, or the login for another account, still refuses.
					other := fx.Digest([]byte("another-account"))
					if installed.ValidateCodexCredential(profile.ID, profile.LoginID, profile.AccountSHA256, authenticator) == nil ||
						installed.ValidateCodexCredential(profile.ID, profile.LoginID, other, retained.Material) == nil {
						t.Error("pinned Codex validation accepted a non-Codex file or another account")
					}
				} else if err := (claudock.CredentialValidator{}).ValidateHeadlessCredential(string(profile.ID), string(profile.LoginID), material.Bytes); err != nil {
					t.Error("Claudock stand-in source fails its projection validator", err)
				}
				var fixture map[string]any
				if err := json.Unmarshal(authenticator, &fixture); err != nil || fixture["program"] != "laneboss-e2e-authenticator" || fixture["vendor_stood_in"] != true {
					t.Fatal("stand-in material lost its E2E authenticator label", err)
				}
				for _, name := range []string{string(profile.Source.SourceHandle) + ".json", ".broker-profile-" + string(profile.ID) + ".json", ".broker-slot-" + string(slot.ID) + ".json"} {
					path := filepath.Join(installed.SecretDirectory, "records", name)
					ciphertext, err := os.ReadFile(path)
					if err != nil || bytes.Contains(ciphertext, material.Bytes) || bytes.Contains(ciphertext, []byte(base64.StdEncoding.EncodeToString(material.Bytes))) {
						t.Fatal("credential source/profile/slot was absent or plaintext", err)
					}
					info, err := os.Stat(path)
					if err != nil || !owned(info, installed.ServiceUID) || info.Mode().Perm() != 0600 {
						t.Fatal("encrypted credential record lost protected ownership", err)
					}
				}
				drifted := profile
				drifted.AccountSHA256 = fx.Digest([]byte("another-account"))
				if ok, err := planner.AuthenticateStandInProfile(ctx, drifted); ok || err == nil {
					t.Error("stand-in authenticator accepted an account digest other than its protected enrollment")
				}
			})
		}
	}
}
