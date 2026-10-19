//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type grantsPrepInput struct {
	Approved   api.RootGrantManifest `json:"approved"`
	Issued     api.GrantSet          `json:"issued"`
	Parent     api.ProfileGrant      `json:"parent"`
	Child      api.ProfileGrant      `json:"child"`
	Delegated  []api.ProfileGrant    `json:"delegated"`
	ProfileIDs map[string]api.ID     `json:"profile_ids"`
}

// This nonroot component uses the actual Python preparation prefix, protected
// stand-in enrollment and encrypted broker. Human/helper ports are fixtures;
// this is not an authenticated vendor or whole installed-namespace test.
func TestGrantsPrepProfiles(t *testing.T) {
	probe := filepath.Join("..", "..", "..", "e2e", "v2", "cases", "grants", "prep_probe.py")
	command := exec.Command("python3", "-B", probe, t.TempDir())
	raw, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("actual grants preparation prefix: %v\n%s", err, exit.Stderr)
		}
		t.Fatal(err)
	}
	var in grantsPrepInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	// Run the broker before checking the desired metadata: the old producer
	// must fail at its real quarantine gate, not a test-only name assertion.
	grantsPrepSlot(t, in, in.Parent, false)
	if len(in.ProfileIDs) != 2 || in.ProfileIDs["parent"] == in.ProfileIDs["child"] ||
		in.Parent.ProfileID != in.ProfileIDs["parent"] || len(in.Delegated) != 3 {
		t.Fatal("parent did not receive its actor profiles plus the explicit refusal control")
	}
	child := in.Child
	if child.ID == "" || !child.Delegate {
		t.Fatal("actual child member is absent or nondelegable")
	}
	grantsPrepSlot(t, in, child, false)
	var baseline api.ProfileGrant
	for _, member := range in.Issued.Profiles {
		if member.ProfileID == "serve-profile-codex" {
			baseline = member
		}
	}
	if baseline.ID == "" {
		t.Fatal("baseline seat disappeared")
	}
	grantsPrepSlot(t, in, baseline, true)
}

func grantsPrepSlot(t *testing.T, in grantsPrepInput, selected api.ProfileGrant, refused bool) {
	t.Helper()
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
	// Retain the selected producer scope, assigning only this store's primitive
	// ceiling identity. Reservation and the planning claim come from SQLite.
	f.Ceiling.Profiles = []api.ProfileGrant{selected}
	f.Ceiling.Profiles[0].ID = f.Start.ProfileGrantID
	f.Ceiling.Profiles[0].ParentGrantID = ""
	f.Ceiling.SHA256 = fx.Digest(fx.JSON(t, f.Ceiling))
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	f.Start.Driver, f.Start.Model = api.DriverCodex, declared.Version
	f.Start.Grants.Profiles[0].ProfileID = selected.ProfileID
	f.Start.Grants.Profiles[0].Delegate = selected.Delegate
	f.Start.Grants.Profiles[0].ExpiresAt = selected.ExpiresAt
	f.Start.Grants.Data[0].ExpiresAt = selected.ExpiresAt
	f.Admit(t, "lane.start", f.Start)
	planner := &initialFixtureProfiles{installed: installed, fixture: *declared}
	profiles, err := planner.PlanStandInProfiles(ctx, admin.InitialManifest{Config: installed.Config, Runtime: installed.RuntimeManifest}, in.Approved)
	if err != nil {
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
	logins, sources, accounts := map[api.ID]bool{}, map[api.ID]bool{}, map[api.Digest]bool{}
	var baseline api.ID
	for _, profile := range profiles {
		if profile.Driver != api.DriverCodex {
			continue
		}
		if logins[profile.LoginID] || sources[profile.Source.SourceHandle] || accounts[profile.AccountSHA256] {
			t.Fatal("item actor shares a canonical login, source or account")
		}
		logins[profile.LoginID], sources[profile.Source.SourceHandle], accounts[profile.AccountSHA256] = true, true, true
		available, err := planner.AuthenticateStandInProfile(ctx, profile)
		if err != nil || !available {
			t.Fatal("protected stand-in enrollment", err)
		}
		now := f.Deps.Clock.Now().UTC()
		data := fx.JSON(t, bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: profile.Config,
			ProfileID: profile.ID, LoginID: profile.LoginID, Generation: profile.Generation, Driver: profile.Driver,
			Provider: profile.Provider, Available: available, CheckedAt: api.Timestamp(now.Format(time.RFC3339Nano)),
			ExpiresAt: api.Timestamp(now.Add(4 * time.Minute).Format(time.RFC3339Nano))})
		profile.Evidence = api.BlobRef{ID: fx.ID(t), Class: "credential_evidence", Bytes: int64(len(data)), SHA256: fx.Digest(data)}
		cause := f.Intent(t, api.InternalOrgBootstrap)
		if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
			ObjectKey: profile.Evidence.ID, Class: profile.Evidence.Class, Bytes: data, SHA256: profile.Evidence.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: installed.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
			t.Fatal(err)
		}
		if err := broker.InstallProfile(ctx, profile); err != nil {
			t.Fatal(err)
		}
		if profile.ID == "serve-profile-codex" {
			baseline = profile.LoginID
		}
	}
	if baseline == "" {
		t.Fatal("baseline login was not enrolled")
	}
	// This is the protected marker left by ruling b. Its normal-release
	// producer is exercised by TestRulingBCodexReleaseRetires in the same run.
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error {
		var login bstate.Login
		if err := j.Read("login", baseline, &login); err != nil {
			return err
		}
		defer clear(login.Material)
		login.Quarantined = true
		return j.Write("login", baseline, login)
	}); err != nil {
		t.Fatal(err)
	}
	f.Reserve(t)
	tx := f.SourceTransaction(t)
	inputs := tx.Writes.LaunchPlans[0].Inputs
	inputs.Sources.Runtime.Driver, inputs.Sources.Runtime.Executable = api.DriverCodex, declared.Executable
	inputs.Sources.Runtime.Manifest = f.Retain(t, "manifest", raw, f.Execution.Actor, "")
	if _, err := f.State.Transact(ctx, tx); err != nil {
		t.Fatal(err)
	}
	f.Record = tx.Writes.LaunchPlans[0]
	workspace := fx.ID(t)
	ports.storage = api.LaunchStorage{ReservationID: f.Reservation.ID, Target: f.Reservation.Target, LeaseID: fx.ID(t), WorkspaceID: workspace,
		Home: api.PrivateHomeBinding{LifeID: f.Reservation.Target.LifeID, RootID: fx.ID(t), Generation: 1,
			Home: api.PrivateHome{ID: fx.ID(t), WorkspaceID: workspace, VendorDirectory: ".codex", HistoryID: fx.ID(t)}}}
	slot, err := broker.AcquireLaunch(ctx, api.LaunchProfileRequest{Target: f.Reservation.Target, Grant: inputs.Grants.Profiles[0],
		Claim: api.PlanningClaim(f.Reservation.ID, f.Claim), HelperLeaseID: ports.storage.LeaseID})
	if refused {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeForbidden ||
			!strings.Contains(typed.Message, "canonical credential is quarantined pending protected rotation") || slot.ID != "" {
			t.Fatal("quarantined-seat twin did not retain its exact refusal", err)
		}
	} else if err != nil || slot.ProfileID != selected.ProfileID || slot.ID == "" {
		t.Fatal("actual item.grants.prepare profile cannot acquire its slot", err)
	}
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error {
		var login bstate.Login
		if err := j.Read("login", baseline, &login); err != nil {
			return err
		}
		defer clear(login.Material)
		if !login.Quarantined || login.SlotID != "" {
			t.Fatal("preparation changed the baseline quarantine")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Run preparation with a real disposable Codex Git worktree as cwd. All
// publication inputs live outside it. Unforced Git removal is the dirty-work
// oracle used by the native collector, not a manufactured cleaned flag.
func TestGrantsPrepWorktree(t *testing.T) {
	probe, err := filepath.Abs(filepath.Join("..", "..", "..", "e2e", "v2", "cases", "grants", "prep_probe.py"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	main, work, inputs := filepath.Join(base, "main"), filepath.Join(base, "codex"), filepath.Join(base, "inputs")
	if err := os.Mkdir(inputs, 0700); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) ([]byte, error) {
		command := exec.Command("git", args...)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
		return command.CombinedOutput()
	}
	for _, args := range [][]string{{"init", "--quiet", main}, {"-C", main, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "--allow-empty", "-m", "initial"},
		{"-C", main, "worktree", "add", "--quiet", "-b", "codex", work}} {
		if raw, err := git(args...); err != nil {
			t.Fatalf("disposable Git setup: %v: %s", err, raw)
		}
	}
	command := exec.Command("python3", "-B", probe, inputs)
	command.Dir = work
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual preparation in Codex cwd: %v: %s", err, raw)
	}
	status, err := git("-C", work, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching")
	if err != nil || len(status) != 0 {
		t.Fatal("actual preparation dirtied the Codex worktree", err)
	}
	control := filepath.Join(work, "profile-control")
	if err := os.WriteFile(control, []byte("dirty-work canary\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := git("-C", main, "worktree", "remove", "--", work); err == nil {
		t.Fatal("dirty-work twin bypassed unforced removal")
	}
	if _, err := os.Stat(control); err != nil {
		t.Fatal("dirty-work twin lost its retained bytes", err)
	}
	if err := os.Remove(control); err != nil {
		t.Fatal(err)
	}
	if raw, err := git("-C", main, "worktree", "remove", "--", work); err != nil {
		t.Fatalf("clean Codex worktree did not collect: %v: %s", err, raw)
	}
	if raw, err := git("-C", main, "branch", "-d", "--", "codex"); err != nil {
		t.Fatalf("clean Codex branch did not collect: %v: %s", err, raw)
	}
	if _, err := os.Stat(work); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Codex worktree remains", err)
	}
	raw, err := git("-C", main, "show-ref", "--verify", "--quiet", "refs/heads/codex")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(raw) != 0 {
		t.Fatal("Codex branch remains or absence is uncertain", err)
	}
	t.Log("actual producer left Codex Git clean; dirty twin retained; unforced worktree and branch collection passed")
}

func TestGrantsProfileScope(t *testing.T) {
	probe := filepath.Join("..", "..", "..", "e2e", "v2", "cases", "grants", "profile_test.py")
	command := exec.Command("python3", "-B", probe, "-v")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual profile-scope controls: %v\n%s", err, raw)
	}
}

func TestGrantsReuseRequired(t *testing.T) {
	probe := filepath.Join("..", "..", "..", "e2e", "v2", "cases", "grants", "reuse_test.py")
	command := exec.Command("python3", "-B", probe, "Reuse.test_required", "-v")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installed seat-reuse gate: %v\n%s", err, raw)
	}
}

func TestGrantsReuseControls(t *testing.T) {
	probe := filepath.Join("..", "..", "..", "e2e", "v2", "cases", "grants", "reuse_test.py")
	command := exec.Command("python3", "-B", probe, "-v")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("seat-reuse evidence controls: %v\n%s", err, raw)
	}
}
