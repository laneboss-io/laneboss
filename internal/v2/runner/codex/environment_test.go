package codex

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Coherent retained spec plus explicit synthetic native observations. These
// validate the consumer gate, not a real UID drop or installed isolation.
func finalEnvFixture(t *testing.T) (api.CredentialProjectionRecord, api.CredentialExecEnvironment, api.PrivateHome) {
	t.Helper()
	f := newFixture(t)
	f.sealCapture()
	plan := f.currentPlan()
	bound := f.store.bindings[plan.Reservation.LaunchID]
	r := api.CredentialProjectionRequest{Handoff: fixtureCopy(bound.Recovery.Handoff), Prepared: bound.Prepared,
		Lease: plan.Plan.Lease, Home: plan.Plan.Data.Home}
	spec := &r.Handoff.Spec
	spec.Grants.Secrets = []api.SecretGrant{{ID: "task_grant", Name: "access", SourceHandle: "task_source", Version: "v1",
		Delivery: "env", Target: "TASK_ACCESS", ExpiresAt: f.request.Slot.ExpiresAt}}
	spec.Injection.GrantIDs, spec.Injection.SourceVersions = []api.ID{"task_grant"}, []string{"v1"}
	spec.Injection.TaskSecretNames = []string{"TASK_ACCESS"}
	spec.Runner.EnvironmentNames = append(environmentNames(), "TASK_ACCESS")
	r.Handoff.Original = f.keepJSON(*spec, "launch_spec")
	r.Handoff.SpecSHA256, r.Prepared.SpecSHA256 = r.Handoff.Original.SHA256, r.Handoff.Original.SHA256
	r.Cause = r.Handoff.Cause
	r.Cause.ID, r.Cause.Kind, r.Cause.EffectID = "prepare_intent", api.InternalHelperPrepare, "prepare_effect"
	r.Claim = api.EffectLease{ClaimID: "prepare_claim", ExpiresAt: f.request.Slot.ExpiresAt,
		Record: api.EffectRecord{State: api.EffectClaimed, Generation: 1, ClaimID: "prepare_claim", ClaimantID: r.Cause.Actor.ID,
			ClaimExpiresAt: f.request.Slot.ExpiresAt, Effect: api.Effect{ID: r.Cause.EffectID, OperationID: r.Cause.CauseOperationID, Context: &r.Cause,
				HelperPrepare: &api.HelperLaunchRequest{Cause: r.Cause, LeaseID: r.Lease.ID, PreparedSpecID: spec.ID, SpecSHA256: r.Prepared.SpecSHA256}}}}
	if err := api.ValidateCredentialProjectionRequest(r, f.clock.Now()); err != nil {
		t.Fatal("invalid final environment request", err)
	}
	targets, err := api.CredentialTargets(r, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	zero, heldCount := uint64(0), uint64(len(targets))
	authority := api.CredentialProjectionAuthority{ID: "environment_projection", Generation: 1, Request: r, Targets: targets}
	held := api.CredentialProjectionReceipt{ProjectionID: authority.ID, Generation: 2, Prepared: r.Prepared, HelperLeaseID: r.Lease.ID,
		SpecSHA256: r.Handoff.SpecSHA256, Home: r.Home, CancellationEpoch: r.Cause.CancellationEpoch,
		HeldDescriptors: &heldCount, InheritedSources: &zero, GateClosed: true, ObservedAt: api.Timestamp(f.clock.Now().Format(time.RFC3339Nano))}
	for index, target := range targets {
		version := target.Version
		if version == "" {
			version = "login_revision_one"
		}
		authority.Sources = append(authority.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
		item := api.CredentialHeldTarget{Target: target, SourceObjectID: "source_" + strconv.Itoa(index), ObjectID: "held_" + strconv.Itoa(index),
			RootID: r.Home.RootID, HomeGeneration: r.Home.Generation, OwnerUID: r.Lease.UID, Mode: target.FileMode, ParentMode: 0700, Links: 1}
		if target.Delivery == "env" {
			item.OwnerUID, item.Mode, item.Links = 0, 0600, 0
		}
		held.Targets = append(held.Targets, item)
	}
	record := api.CredentialProjectionRecord{Authority: authority, Generation: 2, State: "held", Receipt: &held}
	capabilities := uint64(0)
	observed := api.CredentialExecEnvironment{PreparedID: r.Prepared.ID, Stage: "vendor_exec", UID: r.Lease.UID, GID: r.Lease.GID,
		Capabilities: &capabilities, IsolationReady: true, Backend: spec.Backend, ObservedAt: held.ObservedAt,
		EarlierNames: []string{"PATH"}, VendorNames: append(environmentNames(), "TASK_ACCESS")}
	if err := api.ValidateCredentialEnvironment(record, observed); err != nil {
		t.Fatal("invalid final environment holding fixture", err)
	}
	home := f.request.Home
	home.VendorDirectory = filepath.Join(f.home.path, ".codex")
	return record, observed, home
}

func TestFinalEnv(t *testing.T) {
	for _, fault := range []string{"early", "root", "caps", "isolation", "earlier", "missing", "unselected", "nul", "names"} {
		t.Run(fault, func(t *testing.T) {
			record, observed, home := finalEnvFixture(t)
			value := []byte("synthetic private buffer " + t.Name())
			task := map[string][]byte{"TASK_ACCESS": value}
			control, err := FinalEnvironment(record, observed, home, "/usr/bin:/bin", task)
			if err != nil || len(control) != 8 || control[7] != "TASK_ACCESS="+string(value) {
				t.Fatal("valid final vendor environment refused", err)
			}
			base, err := Environment(home, "/usr/bin:/bin")
			if err != nil || strings.Contains(strings.Join(base, "\n"), "TASK_ACCESS=") {
				t.Fatal("task value entered the outer environment", err)
			}
			code := api.CodeInvalid
			switch fault {
			case "early":
				observed.Stage = "bootstrap"
			case "root":
				observed.UID = 0
			case "caps":
				*observed.Capabilities = 1
			case "isolation":
				observed.IsolationReady = false
			case "earlier":
				observed.EarlierNames = append(observed.EarlierNames, "TASK_ACCESS")
			case "missing":
				delete(task, "TASK_ACCESS")
				code = api.CodeIntegrity
			case "unselected":
				delete(task, "TASK_ACCESS")
				task["OPENAI_API_KEY"] = value
				code = api.CodeIntegrity
			case "nul":
				task["TASK_ACCESS"] = append(value, 0)
				code = api.CodeIntegrity
			case "names":
				observed.VendorNames[0] = "ANOTHER_NAME"
				code = api.CodeIntegrity
			}
			actual, err := FinalEnvironment(record, observed, home, "/usr/bin:/bin", task)
			wantCode(t, err, code)
			if actual != nil {
				t.Fatal("refused final environment returned values")
			}
		})
	}
}
