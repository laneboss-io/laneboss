package api

import "testing"

func envFixture(t *testing.T) (CredentialProjectionRecord, CredentialExecEnvironment) {
	t.Helper()
	x, _, held, _ := projectionFixture(t)
	record := CredentialProjectionRecord{Authority: x.Authority, State: "held", Generation: held.Generation, Receipt: &held}
	r := x.Authority.Request
	exec := CredentialExecEnvironment{PreparedID: r.Prepared.ID, Stage: "vendor_exec", UID: r.Lease.UID, GID: r.Lease.GID,
		Capabilities: projectionCount(0), Backend: r.Handoff.Spec.Backend, IsolationReady: true, ObservedAt: contractStamp(contractNow()),
		EarlierNames: []string{"PATH"}, VendorNames: []string{"TASK_ACCESS"}}
	return record, exec
}

func sealEnvRecord(t *testing.T, record *CredentialProjectionRecord) {
	t.Helper()
	projectionSeal(t, &record.Authority.Request)
	record.Receipt.Prepared = record.Authority.Request.Prepared
	record.Receipt.SpecSHA256 = record.Authority.Request.Handoff.SpecSHA256
	record.Receipt.Home = record.Authority.Request.Home
}

func TestEnvAuthority(t *testing.T) {
	for _, fault := range []string{"receipt", "revision", "authority", "revoked", "count", "gid", "targets", "runner", "task", "empty", "stamp"} {
		t.Run(fault, func(t *testing.T) {
			record, exec := envFixture(t)
			if err := ValidateCredentialEnvironment(record, exec); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "receipt":
				record.Receipt.Targets[1].Mode = 0777
			case "revision":
				record.Generation++
			case "authority":
				record.Authority.Generation, record.Generation, record.Receipt.Generation = 0, 1, 1
			case "revoked":
				record.Authority.Sources[1].Revoked = true
			case "count":
				record.Authority.Sources = append(record.Authority.Sources, record.Authority.Sources[0])
			case "gid":
				record.Authority.Request.Lease.GID, exec.GID = 0, 0
			case "targets":
				record.Authority.Targets = record.Authority.Targets[:2]
				record.Authority.Sources = record.Authority.Sources[:2]
				record.Receipt.Targets = record.Receipt.Targets[:2]
				record.Receipt.HeldDescriptors = projectionCount(2)
			case "runner":
				record.Authority.Request.Handoff.Spec.Runner.EnvironmentNames = []string{"EXTRA_ACCESS"}
			case "task":
				record.Authority.Request.Handoff.Spec.Injection.TaskSecretNames = append(record.Authority.Request.Handoff.Spec.Injection.TaskSecretNames, "missing")
			case "empty":
				record.Authority.Targets, record.Authority.Sources = []CredentialTarget{}, []CredentialSourceVersion{}
				record.Receipt.Targets, record.Receipt.HeldDescriptors = []CredentialHeldTarget{}, projectionCount(0)
				record.Authority.Request.Handoff.Spec.Injection.TaskSecretNames = nil
				exec.EarlierNames = []string{"TASK_ACCESS"}
			case "stamp":
				exec.ObservedAt = "invalid"
			}
			sealEnvRecord(t, &record)
			requireLaunchInvalid(t, ValidateCredentialEnvironment(record, exec), "credential environment authority was bypassed")
		})
	}
}

func envMode(t *testing.T, mode string) (CredentialProjectionRecord, CredentialExecEnvironment) {
	t.Helper()
	record, exec := envFixture(t)
	r := &record.Authority.Request
	switch mode {
	case "headless":
		r.Handoff.Spec.Runner.Driver, r.Handoff.Spec.Runner.Slot.Mode = DriverClaudock, "claudock-headless"
		r.Handoff.Spec.Runner.Home.VendorDirectory, r.Home.Home.VendorDirectory = ".claude", ".claude"
		r.Handoff.Spec.Grants.Profiles[0].Driver = DriverClaudock
		r.Handoff.Spec.Runner.EnvironmentNames = []string{"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR", "HOME"}
		exec.VendorNames = []string{"TASK_ACCESS", "CLAUDE_CODE_OAUTH_TOKEN"}
	case "worker":
		r.Handoff.Spec.Kind, r.Handoff.Spec.Runner = "worker", nil
		r.Handoff.Spec.Worker = &WorkerPlan{Kind: "channel"}
		r.Handoff.Spec.Injection.GrantIDs, r.Handoff.Spec.Injection.SourceVersions = []ID{}, []string{}
		r.Handoff.Spec.Injection.SlotIDs, r.Handoff.Spec.Injection.TaskSecretFileNames = nil, nil
		r.Handoff.Spec.Grants.Profiles, r.Handoff.Spec.Grants.Secrets = nil, nil
		r.Handoff.Spec.Injection.TaskSecretNames = []string{"WORKER_ACCESS"}
		r.Worker = &WorkerLease{ID: "worker-lease", Kind: "channel", Target: r.Prepared.Target, ConsumedBy: r.Handoff.Spec.LaunchID,
			GrantSetID: r.Handoff.Spec.Grants.ID, Generation: 1, ExpiresAt: "2100-01-01T00:00:00Z"}
		r.WorkerCredentials = []WorkerCredential{{Name: "worker-key", SourceHandle: "worker-source", Version: "v1", Delivery: "env", Target: "WORKER_ACCESS"}}
		exec.VendorNames = []string{"WORKER_ACCESS"}
	default:
		t.Fatal("unknown fixture mode")
	}
	sealEnvRecord(t, &record)
	targets, err := CredentialTargets(*r, contractNow())
	if err != nil {
		t.Fatal(err)
	}
	record.Authority.Targets, record.Authority.Sources = targets, []CredentialSourceVersion{}
	old := record.Receipt.Targets
	record.Receipt.Targets = []CredentialHeldTarget{}
	record.Receipt.HeldDescriptors = projectionCount(uint64(len(targets)))
	for index, target := range targets {
		held := old[index]
		held.Target, held.OwnerUID, held.Mode, held.ParentMode = target, r.Lease.UID, target.FileMode, 0700
		if target.Delivery == "env" {
			held.OwnerUID, held.Mode = 0, 0600
		}
		if target.FileMode == 0400 {
			held.ReadOnlyView, held.ParentMode = true, 0500
		}
		if target.SlotID != "" && target.EnvironmentName != "" {
			held.ReadOnlyView = true
		}
		record.Receipt.Targets = append(record.Receipt.Targets, held)
		version := target.Version
		if target.SlotID != "" {
			version = "login-generation-one"
		}
		record.Authority.Sources = append(record.Authority.Sources, CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
	}
	return record, exec
}

func TestEnvModes(t *testing.T) {
	for _, mode := range []string{"headless", "worker"} {
		t.Run(mode, func(t *testing.T) {
			record, exec := envMode(t, mode)
			if err := ValidateCredentialEnvironment(record, exec); err != nil {
				t.Fatalf("selected credential mode was refused: %v", err)
			}
			exec.EarlierNames = append(exec.EarlierNames, exec.VendorNames[len(exec.VendorNames)-1])
			requireLaunchInvalid(t, ValidateCredentialEnvironment(record, exec), "selected mode leaked to an earlier environment")
		})
	}
}

func TestEnvFixedNames(t *testing.T) {
	record, exec := envFixture(t)
	record.Authority.Request.Handoff.Spec.Runner.EnvironmentNames = []string{"CODEX_HOME", "HOME", "PATH", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "TASK_ACCESS"}
	sealEnvRecord(t, &record)
	if err := ValidateCredentialEnvironment(record, exec); err != nil {
		t.Fatalf("fixed adapter environment required a task grant: %v", err)
	}
	record.Authority.Request.Handoff.Spec.Runner.EnvironmentNames = []string{"CLAUDE_CONFIG_DIR"}
	sealEnvRecord(t, &record)
	requireLaunchInvalid(t, ValidateCredentialEnvironment(record, exec), "foreign driver environment was accepted")
}

func TestEnvFile(t *testing.T) {
	record, exec := envMode(t, "headless")
	if err := ValidateCredentialEnvironment(record, exec); err != nil {
		t.Fatal(err)
	}
	record.Receipt.Targets[0].Links = 0
	requireLaunchInvalid(t, ValidateCredentialEnvironment(record, exec), "anonymous file target was accepted")
}

func TestBindFailure(t *testing.T) {
	cause := &Error{Code: CodeUnavailable, Owner: "lb-v2-admin", Retryable: true}
	failure := &CredentialBindingFailure{Cause: cause, Unbound: true}
	if !CredentialBindingRetryable(failure) || failure.Error() != cause.Error() || failure.Unwrap() != cause {
		t.Fatal("certified retry error lost its owner or eligibility")
	}
	for _, fault := range []string{"partial", "generic", "permanent", "missing", "owner"} {
		t.Run(fault, func(t *testing.T) {
			var err error
			switch fault {
			case "partial":
				err = &CredentialBindingFailure{Cause: cause}
			case "generic":
				err = cause
			case "permanent":
				other := *cause
				other.Code = CodeNotImplemented
				err = &CredentialBindingFailure{Cause: &other, Unbound: true}
			case "missing":
				err = &CredentialBindingFailure{Unbound: true}
			case "owner":
				other := *cause
				other.Owner = "lb-v2-service"
				err = &CredentialBindingFailure{Cause: &other, Unbound: true}
			}
			if CredentialBindingRetryable(err) {
				t.Fatal("uncertified binding failure became retryable")
			}
		})
	}
}
