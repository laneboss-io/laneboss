package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func projectionCount(value uint64) *uint64 { return &value }

// Native peer/ownership observations here are correlation fixtures. The files
// are real read-only unlinked test descriptors, not a native authentication or
// namespace proof; those must be measured by the administrator implementation.
func projectionFixture(t *testing.T) (CredentialTransfer, []CredentialDescriptorFact, CredentialProjectionReceipt, LaunchBindingRequest) {
	t.Helper()
	plan := launchFixture(t)
	plan.Runner.Slot.Mode = "codex-file"
	plan.Inputs.Grants.Secrets = []SecretGrant{
		{ID: "env-grant", Name: "access", SourceHandle: "env-source", Version: "v1", Delivery: "env", Target: "TASK_ACCESS", ExpiresAt: "2100-01-01T00:00:00Z"},
		{ID: "file-grant", Name: "tool", SourceHandle: "file-source", Version: "v2", Delivery: "file", Target: "tool-token", ExpiresAt: "2100-01-01T00:00:00Z"},
	}
	plan.Injection.GrantIDs, plan.Injection.SourceVersions = []ID{"env-grant", "file-grant"}, []string{"v1", "v2"}
	plan.Injection.TaskSecretNames, plan.Injection.TaskSecretFileNames = []string{"TASK_ACCESS"}, []string{"tool-token"}
	binding := launchFixtureBinding(t, plan)
	cause := binding.Recovery.Handoff.Cause
	cause.ID, cause.Kind, cause.EffectID = "prepare-intent", InternalHelperPrepare, "prepare-effect"
	request := CredentialProjectionRequest{Cause: cause, Handoff: binding.Recovery.Handoff, Prepared: binding.Prepared, Lease: plan.Lease, Home: plan.Data.Home}
	request.Claim = EffectLease{ClaimID: "prepare-claim", ExpiresAt: "2100-01-01T00:00:00Z", Record: EffectRecord{
		State: "claimed", Generation: 1, ClaimID: "prepare-claim", ClaimantID: "service-one", ClaimExpiresAt: "2100-01-01T00:00:00Z",
		Effect: Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause,
			HelperPrepare: &HelperLaunchRequest{Cause: cause, LeaseID: plan.Lease.ID, PreparedSpecID: plan.Reservation.SpecID, SpecSHA256: binding.Prepared.SpecSHA256}}}}
	targets, err := CredentialTargets(request, contractNow())
	if err != nil {
		t.Fatal(err)
	}
	authority := CredentialProjectionAuthority{ID: "credential-projection", Generation: 1, Request: request, Targets: targets,
		Helper:     Executable{ID: "installed-helper", Version: "fixture", SHA256: launchFixtureBlob("helper", "manifest").SHA256},
		Broker:     Executable{ID: "credential-worker", Version: "fixture", SHA256: launchFixtureBlob("broker", "manifest").SHA256},
		HelperPeer: PeerFacts{HostPID: 101, ProcessGeneration: "helper-generation"},
		BrokerPeer: PeerFacts{HostUID: 13001, HostGID: 13001, HostPID: 102, ProcessGeneration: "broker-generation", ContainmentID: "broker-containment"},
		ServiceUID: 11001, InstallationGeneration: 1, BootID: "boot-one"}
	transfer := CredentialTransfer{Authority: authority}
	facts := []CredentialDescriptorFact{}
	receipt := CredentialProjectionReceipt{ProjectionID: authority.ID, Generation: 2, Prepared: request.Prepared,
		HelperLeaseID: plan.Lease.ID, SpecSHA256: request.Handoff.SpecSHA256, Home: request.Home, CancellationEpoch: cause.CancellationEpoch,
		HeldDescriptors: projectionCount(uint64(len(targets))), InheritedSources: projectionCount(0), GateClosed: true, ObservedAt: contractStamp(contractNow())}
	for index, target := range targets {
		file, err := os.CreateTemp(t.TempDir(), "projection-")
		if err != nil {
			t.Fatal(err)
		}
		name := file.Name()
		if _, err := file.WriteString("synthetic descriptor payload\n"); err != nil {
			t.Fatal(err)
		}
		if err := file.Chmod(0600); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		file, err = os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Error(err)
			}
		})
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
		stat, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		sourceID := fmt.Sprintf("source-object-%d", index)
		transfer.Files = append(transfer.Files, file)
		version := target.Version
		if target.SlotID != "" {
			version = "login-generation-one"
		}
		transfer.Authority.Sources = append(transfer.Authority.Sources, CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
		facts = append(facts, CredentialDescriptorFact{ObjectID: sourceID, OwnerUID: authority.BrokerPeer.HostUID, Mode: uint32(stat.Mode().Perm()), Size: stat.Size(),
			Regular: stat.Mode().IsRegular(), ReadOnly: true, CloseOnExec: true, WritableHandles: projectionCount(0)})
		held := CredentialHeldTarget{Target: target, SourceObjectID: sourceID, ObjectID: fmt.Sprintf("projected-object-%d", index), RootID: request.Home.RootID,
			HomeGeneration: request.Home.Generation, OwnerUID: plan.Lease.UID, Mode: target.FileMode, ParentMode: 0700, Links: 1}
		if target.Delivery == "env" {
			held.OwnerUID, held.Mode = 0, 0600
		}
		if target.FileMode == 0400 {
			held.ParentMode, held.ReadOnlyView = 0500, true
		}
		receipt.Targets = append(receipt.Targets, held)
	}
	return transfer, facts, receipt, binding
}

func projectionSeal(t *testing.T, request *CredentialProjectionRequest) {
	t.Helper()
	encoded, digest := launchFixtureHash(t, request.Handoff.Spec)
	request.Handoff.SpecSHA256, request.Prepared.SpecSHA256 = digest, digest
	request.Handoff.Original.SHA256, request.Handoff.Original.Bytes = digest, int64(len(encoded))
	request.Claim.Record.Effect.HelperPrepare.SpecSHA256 = digest
}

func TestProjectionTargets(t *testing.T) {
	transfer, _, _, _ := projectionFixture(t)
	r := transfer.Authority.Request
	targets, err := CredentialTargets(r, contractNow())
	if err != nil || len(targets) != 3 || targets[0].RelativePath != ".codex/auth.json" || targets[1].EnvironmentName != "TASK_ACCESS" || targets[2].RelativePath != ".laneboss-secrets/tool-token" {
		t.Fatalf("credential destinations did not follow the selected mode and grants: %v", err)
	}
	t.Run("headless", func(t *testing.T) {
		x, _, _, _ := projectionFixture(t)
		r := x.Authority.Request
		r.Handoff.Spec.Runner.Driver, r.Handoff.Spec.Runner.Slot.Mode = DriverClaudock, "claudock-headless"
		r.Handoff.Spec.Runner.Home.VendorDirectory = ".claude"
		r.Handoff.Spec.Grants.Profiles[0].Driver = DriverClaudock
		items, err := CredentialTargets(r, contractNow())
		if err != nil || items[0].RelativePath != ".runnerhome-runtime/.runnerhome-token" || items[0].EnvironmentName != "CLAUDE_CODE_OAUTH_TOKEN" {
			t.Fatalf("headless mode lost its fixed projection: %v", err)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		r.Handoff.Spec.Runner.Slot.Mode = "codex-api"
		var typed *Error
		if _, err := CredentialTargets(r, contractNow()); !errors.As(err, &typed) || typed.Code != CodeNotImplemented || typed.Owner != "lb-v2-secrets" {
			t.Fatalf("unimplemented profile mode acquired a projection: %v", err)
		}
	})
	for _, fault := range []string{"expired", "profile", "reserved", "go-runtime", "tunables", "traversal", "version", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			x, _, _, _ := projectionFixture(t)
			r := x.Authority.Request
			switch fault {
			case "expired":
				r.Handoff.Spec.Runner.Slot.ExpiresAt = contractStamp(contractNow())
			case "profile":
				r.Handoff.Spec.Grants.Profiles[0].ProfileID = "other-profile"
			case "reserved":
				r.Handoff.Spec.Grants.Secrets[0].Target = "HOME"
			case "go-runtime":
				r.Handoff.Spec.Grants.Secrets[0].Target = "GOMAXPROCS"
			case "tunables":
				r.Handoff.Spec.Grants.Secrets[0].Target = "GLIBC_TUNABLES"
			case "traversal":
				r.Handoff.Spec.Grants.Secrets[1].Target = "../outside"
			case "version":
				r.Handoff.Spec.Injection.SourceVersions[0] = "other-version"
			case "duplicate":
				r.Handoff.Spec.Injection.GrantIDs = append(r.Handoff.Spec.Injection.GrantIDs, "env-grant")
				r.Handoff.Spec.Injection.SourceVersions = append(r.Handoff.Spec.Injection.SourceVersions, "v1")
			}
			_, err := CredentialTargets(r, contractNow())
			requireLaunchInvalid(t, err, "credential target boundary was bypassed")
		})
	}
}

func TestProjectionRequest(t *testing.T) {
	x, _, _, _ := projectionFixture(t)
	if err := ValidateCredentialProjectionRequest(x.Authority.Request, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"home", "claim", "payload", "epoch", "digest"} {
		t.Run(fault, func(t *testing.T) {
			x, _, _, _ := projectionFixture(t)
			r := x.Authority.Request
			switch fault {
			case "home":
				r.Home.RootID = "foreign-home"
				// The held helper root is independently correlated by the receipt;
				// request shape pins the life, home descriptor and root revision.
				r.Home.LifeID = "foreign-life"
			case "claim":
				r.Claim.ExpiresAt = contractStamp(contractNow())
				r.Claim.Record.ClaimExpiresAt = r.Claim.ExpiresAt
			case "payload":
				r.Claim.Record.Effect.HelperPrepare.PreparedSpecID = "foreign-spec"
			case "epoch":
				r.Cause.CancellationEpoch++
				r.Claim.Record.Effect.Context = &r.Cause
				r.Claim.Record.Effect.HelperPrepare.Cause = r.Cause
			case "digest":
				r.Handoff.Spec.PolicyGeneration++
				projectionSeal(t, &r)
				r.Prepared.SpecSHA256 = x.Authority.Request.Prepared.SpecSHA256
			}
			requireLaunchInvalid(t, ValidateCredentialProjectionRequest(r, contractNow()), "credential request boundary was bypassed")
		})
	}
}

func TestProjectionWorker(t *testing.T) {
	x, _, _, _ := projectionFixture(t)
	r := x.Authority.Request
	r.Handoff.Spec.Kind, r.Handoff.Spec.Runner = "worker", nil
	r.Handoff.Spec.Worker = &WorkerPlan{Kind: "channel"}
	r.Handoff.Spec.Injection.GrantIDs, r.Handoff.Spec.Injection.SourceVersions = []ID{}, []string{}
	r.Worker = &WorkerLease{ID: "channel-lease", Kind: "channel", Target: r.Prepared.Target, ConsumedBy: r.Handoff.Spec.LaunchID,
		GrantSetID: r.Handoff.Spec.Grants.ID, Generation: 1, ExpiresAt: "2100-01-01T00:00:00Z"}
	r.WorkerCredentials = []WorkerCredential{{Name: "channel-key", SourceHandle: "channel-source", Version: "v1", Delivery: "env", Target: "CHANNEL_ACCESS"}}
	items, err := CredentialTargets(r, contractNow())
	if err != nil || len(items) != 1 || items[0].SourceHandle != r.WorkerCredentials[0].SourceHandle || items[0].EnvironmentName != "CHANNEL_ACCESS" {
		t.Fatalf("worker projection lost its selected protected credentials: %v", err)
	}
	r.Worker.Kind, r.Handoff.Spec.Worker.Kind = "capture", "capture"
	_, err = CredentialTargets(r, contractNow())
	requireLaunchInvalid(t, err, "worker credential boundary was bypassed")
}

func TestProjectionTransfer(t *testing.T) {
	x, facts, _, _ := projectionFixture(t)
	if err := ValidateCredentialTransfer(x, facts, contractNow()); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(x)
	if err != nil || bytes.Contains(encoded, []byte(`"Files"`)) || bytes.Contains(encoded, []byte("synthetic descriptor payload")) {
		t.Fatalf("credential descriptors serialized: %v", err)
	}
	for _, fault := range []string{"linked", "readonly", "inherit", "writer", "owner", "broker", "helper", "source", "version", "count", "destination"} {
		t.Run(fault, func(t *testing.T) {
			x, facts, _, _ := projectionFixture(t)
			switch fault {
			case "linked":
				facts[0].Links = 1
			case "readonly":
				facts[0].ReadOnly = false
			case "inherit":
				facts[0].CloseOnExec = false
			case "writer":
				facts[0].WritableHandles = projectionCount(1)
			case "owner":
				facts[0].OwnerUID = x.Authority.Request.Lease.UID
			case "broker":
				x.Authority.BrokerPeer.HostUID = x.Authority.Request.Lease.UID
				for i := range facts {
					facts[i].OwnerUID = x.Authority.BrokerPeer.HostUID
				}
			case "helper":
				x.Authority.HelperPeer.HostUID = x.Authority.Request.Lease.UID
			case "source":
				x.Authority.Sources[0].Revoked = true
			case "version":
				x.Authority.Sources[1].Version = "other-version"
			case "count":
				x.Files = x.Files[:len(x.Files)-1]
			case "destination":
				x.Authority.Targets[0].RelativePath = ".codex/other.json"
			}
			requireLaunchInvalid(t, ValidateCredentialTransfer(x, facts, contractNow()), "credential descriptor boundary was bypassed")
		})
	}
}

func TestProjectionReceipt(t *testing.T) {
	x, facts, receipt, _ := projectionFixture(t)
	if err := ValidateCredentialProjectionReceipt(x, facts, receipt, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"alias", "root", "revision", "owner", "held", "inherit", "gate", "readonly", "received"} {
		t.Run(fault, func(t *testing.T) {
			x, facts, receipt, _ := projectionFixture(t)
			switch fault {
			case "alias":
				receipt.Targets[0].ObjectID = receipt.Targets[0].SourceObjectID
			case "root":
				receipt.Targets[0].RootID = "foreign-root"
			case "revision":
				receipt.Targets[0].HomeGeneration++
			case "owner":
				receipt.Targets[0].OwnerUID++
			case "held":
				receipt.HeldDescriptors = nil
			case "inherit":
				receipt.InheritedSources = projectionCount(1)
			case "gate":
				receipt.GateClosed = false
			case "readonly":
				receipt.Targets[2].ReadOnlyView = false
			case "received":
				receipt.Targets[0].SourceObjectID = "other-source"
			}
			requireLaunchInvalid(t, ValidateCredentialProjectionReceipt(x, facts, receipt, contractNow()), "credential held projection was bypassed")
		})
	}
}

func TestProjectionGate(t *testing.T) {
	x, _, receipt, binding := projectionFixture(t)
	record := CredentialProjectionRecord{Authority: x.Authority, Generation: 2, State: "held", Receipt: &receipt}
	if err := ValidateCredentialProjectionGate(record, binding, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"state", "revoked", "source", "fence", "receipt", "binding", "targets"} {
		t.Run(fault, func(t *testing.T) {
			x, _, receipt, binding := projectionFixture(t)
			record := CredentialProjectionRecord{Authority: x.Authority, Generation: 2, State: "held", Receipt: &receipt}
			switch fault {
			case "state":
				record.State = "withdrawing"
			case "revoked":
				record.Authority.Revoked = true
			case "source":
				record.Authority.Sources[0].Revoked = true
			case "fence":
				record.Fence = &CredentialWithdrawalRequest{ProjectionID: record.Authority.ID}
			case "receipt":
				record.Receipt = nil
			case "binding":
				binding.Record.HostUID++
			case "targets":
				receipt.Targets = nil
			}
			requireLaunchInvalid(t, ValidateCredentialProjectionGate(record, binding, contractNow()), "credential gate boundary was bypassed")
		})
	}
}

func TestProjectionLock(t *testing.T) {
	x, _, receipt, binding := projectionFixture(t)
	record := CredentialProjectionRecord{Authority: x.Authority, Generation: 2, State: "held", Receipt: &receipt}
	cause := x.Authority.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "open-intent", InternalHelperOpen, "open-effect"
	request := CredentialGateRequest{ProjectionID: x.Authority.ID, ExpectedGeneration: record.Generation, Open: HelperOpenRequest{
		Cause: cause, Prepared: binding.Prepared, OperationID: cause.CauseOperationID, EffectID: cause.EffectID,
		Permit: LaunchPermit{LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, RecordSHA256: binding.Identity.RecordSHA256, CommittedSeq: binding.Identity.CommittedSeq}}}
	if err := ValidateCredentialGateRequest(record, request, binding, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"revision", "permit", "epoch"} {
		t.Run(fault, func(t *testing.T) {
			r := request
			switch fault {
			case "revision":
				r.ExpectedGeneration++
			case "permit":
				r.Open.Permit.RecordSHA256 = launchFixtureBlob("other-record", "manifest").SHA256
			case "epoch":
				r.Open.Cause.CancellationEpoch++
			}
			requireLaunchInvalid(t, ValidateCredentialGateRequest(record, r, binding, contractNow()), "credential gate lock was bypassed")
		})
	}
}

func withdrawalFixture(t *testing.T) (CredentialProjectionRecord, CredentialWithdrawalReceipt) {
	t.Helper()
	x, _, held, _ := projectionFixture(t)
	cause := x.Authority.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "withdraw-intent", InternalHelperAbort, "withdraw-effect"
	fence := CredentialWithdrawalRequest{ProjectionID: x.Authority.ID, ExpectedGeneration: 2, Cause: cause, Reason: "revoked"}
	record := CredentialProjectionRecord{Authority: x.Authority, Generation: 2, State: "held", Receipt: &held}
	if err := ValidateCredentialWithdrawalRequest(record, fence); err != nil {
		t.Fatal(err)
	}
	record.Generation, record.State, record.Fence = 3, "withdrawing", &fence
	r := x.Authority.Request
	receipt := CredentialWithdrawalReceipt{ProjectionID: x.Authority.ID, Generation: 4, Cause: cause, Prepared: r.Prepared, HelperLeaseID: r.Lease.ID, Home: r.Home,
		Observation:       ProcessObservation{Handle: ProcessHandle{ID: "original-process", Target: r.Prepared.Target, ContainmentID: r.Prepared.ContainmentID, Generation: r.Prepared.ProcessGeneration}, State: "absent", Survivors: projectionCount(0), ObservedAt: contractStamp(contractNow())},
		HelperDescriptors: projectionCount(0), ProjectedFiles: projectionCount(0), EnvironmentBuffers: projectionCount(0), OpenGates: projectionCount(0),
		BrokerDescriptors: projectionCount(0), RefreshLeases: projectionCount(0), ObservedAt: contractStamp(contractNow())}
	return record, receipt
}

func TestProjectionWithdraw(t *testing.T) {
	record, receipt := withdrawalFixture(t)
	if err := ValidateCredentialWithdrawal(record, receipt); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"unknown", "helper", "files", "environment", "gate", "broker", "refresh", "survivors", "cause", "home", "fence"} {
		t.Run(fault, func(t *testing.T) {
			record, receipt := withdrawalFixture(t)
			switch fault {
			case "unknown":
				receipt.HelperDescriptors = nil
			case "helper":
				receipt.HelperDescriptors = projectionCount(1)
			case "files":
				receipt.ProjectedFiles = projectionCount(1)
			case "environment":
				receipt.EnvironmentBuffers = projectionCount(1)
			case "gate":
				receipt.OpenGates = projectionCount(1)
			case "broker":
				receipt.BrokerDescriptors = projectionCount(1)
			case "refresh":
				receipt.RefreshLeases = projectionCount(1)
			case "survivors":
				receipt.Observation.Survivors = projectionCount(1)
			case "cause":
				receipt.Cause.ID = "other-intent"
			case "home":
				receipt.Home.RootID = "other-home"
			case "fence":
				record.Fence.ExpectedGeneration++
			}
			requireLaunchInvalid(t, ValidateCredentialWithdrawal(record, receipt), "credential withdrawal boundary was bypassed")
		})
	}
}

func TestProjectionFence(t *testing.T) {
	x, _, held, _ := projectionFixture(t)
	record := CredentialProjectionRecord{Authority: x.Authority, Generation: 2, State: "held", Receipt: &held}
	cause := x.Authority.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "cancel-intent", InternalHelperStop, "cancel-effect"
	request := CredentialWithdrawalRequest{ProjectionID: record.Authority.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: "cancelled"}
	if err := ValidateCredentialWithdrawalRequest(record, request); err != nil {
		t.Fatal(err)
	}
	request.ExpectedGeneration++
	requireLaunchInvalid(t, ValidateCredentialWithdrawalRequest(record, request), "credential fence revision was bypassed")
}

func TestProjectionRefresh(t *testing.T) {
	record, withdrawn := withdrawalFixture(t)
	record.Fence.Reason = "release"
	x, facts, _, _ := projectionFixture(t)
	fact := facts[0]
	fact.ObjectID, fact.OwnerUID = "refresh-export", 0
	refresh := CredentialRefresh{ProjectionID: record.Authority.ID, ExpectedGeneration: record.Generation,
		SlotID: record.Authority.Request.Handoff.Spec.Runner.Slot.ID, ExpectedSourceGeneration: record.Authority.Sources[0].Generation,
		Observation: withdrawn.Observation, Fact: fact, File: x.Files[0]}
	if err := ValidateCredentialRefresh(record, refresh, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"survivors", "generation", "alias", "revoked"} {
		t.Run(fault, func(t *testing.T) {
			r := refresh
			switch fault {
			case "survivors":
				r.Observation.Survivors = projectionCount(1)
			case "generation":
				r.ExpectedSourceGeneration++
			case "alias":
				r.Fact.ObjectID = record.Receipt.Targets[0].ObjectID
			case "revoked":
				rrecord := record
				fence := *record.Fence
				fence.Reason = "revoked"
				rrecord.Fence = &fence
				requireLaunchInvalid(t, ValidateCredentialRefresh(rrecord, r, contractNow()), "credential refresh boundary was bypassed")
				return
			}
			requireLaunchInvalid(t, ValidateCredentialRefresh(record, r, contractNow()), "credential refresh boundary was bypassed")
		})
	}
}
