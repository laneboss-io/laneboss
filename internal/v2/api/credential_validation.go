package api

import (
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

var credentialEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// AgentTaskSlotID preserves the broker's reserved-launch task slot identity.
// It is only a selector: delivery still requires the current planning claim,
// exact grant and protected journal. Sharing it lets consumers check every
// task slot in request order without accepting arbitrary extra slots.
func AgentTaskSlotID(reservation, grant ID) ID {
	if !launchID(reservation) || !launchID(grant) {
		return ""
	}
	_, digest, err := launchCanonical([]any{"task", reservation, grant})
	if err != nil {
		return ""
	}
	return ID("credential-" + string(digest))
}

func credentialTimestamp(stamp Timestamp) bool {
	_, err := time.Parse(time.RFC3339Nano, string(stamp))
	return err == nil
}

func credentialExpiry(stamp Timestamp, now time.Time) bool {
	expires, err := time.Parse(time.RFC3339Nano, string(stamp))
	return err == nil && now.Before(expires)
}

func credentialEnvironment(name string) bool {
	if !credentialEnvName.MatchString(name) {
		return false
	}
	for _, prefix := range []string{"LD_", "DYLD_", "MALLOC_", "GIT_", "PERL", "RUBY", "JAVA_", "JDK_", "LANEBOSS_", "CLAUDE_", "CLAUDOCK_", "CODEX_", "OPENAI_", "ANTHROPIC_", "XDG_"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return !slices.Contains([]string{"HOME", "PATH", "TMPDIR", "TMP", "TEMP", "SHELL", "ENV", "BASH_ENV", "PYTHONPATH", "NODE_OPTIONS",
		"GLIBC_TUNABLES", "GCONV_PATH", "GETCONF_DIR", "HOSTALIASES", "LOCALDOMAIN", "LOCPATH", "NIS_PATH", "NLSPATH", "RESOLV_HOST_CONF", "RES_OPTIONS", "TZDIR", "IFS", "PROMPT_COMMAND", "CDPATH", "PS4", "GOFLAGS", "GOMAXPROCS"}, name)
}

func credentialTaskTarget(key, grantID, source ID, version, delivery, target string) (CredentialTarget, error) {
	item := CredentialTarget{Key: key, GrantID: grantID, SourceHandle: source, Version: version, Delivery: delivery}
	if !launchID(key) || !launchID(grantID) || !launchID(source) || version == "" {
		return item, launchInvalid("credential selection lacks its protected source")
	}
	switch delivery {
	case "env":
		if !credentialEnvironment(target) {
			return item, launchInvalid("credential environment target is reserved")
		}
		item.EnvironmentName = target
	case "file":
		if target == "" || path.IsAbs(target) || path.Clean(target) != target || target == "." || target == ".." || strings.HasPrefix(target, "../") || strings.ContainsAny(target, "\\\x00") {
			return item, launchInvalid("credential file target escapes its private directory")
		}
		item.RelativePath, item.FileMode = ".laneboss-secrets/"+target, 0400
	default:
		return item, launchInvalid("credential delivery is not supported")
	}
	return item, nil
}

// CredentialTargets derives destinations only from the retained selected slot
// and grants. No caller supplies a source path or an arbitrary vendor path.
func CredentialTargets(request CredentialProjectionRequest, now time.Time) ([]CredentialTarget, error) {
	spec := request.Handoff.Spec
	items := []CredentialTarget{}
	if spec.Kind == "agent" {
		if spec.Runner == nil || request.Worker != nil || len(request.WorkerCredentials) != 0 {
			return nil, launchInvalid("credential agent and worker authority are mixed")
		}
		slot := spec.Runner.Slot
		if !launchID(slot.ID) || !launchID(slot.LeaseID) || !credentialExpiry(slot.ExpiresAt, now) || !slices.Contains(spec.Injection.SlotIDs, slot.ID) {
			return nil, launchInvalid("credential slot is absent or expired")
		}
		selected := 0
		for _, grant := range spec.Grants.Profiles {
			if grant.ID == slot.ProfileGrantID && grant.ProfileID == slot.ProfileID && grant.Driver == spec.Runner.Driver && credentialExpiry(grant.ExpiresAt, now) {
				selected++
			}
		}
		if selected != 1 {
			return nil, launchInvalid("credential slot differs from its profile grant")
		}
		item := CredentialTarget{Key: slot.ID, SlotID: slot.ID, GrantID: slot.ProfileGrantID, Delivery: "file", FileMode: 0600}
		switch {
		case slot.Mode == "codex-file" && spec.Runner.Driver == DriverCodex && spec.Runner.Home.VendorDirectory == ".codex":
			item.RelativePath = ".codex/auth.json"
		case slot.Mode == "claudock-headless" && spec.Runner.Driver == DriverClaudock && spec.Runner.Home.VendorDirectory == ".claude":
			item.RelativePath, item.EnvironmentName = ".runnerhome-runtime/.runnerhome-token", "CLAUDE_CODE_OAUTH_TOKEN"
		case slot.Mode == "claude-api-key" && spec.Runner.Driver == DriverClaudock && spec.Runner.Home.VendorDirectory == ".claude":
			item.RelativePath = ".config/claudock/key-store.json"
			item.EnvironmentName = "ANTHROPIC_API_KEY"
		default:
			return nil, NotImplemented("lb-v2-secrets", "credential projection for the selected profile mode")
		}
		items = append(items, item)
	} else if spec.Kind == "worker" {
		worker := request.Worker
		if spec.Runner != nil || worker == nil || spec.Worker == nil || worker.Target != spec.Target || worker.ConsumedBy != spec.LaunchID ||
			worker.Kind != spec.Worker.Kind || !workerPermits(worker.Kind, WorkerCredentialInject) || worker.GrantSetID != spec.Grants.ID ||
			!credentialExpiry(worker.ExpiresAt, now) || !launchGeneration(worker.Generation) {
			return nil, launchInvalid("credential worker differs from its protected lease")
		}
		for _, selected := range request.WorkerCredentials {
			item, err := credentialTaskTarget(ID(selected.Name), ID(selected.Name), selected.SourceHandle, selected.Version, selected.Delivery, selected.Target)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
	} else {
		return nil, launchInvalid("credential projection has an unknown launch kind")
	}
	if len(spec.Injection.GrantIDs) != len(spec.Injection.SourceVersions) {
		return nil, launchInvalid("credential injection version list is not aligned")
	}
	for index, id := range spec.Injection.GrantIDs {
		if spec.Kind == "worker" {
			// Worker selectors are the protected enrolled WorkerCredentials;
			// they need not be lane SecretGrants. Identity verifies that list.
			break
		}
		matches := 0
		for _, grant := range spec.Grants.Secrets {
			if grant.ID != id {
				continue
			}
			matches++
			if grant.Version != spec.Injection.SourceVersions[index] || !credentialExpiry(grant.ExpiresAt, now) {
				return nil, launchInvalid("credential injection changed its granted version")
			}
			item, err := credentialTaskTarget(grant.ID, grant.ID, grant.SourceHandle, grant.Version, grant.Delivery, grant.Target)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		if matches != 1 {
			return nil, launchInvalid("credential injection names an ungranted source")
		}
	}
	seen, destinations := map[ID]bool{}, map[string]bool{}
	for _, item := range items {
		destination := item.Delivery + ":" + item.RelativePath + ":" + item.EnvironmentName
		if seen[item.Key] || destinations[destination] {
			return nil, launchInvalid("credential projection duplicates a source or destination")
		}
		seen[item.Key], destinations[destination] = true, true
	}
	if len(items) > 64 {
		return nil, launchInvalid("credential projection exceeds its descriptor bound")
	}
	return items, nil
}

func ValidateCredentialProjectionRequest(request CredentialProjectionRequest, now time.Time) error {
	h, prepared, cause := request.Handoff, request.Prepared, request.Cause
	spec := h.Spec
	_, digest, err := launchCanonical(spec)
	claim := request.Claim
	// Named groups of the same checks, in the same order, so a refusal says which group failed (item 1 diagnosis).
	for _, group := range []struct {
		name string
		bad  func() bool
	}{
		{"spec_digest", func() bool {
			return err != nil || digest != h.SpecSHA256 || prepared.SpecSHA256 != digest || !launchBlob(h.Original, "launch_spec") || h.Original.SHA256 != digest
		}},
		{"handoff", func() bool {
			return !launchID(h.OperationID) || !launchID(h.RequestID) || h.Cause.Kind != InternalHelperRegister || h.Cause.Config != h.Config || h.Cause.Target != spec.Target ||
				!bindingConfigName.MatchString(h.Config)
		}},
		{"cause", func() bool {
			return cause.Config != h.Config || cause.Target != spec.Target || cause.Kind != InternalHelperPrepare ||
				!launchID(cause.ID) || cause.Actor.Kind != "service" || !launchID(cause.Actor.ID) || cause.CauseOperationID != h.OperationID || cause.CauseRequestID != h.RequestID ||
				cause.CancellationEpoch != h.Cause.CancellationEpoch || !reflect.DeepEqual(cause.RequestedBy, h.Cause.RequestedBy) ||
				!launchID(cause.EffectID) || cause.CancellationEpoch > launchMaxInteger
		}},
		{"claim_context " + intentFieldDiff(claim.Record.Effect.Context, cause), func() bool { return !RetainedCause(claim.Record.Effect.Context, cause, claim.Record.ClaimantID) }},
		{"claim_effect", func() bool {
			return claim.Record.Effect.ID != cause.EffectID || claim.Record.Effect.OperationID != cause.CauseOperationID
		}},
		{"claim_claimed", func() bool { return !EffectLeaseClaimed(claim) }},
		{"claim_prepare", func() bool {
			return claim.Record.Effect.HelperPrepare == nil || claim.Record.Effect.HelperPrepare.LeaseID != spec.UIDLeaseID || claim.Record.Effect.HelperPrepare.PreparedSpecID != spec.ID ||
				claim.Record.Effect.HelperPrepare.SpecSHA256 != digest || !RetainedCause(&claim.Record.Effect.HelperPrepare.Cause, cause, claim.Record.ClaimantID)
		}},
		{"claim_lease", func() bool {
			return !launchID(claim.ClaimID) || claim.Record.ClaimID != claim.ClaimID || claim.Record.ClaimExpiresAt != claim.ExpiresAt || !credentialExpiry(claim.ExpiresAt, now)
		}},
		{"spec_ids", func() bool {
			return !launchID(spec.ID) || !launchID(spec.LaunchID) || !launchID(prepared.ID) || !launchID(prepared.GateID) || prepared.Target != spec.Target
		}},
		{"spec_grants", func() bool {
			return !launchID(spec.Target.LifeID) || spec.Target.Run == 0 || spec.Grants.Revoked || spec.Grants.LifeID != spec.Target.LifeID || !credentialExpiry(spec.Grants.ExpiresAt, now)
		}},
		{"uid_lease", func() bool {
			return request.Lease.ID != spec.UIDLeaseID || !launchID(request.Lease.ID) || request.Lease.UID == 0 || request.Lease.GID == 0
		}},
		{"containment", func() bool {
			return prepared.ContainmentID != request.Lease.ContainmentID || !launchID(prepared.ContainmentID) || prepared.ProcessGeneration == ""
		}},
		{"endpoint", func() bool {
			return prepared.EndpointGeneration != request.Lease.EndpointGeneration || prepared.EndpointGeneration != spec.EndpointGeneration || !launchGeneration(prepared.EndpointGeneration)
		}},
		{"home", func() bool {
			return request.Home.LifeID != spec.Target.LifeID || !launchID(request.Home.RootID) || !launchGeneration(request.Home.Generation) || !launchID(request.Home.Home.ID)
		}},
		{"injection", func() bool { return spec.Injection.Target != spec.Target || spec.Injection.Outcome != "prepared" }},
		{"runner_home", func() bool {
			return spec.Kind == "agent" && (spec.Runner == nil || request.Home.Home != spec.Runner.Home)
		}},
	} {
		if group.bad() {
			return launchInvalid("credential projection request lost its retained launch authority (" + group.name + ")")
		}
	}
	_, err = CredentialTargets(request, now)
	return err
}

func ValidateCredentialTransfer(transfer CredentialTransfer, facts []CredentialDescriptorFact, now time.Time) error {
	a := transfer.Authority
	if err := ValidateCredentialProjectionRequest(a.Request, now); err != nil {
		return err
	}
	expected, err := CredentialTargets(a.Request, now)
	if err != nil {
		return err
	}
	if !launchID(a.ID) || !launchGeneration(a.Generation) || a.Generation >= launchMaxInteger || a.Revoked ||
		!launchExecutable(a.Helper) || !launchExecutable(a.Broker) || !launchGeneration(a.InstallationGeneration) || a.BootID == "" ||
		a.HelperPeer.HostUID != 0 || a.HelperPeer.HostPID <= 0 || a.HelperPeer.ProcessGeneration == "" ||
		a.BrokerPeer.HostUID == 0 || a.BrokerPeer.HostUID == a.ServiceUID || a.BrokerPeer.HostUID == a.Request.Lease.UID || a.ServiceUID == 0 ||
		a.BrokerPeer.HostPID <= 0 || a.BrokerPeer.ProcessGeneration == "" || !launchID(a.BrokerPeer.ContainmentID) || a.BrokerPeer.ContainmentID == a.Request.Lease.ContainmentID ||
		!reflect.DeepEqual(a.Targets, expected) || len(a.Sources) != len(expected) || len(transfer.Files) != len(expected) || len(facts) != len(expected) {
		return launchInvalid("credential transfer lacks its pinned outside producer and root receiver")
	}
	objects := map[string]bool{}
	for index, item := range expected {
		source, fact := a.Sources[index], facts[index]
		if transfer.Files[index] == nil || source.Key != item.Key || !launchGeneration(source.Generation) || source.Revoked ||
			item.SlotID == "" && source.Version != item.Version || source.Version == "" ||
			fact.ObjectID == "" || objects[fact.ObjectID] || fact.OwnerUID != a.BrokerPeer.HostUID || fact.Mode != 0600 || !fact.Regular ||
			fact.Links != 0 || !fact.ReadOnly || !fact.CloseOnExec || fact.Size <= 0 || fact.Size > MaxFrameBytes ||
			fact.WritableHandles == nil || *fact.WritableHandles != 0 {
			return launchInvalid("credential descriptor is not exclusive immutable private material")
		}
		objects[fact.ObjectID] = true
	}
	return nil
}

func ValidateCredentialProjectionReceipt(transfer CredentialTransfer, facts []CredentialDescriptorFact, receipt CredentialProjectionReceipt, now time.Time) error {
	if err := ValidateCredentialTransfer(transfer, facts, now); err != nil {
		return err
	}
	if err := validateCredentialHolding(transfer.Authority, receipt); err != nil {
		return err
	}
	for index, item := range receipt.Targets {
		if item.SourceObjectID != facts[index].ObjectID {
			return launchInvalid("credential projection changed its actual received descriptor")
		}
	}
	return nil
}

func validateCredentialHolding(a CredentialProjectionAuthority, receipt CredentialProjectionReceipt) error {
	r := a.Request
	if receipt.ProjectionID != a.ID || receipt.Generation != a.Generation+1 || receipt.Prepared != r.Prepared ||
		receipt.HelperLeaseID != r.Lease.ID || receipt.SpecSHA256 != r.Handoff.SpecSHA256 || receipt.Home != r.Home || receipt.CancellationEpoch != r.Cause.CancellationEpoch ||
		!receipt.GateClosed || !credentialTimestamp(receipt.ObservedAt) || len(receipt.Targets) != len(a.Targets) ||
		receipt.HeldDescriptors == nil || *receipt.HeldDescriptors != uint64(len(a.Targets)) || receipt.InheritedSources == nil || *receipt.InheritedSources != 0 {
		return launchInvalid("credential projection is not held behind its original closed gate")
	}
	objects := map[string]bool{}
	for index, item := range receipt.Targets {
		want := a.Targets[index]
		if item.Target != want || item.SourceObjectID == "" || item.ObjectID == "" || item.ObjectID == item.SourceObjectID || objects[item.ObjectID] ||
			item.RootID != r.Home.RootID || item.HomeGeneration != r.Home.Generation || item.WritableByOthers ||
			want.Delivery == "file" && item.Links != 1 ||
			want.Delivery == "file" && (item.OwnerUID != r.Lease.UID || item.Mode != want.FileMode) ||
			want.Delivery == "file" && want.FileMode == 0400 && (!item.ReadOnlyView || item.ParentMode != 0500) ||
			want.SlotID != "" && want.Delivery == "file" && want.EnvironmentName != "" && !item.ReadOnlyView ||
			want.SlotID != "" && want.Delivery == "env" && item.Links != 0 ||
			want.Delivery == "file" && want.FileMode == 0600 && item.ParentMode != 0700 ||
			want.Delivery == "env" && (item.OwnerUID != 0 || item.Mode != 0600 || item.ParentMode != 0700 || item.Links != 0 && item.Links != 1) {
			return launchInvalid("credential projection changed its held destination or private ownership")
		}
		objects[item.ObjectID] = true
	}
	return nil
}

// Identity calls this on the protected current record before BindLaunch; helper
// additionally holds LockCredentialProjection through its actual OpenGate.
func ValidateCredentialProjectionGate(record CredentialProjectionRecord, binding LaunchBindingRequest, now time.Time) error {
	r, receipt := record.Authority.Request, record.Receipt
	if err := ValidateCredentialProjectionRequest(r, now); err != nil {
		return err
	}
	expected, err := CredentialTargets(r, now)
	if err != nil {
		return err
	}
	if !launchID(record.Authority.ID) || !launchGeneration(record.Authority.Generation) ||
		!reflect.DeepEqual(record.Authority.Targets, expected) || len(record.Authority.Sources) != len(expected) || receipt == nil {
		return launchInvalid("credential gate changed its selected targets")
	}
	if err := validateCredentialHolding(record.Authority, *receipt); err != nil {
		return err
	}
	if record.State != "held" || record.Revoked || record.Authority.Revoked || record.Fence != nil || record.Withdrawal != nil || record.Generation != record.Authority.Generation+1 ||
		receipt.Generation != record.Generation || receipt.ProjectionID != record.Authority.ID || receipt.Prepared != binding.Prepared || r.Prepared != binding.Prepared ||
		binding.Record.Revoked || binding.Record.ID != r.Handoff.Spec.LaunchID || binding.Record.Config != r.Handoff.Config || binding.Record.Target != r.Prepared.Target ||
		binding.Record.UIDLeaseID != r.Lease.ID || binding.Record.HostUID != r.Lease.UID || binding.Record.ContainmentID != r.Prepared.ContainmentID ||
		binding.Record.ProcessGeneration != r.Prepared.ProcessGeneration || binding.Record.EndpointGeneration != r.Prepared.EndpointGeneration ||
		receipt.Home != r.Home || receipt.CancellationEpoch != r.Cause.CancellationEpoch || !receipt.GateClosed ||
		r.Handoff.Spec.Kind == "agent" && (binding.Recovery == nil || binding.Recovery.PlanID != r.Handoff.Spec.PlanID || binding.Recovery.Home != r.Home) {
		return launchInvalid("credential gate lacks its current held projection")
	}
	for index, source := range record.Authority.Sources {
		if source.Revoked || source.Key != expected[index].Key || !launchGeneration(source.Generation) || source.Version == "" ||
			expected[index].SlotID == "" && source.Version != expected[index].Version {
			return launchInvalid("credential gate source was revoked")
		}
	}
	return nil
}

func ValidateCredentialGateRequest(record CredentialProjectionRecord, request CredentialGateRequest, binding LaunchBindingRequest, now time.Time) error {
	if err := ValidateCredentialProjectionGate(record, binding, now); err != nil {
		return err
	}
	open := request.Open
	if request.ProjectionID != record.Authority.ID || request.ExpectedGeneration != record.Generation || open.Prepared != binding.Prepared ||
		!launchID(open.Cause.ID) || open.Cause.Actor.Kind != "service" || !launchID(open.Cause.Actor.ID) || !launchID(open.OperationID) || !launchID(open.EffectID) ||
		open.Permit.LaunchID != binding.Record.ID || open.Permit.PreparedID != binding.Prepared.ID || open.Permit != (LaunchPermit{LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, RecordSHA256: binding.Identity.RecordSHA256, CommittedSeq: binding.Identity.CommittedSeq}) ||
		open.Permit.CommittedSeq == 0 || open.Cause.Kind != InternalHelperOpen || open.Cause.Config != binding.Record.Config || open.Cause.Target != binding.Record.Target ||
		open.Cause.CancellationEpoch != record.Authority.Request.Cause.CancellationEpoch || open.OperationID != open.Cause.CauseOperationID || open.EffectID != open.Cause.EffectID {
		return launchInvalid("credential gate guard differs from the original launch permit")
	}
	return nil
}

func ValidateCredentialWithdrawalRequest(record CredentialProjectionRecord, request CredentialWithdrawalRequest) error {
	r := record.Authority.Request
	initial := (record.State == "reserved" || record.State == "held") && record.Fence == nil && record.PriorFence == nil && !record.Revoked
	escalation := record.State == "withdrawing" && record.Fence != nil && record.PriorFence == nil && !record.Revoked &&
		request.Reason == "revoked" && request.Cause == record.Fence.Cause
	if !launchID(record.Authority.ID) || !launchGeneration(record.Generation) || request.ProjectionID != record.Authority.ID || request.ExpectedGeneration != record.Generation || record.Generation >= launchMaxInteger ||
		!initial && !escalation || record.Withdrawal != nil ||
		request.Cause.Config != r.Handoff.Config || request.Cause.Target != r.Prepared.Target || request.Cause.Actor.Kind != "service" ||
		!launchID(request.Cause.ID) || !launchID(request.Cause.Actor.ID) || !launchID(request.Cause.CauseOperationID) || !launchID(request.Cause.EffectID) ||
		request.Cause.CancellationEpoch < r.Cause.CancellationEpoch || request.Cause.CancellationEpoch > launchMaxInteger ||
		request.Cause.Kind != InternalHelperAbort && request.Cause.Kind != InternalHelperStop && request.Cause.Kind != InternalHelperRelease ||
		!slices.Contains([]string{"refused", "revoked", "expired", "cancelled", "release", "restart"}, request.Reason) {
		return launchInvalid("credential withdrawal request lacks its current fence")
	}
	return nil
}

func ValidateCredentialWithdrawal(record CredentialProjectionRecord, receipt CredentialWithdrawalReceipt) error {
	if err := validateCredentialWithdrawalHelper(record, receipt); err != nil {
		return err
	}
	unopened := receipt.AgentExecuted != nil && !*receipt.AgentExecuted
	if (record.Revoked || record.Authority.Revoked || record.Fence != nil && record.Fence.Reason == "revoked") &&
		(receipt.RotationRequired || receipt.Observation.State != "absent" && !unopened) {
		return &Error{Code: CodeContainmentUnknown, Message: "revoked credential exposure requires protected rotation"}
	}
	for _, count := range []*uint64{receipt.BrokerDescriptors, receipt.RefreshLeases} {
		if count == nil || *count != 0 {
			return launchInvalid("credential withdrawal has unknown or surviving material")
		}
	}
	return nil
}

// ValidateCredentialWithdrawalHelper validates the helper-owned shape before
// the broker retires its resources. It neither supplies nor assumes broker
// counts. Final completion still requires ValidateCredentialWithdrawal.
func ValidateCredentialWithdrawalHelper(record CredentialProjectionRecord, receipt CredentialWithdrawalReceipt) error {
	if receipt.BrokerDescriptors != nil || receipt.RefreshLeases != nil {
		return launchInvalid("credential helper cannot supply broker resource counts")
	}
	return validateCredentialWithdrawalHelper(record, receipt)
}

func validateCredentialWithdrawalHelper(record CredentialProjectionRecord, receipt CredentialWithdrawalReceipt) error {
	r := record.Authority.Request
	if record.State != "withdrawing" || record.Generation >= launchMaxInteger || record.Fence == nil ||
		record.Fence.ProjectionID != record.Authority.ID || record.Fence.ExpectedGeneration+1 != record.Generation || !reflect.DeepEqual(receipt.Cause, record.Fence.Cause) ||
		receipt.ProjectionID != record.Authority.ID || receipt.Generation != record.Generation+1 ||
		receipt.Cause.Config != r.Handoff.Config || receipt.Cause.Target != r.Prepared.Target || receipt.Cause.Actor.Kind != "service" ||
		!launchID(receipt.Cause.ID) || !launchID(receipt.Cause.CauseOperationID) || !launchID(receipt.Cause.EffectID) ||
		receipt.Cause.Kind != InternalHelperAbort && receipt.Cause.Kind != InternalHelperStop && receipt.Cause.Kind != InternalHelperRelease ||
		receipt.Prepared != r.Prepared || receipt.HelperLeaseID != r.Lease.ID || receipt.Home != r.Home || !credentialTimestamp(receipt.ObservedAt) ||
		!credentialTimestamp(receipt.Observation.ObservedAt) ||
		receipt.Observation.Handle.Target != r.Prepared.Target || receipt.Observation.Handle.ContainmentID != r.Prepared.ContainmentID || receipt.Observation.Handle.Generation != r.Prepared.ProcessGeneration ||
		receipt.Observation.State != "exited" && receipt.Observation.State != "absent" {
		return launchInvalid("credential withdrawal lost its fenced launch and cleanup cause")
	}
	for _, count := range []*uint64{receipt.Observation.Survivors, receipt.HelperDescriptors, receipt.ProjectedFiles, receipt.EnvironmentBuffers, receipt.OpenGates} {
		if count == nil || *count != 0 {
			return launchInvalid("credential withdrawal has unknown or surviving material")
		}
	}
	return nil
}

func ValidateCredentialRefresh(record CredentialProjectionRecord, refresh CredentialRefresh, now time.Time) error {
	r := record.Authority.Request
	if record.State != "withdrawing" || record.Fence == nil || record.Fence.Reason != "release" || record.Revoked || record.Authority.Revoked ||
		refresh.ProjectionID != record.Authority.ID || refresh.ExpectedGeneration != record.Generation ||
		r.Handoff.Spec.Kind != "agent" || r.Handoff.Spec.Runner == nil || r.Handoff.Spec.Runner.Slot.Mode != "codex-file" ||
		refresh.SlotID != r.Handoff.Spec.Runner.Slot.ID || !credentialExpiry(r.Handoff.Spec.Runner.Slot.ExpiresAt, now) || refresh.File == nil ||
		refresh.Observation.Handle.Target != r.Prepared.Target || refresh.Observation.Handle.ContainmentID != r.Prepared.ContainmentID || refresh.Observation.Handle.Generation != r.Prepared.ProcessGeneration ||
		refresh.Observation.State != "exited" && refresh.Observation.State != "absent" || !credentialTimestamp(refresh.Observation.ObservedAt) ||
		refresh.Observation.Survivors == nil || *refresh.Observation.Survivors != 0 ||
		refresh.Fact.ObjectID == "" || refresh.Fact.OwnerUID != 0 || refresh.Fact.Links != 0 || !refresh.Fact.Regular ||
		refresh.Fact.Mode != 0600 || !refresh.Fact.ReadOnly || !refresh.Fact.CloseOnExec || refresh.Fact.Size <= 0 || refresh.Fact.Size > MaxFrameBytes ||
		refresh.Fact.WritableHandles == nil || *refresh.Fact.WritableHandles != 0 {
		return launchInvalid("credential refresh lacks a private quiescent return")
	}
	matched := 0
	for _, source := range record.Authority.Sources {
		if source.Key == refresh.SlotID && source.Generation == refresh.ExpectedSourceGeneration && launchGeneration(source.Generation) && !source.Revoked {
			matched++
		}
	}
	if matched != 1 || record.Receipt == nil {
		return launchInvalid("credential refresh changed its canonical source generation")
	}
	for _, target := range record.Receipt.Targets {
		if refresh.Fact.ObjectID == target.ObjectID || refresh.Fact.ObjectID == target.SourceObjectID {
			return launchInvalid("credential refresh reused a lane-visible or original source object")
		}
	}
	return nil
}

// RetainedCause reports whether cause is the retained context, where the cause may carry the live claimant
// {service, claimant} in place of the effect's author, as the helper stage accepts it (admin currentStage).
func RetainedCause(retained *InternalIntent, cause InternalIntent, claimant ID) bool {
	if retained == nil {
		return false
	}
	want := *retained
	if cause.Actor == (Actor{Kind: "service", ID: claimant}) {
		want.Actor = cause.Actor
	}
	return want == cause
}

// intentFieldDiff names the fields (never their values) where a claim's context differs from the cause.
func intentFieldDiff(context *InternalIntent, cause InternalIntent) string {
	if context == nil {
		return "nil"
	}
	a, b := reflect.ValueOf(*context), reflect.ValueOf(cause)
	var names []string
	for i := 0; i < a.NumField(); i++ {
		if !reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
			names = append(names, a.Type().Field(i).Name)
		}
	}
	return strings.Join(names, ",")
}
