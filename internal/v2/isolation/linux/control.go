package linux

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// ControlSource is a trusted service-construction dependency, not an RPC, a
// context.Value convention or a second helper wire protocol. Its requests come
// from the current claimed durable effect and protected launch binding. It must
// recheck revocation/generation and preserve the actual requester and cause.
// Assembly owns wiring it; a public body or a launch-ID map cannot supply it.
type ControlSource = api.LaunchControlSource

var controlConfig = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func validateCause(cause api.InternalIntent, kind api.InternalKind, target api.LifeRef) error {
	if cause.Kind != kind || cause.ID == "" || !controlConfig.MatchString(cause.Config) ||
		cause.Actor.ID == "" || cause.Actor.Kind != "service" || cause.RequestedBy.ID == "" ||
		cause.RequestedBy.Kind == "" || cause.CauseOperationID == "" || cause.CauseRequestID == "" ||
		cause.EffectID == "" || !validLife(target) || cause.Target != target {
		return failure(api.CodeIntegrity, "missing or mismatched causal helper context")
	}
	return nil
}

func digestBytes(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func validateHandoff(spec api.LaunchSpec, handoff api.PreparedSpecHandoff, original []byte) error {
	if err := validateCause(handoff.Cause, api.InternalHelperRegister, spec.Target); err != nil {
		return err
	}
	if handoff.Config != handoff.Cause.Config || handoff.OperationID != handoff.Cause.CauseOperationID ||
		handoff.RequestID != handoff.Cause.CauseRequestID || !reflect.DeepEqual(handoff.Spec, spec) ||
		validateBlob(handoff.Original) != nil || len(original) == 0 || len(original) > api.MaxFrameBytes ||
		handoff.Original.Bytes != int64(len(original)) || handoff.Original.SHA256 != digestBytes(original) {
		return failure(api.CodeIntegrity, "prepared spec differs from its retained original context")
	}
	var decoded api.LaunchSpec
	if err := api.DecodeObject(original, &decoded); err != nil {
		return err
	}
	canonical, err := api.CanonicalJSON(original)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(decoded, spec) || handoff.SpecSHA256 != digestBytes(canonical) {
		return failure(api.CodeIntegrity, "prepared spec canonical digest or bytes differ")
	}
	return nil
}

func validateRegistration(handoff api.PreparedSpecHandoff, receipt api.PreparedSpecReceipt) error {
	if receipt.SpecID != handoff.Spec.ID || receipt.Config != handoff.Config ||
		receipt.Target != handoff.Spec.Target || receipt.LeaseID != handoff.Spec.UIDLeaseID ||
		receipt.SpecSHA256 != handoff.SpecSHA256 || receipt.RuntimeManifest != handoff.Spec.RuntimeManifest ||
		receipt.OperationID != handoff.OperationID {
		return failure(api.CodeIntegrity, "helper registration receipt differs from the original spec")
	}
	return nil
}

func validateRuntime(handoff api.PreparedSpecHandoff, runtime api.ResolvedRuntime) error {
	if err := validateRegistration(handoff, runtime.SpecReceipt); err != nil {
		return err
	}
	manifest := runtime.Manifest
	if manifest.Schema != "laneboss.runtime.v2" || manifest.Generation == 0 ||
		validateExecutable(manifest.Artifact) != nil || validateExecutable(manifest.Bootstrap) != nil ||
		manifest.Artifact.SHA256 != manifest.Bootstrap.SHA256 ||
		manifest.Artifact.Version != manifest.Bootstrap.Version || len(manifest.Objects) == 0 ||
		runtime.Workspace != handoff.Spec.Workspace {
		return failure(api.CodeIntegrity, "resolved runtime pins or workspace differ")
	}
	seen := make(map[api.ID]bool)
	for _, object := range manifest.Objects {
		if object.ID == "" || seen[object.ID] || object.RootID == "" || object.Role == "" ||
			object.RelativePath == "" || path.IsAbs(object.RelativePath) ||
			path.Clean(object.RelativePath) != object.RelativePath || object.RelativePath == ".." ||
			within(object.RelativePath, "..") || strings.ContainsRune(object.RelativePath, 0) ||
			validateBlob(object.Content) != nil || object.Mode&07022 != 0 {
			return failure(api.CodeIntegrity, "invalid enrolled runtime object")
		}
		seen[object.ID] = true
	}
	if handoff.Spec.Runner != nil && runtime.Home != handoff.Spec.Runner.Home {
		return failure(api.CodeIntegrity, "resolved private home/history differs")
	}
	bindings := 0
	class := api.EndpointLane
	if handoff.Spec.Kind == "worker" {
		class = api.EndpointWorker
	}
	for _, binding := range manifest.Bindings {
		if err := api.ValidateBinding(binding, handoff.Config, manifest.Artifact.Version); err != nil {
			return err
		}
		if binding.Backend != backendName || binding.ArtifactSHA256 != manifest.Artifact.SHA256 ||
			binding.Class != class || binding.Target == nil || *binding.Target != handoff.Spec.Target ||
			binding.LaunchID != handoff.Spec.LaunchID || binding.EndpointGeneration != handoff.Spec.EndpointGeneration {
			return failure(api.CodeIntegrity, "runtime endpoint artifact/backend differs")
		}
		if binding.Target != nil && *binding.Target == handoff.Spec.Target &&
			binding.LaunchID == handoff.Spec.LaunchID && binding.EndpointGeneration == handoff.Spec.EndpointGeneration {
			bindings++
		}
	}
	if bindings != 1 || len(manifest.Bindings) != 1 {
		return failure(api.CodeIntegrity, "runtime requires one exact run endpoint projection")
	}
	return validateNetwork(handoff.Spec, runtime.Network)
}

func validateNetwork(spec api.LaunchSpec, lease api.NetworkLease) error {
	if len(spec.Grants.Network) == 0 {
		if lease.ID != "" || lease.NamespaceID != "" || lease.GrantSetID != "" || len(lease.EndpointIDs) != 0 ||
			lease.Generation != 0 || lease.PolicySHA256 != "" || lease.ExpiresAt != "" {
			return failure(api.CodeIntegrity, "offline spec unexpectedly acquired an egress lease")
		}
		return nil
	}
	if err := validateNetworkGrants(spec.Grants.Network, time.Now()); err != nil {
		return err
	}
	if lease.ID == "" || lease.NamespaceID == "" || lease.GrantSetID != spec.Grants.ID ||
		lease.Generation == 0 || !validDigest(lease.PolicySHA256) || lease.ExpiresAt == "" ||
		!notExpired(lease.ExpiresAt, time.Now()) {
		return &PrerequisiteError{Check: "controlled_egress", Err: errEgressLease}
	}
	endpoints := make(map[api.ID]bool)
	for _, grant := range spec.Grants.Network {
		if grant.EndpointID == "" || !notExpired(grant.ExpiresAt, time.Now()) {
			return failure(api.CodeForbidden, "network grant is stale or incomplete")
		}
		endpoints[grant.EndpointID] = true
	}
	for _, endpoint := range lease.EndpointIDs {
		if !endpoints[endpoint] {
			return failure(api.CodeIntegrity, "egress lease endpoint differs from grants")
		}
		delete(endpoints, endpoint)
	}
	if len(endpoints) != 0 {
		return &PrerequisiteError{Check: "controlled_egress", Err: errEgressLease}
	}
	return nil
}

func validPrepared(prepared api.PreparedLaunch) bool {
	return prepared.ID != "" && prepared.GateID != "" && prepared.ContainmentID != "" &&
		prepared.ProcessGeneration != "" && prepared.EndpointGeneration != 0 &&
		validDigest(prepared.SpecSHA256) && validLife(prepared.Target)
}

func validateProcess(handle api.ProcessHandle) error {
	if handle.ID == "" || !validLife(handle.Target) || handle.ContainmentID == "" || handle.Generation == "" {
		return failure(api.CodeContainmentUnknown, "process identity/containment is incomplete")
	}
	return nil
}

func validTime(value api.Timestamp) bool {
	_, err := time.Parse(time.RFC3339Nano, string(value))
	return value != "" && strings.HasSuffix(string(value), "Z") && err == nil
}

func validateObservation(handle api.ProcessHandle, observed api.ProcessObservation, terminal bool) error {
	if validateProcess(handle) != nil || observed.Handle != handle || !validTime(observed.ObservedAt) ||
		observed.Survivors == nil || observed.State != "running" && observed.State != "exited" ||
		observed.State == "running" && *observed.Survivors == 0 ||
		terminal && (observed.State != "exited" || *observed.Survivors != 0) {
		return failure(api.CodeContainmentUnknown, "helper observation is unknown, nonterminal or mismatched")
	}
	if !validPromptStatus(observed.PromptStatus) ||
		observed.State == "running" && (observed.ExitCode != nil || observed.Signal != nil) ||
		observed.State == "exited" && (observed.ExitCode == nil) == (observed.Signal == nil) ||
		!signedExit(observed.ExitCode) || !signedExit(observed.Signal) {
		return failure(api.CodeContainmentUnknown, "process prompt or exit/signal observation is invalid")
	}
	return nil
}

func signedExit(value *int) bool {
	return value == nil || int64(*value) >= -2147483648 && int64(*value) <= 2147483647
}

func validPromptStatus(value string) bool {
	switch value {
	case "not_written", "written", "cut", "unknown", "completed":
		return true
	}
	return false
}

func sameObservation(a, b api.ProcessObservation) bool {
	a.ObservedAt, b.ObservedAt = "", ""
	return reflect.DeepEqual(a, b)
}

func validateReleased(request api.HelperReleaseRequest, receipt api.ReleaseReceipt) error {
	if err := api.ValidateReleaseReceipt(receipt); err != nil {
		return err
	}
	if receipt.LeaseID != request.LeaseID || receipt.Backend != backendName ||
		receipt.OperationID != request.Cause.CauseOperationID || receipt.EffectID != request.Cause.EffectID ||
		!sameObservation(receipt.Quiescence, request.Observation) || !validTime(receipt.ObservedAt) ||
		validateObservation(request.Observation.Handle, receipt.Quiescence, true) != nil {
		return failure(api.CodeContainmentUnknown, "helper measured release does not match the requested lease")
	}
	return nil
}

func validateIdentity(prepared api.PreparedLaunch, permit api.LaunchPermit, binding api.LaunchBindingRequest) error {
	record := binding.Record
	if err := validateRecordKind(binding); err != nil {
		return err
	}
	digest, err := canonicalDigest(record)
	if err != nil || digest != binding.Identity.RecordSHA256 {
		return failure(api.CodeIntegrity, "committed identity digest differs from its launch record")
	}
	if binding.Prepared != prepared || record.ID != permit.LaunchID || record.ID == prepared.ID || record.Revoked ||
		record.UIDLeaseID == "" || record.HostUID == 0 || record.Config == "" || record.Target != prepared.Target ||
		record.Actor.ID == "" || record.Actor.Kind != "lane" && record.Actor.Kind != "worker" ||
		record.ContainmentID != prepared.ContainmentID || record.ProcessGeneration != prepared.ProcessGeneration ||
		record.EndpointGeneration != prepared.EndpointGeneration || record.PolicyGeneration == 0 ||
		record.GrantSetID == "" || !validDigest(record.GrantsSHA256) || binding.Identity.LaunchID != record.ID ||
		binding.Identity.EventID == "" || binding.Identity.CommittedSeq != permit.CommittedSeq ||
		binding.Identity.RecordSHA256 != permit.RecordSHA256 {
		return failure(api.CodeIntegrity, "permit differs from the committed identity tuple")
	}
	return nil
}

func validateRecordKind(binding api.LaunchBindingRequest) error {
	record := binding.Record
	if record.Kind != "agent" && record.Kind != "worker" ||
		record.Kind == "agent" && record.Actor.Kind != "lane" ||
		record.Kind == "worker" && (record.Actor.Kind != "worker" || binding.Recovery != nil) {
		return failure(api.CodeIntegrity, "launch record has no matching explicit agent or worker kind")
	}
	if record.Kind == "worker" && (record.Actor.Level != 0 || record.Actor.Role != "") {
		return failure(api.CodeIntegrity, "worker actor cannot inherit an agent level or role")
	}
	return nil
}

// CanonicalSpecDigest is useful to the trusted service adapter. It retains no
// original bytes and therefore cannot replace ControlSource.Original.
func CanonicalSpecDigest(spec api.LaunchSpec) (api.Digest, error) {
	return canonicalDigest(spec)
}

func canonicalDigest(value any) (api.Digest, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := api.CanonicalJSON(data)
	if err != nil {
		return "", err
	}
	return digestBytes(canonical), nil
}
