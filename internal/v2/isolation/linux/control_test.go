package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This fixture supplies protocol inputs only. It cannot advertise readiness or
// start a fake successful process: the helper tripwire returns its real error.
type fixtureControls struct {
	ControlSource
	handoff     api.PreparedSpecHandoff
	original    []byte
	binding     api.LaunchBindingRequest
	open        api.HelperOpenRequest
	observation api.HelperObserveRequest
	release     api.HelperReleaseRequest
	recorded    int
}

func (f *fixtureControls) Plan(context.Context, api.ID) (api.LaunchPlanRecord, error) {
	return api.LaunchPlanRecord{}, api.NotImplemented("lb-v2-service", "test Plan")
}

func (f *fixtureControls) Handoff(context.Context, api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	return f.handoff, nil
}

func (f *fixtureControls) Original(context.Context, api.BlobRef) ([]byte, error) {
	return append([]byte{}, f.original...), nil
}

func (f *fixtureControls) Binding(context.Context, api.ID) (api.LaunchBindingRequest, error) {
	return f.binding, nil
}

func (f *fixtureControls) Open(context.Context, api.PreparedLaunch, api.LaunchPermit) (api.HelperOpenRequest, error) {
	return f.open, nil
}

func (f *fixtureControls) Observe(context.Context, api.ProcessHandle) (api.HelperObserveRequest, error) {
	return f.observation, nil
}

func (f *fixtureControls) Release(context.Context, api.ID, api.ProcessObservation) (api.HelperReleaseRequest, error) {
	return f.release, nil
}

func (f *fixtureControls) RecordRelease(context.Context, api.HelperReleaseRequest, api.ReleaseReceipt) error {
	f.recorded++
	return api.NotImplemented("lb-v2-service", "test release completion")
}

func fixtureCause(kind api.InternalKind, target api.LifeRef) api.InternalIntent {
	return api.InternalIntent{ID: api.ID(kind), Kind: kind, Config: "demo",
		Actor: api.Actor{ID: "service", Kind: "service"}, RequestedBy: api.Actor{ID: "starter", Kind: "lane"},
		CauseOperationID: "operation", CauseRequestID: "request", EffectID: "effect", Target: target}
}

func committedFixture(t *testing.T) (*fixtureControls, api.PreparedLaunch, api.LaunchPermit) {
	t.Helper()
	source, spec := handoffFixture(t)
	prepared := api.PreparedLaunch{ID: "prepared", Target: spec.Target, SpecSHA256: source.handoff.SpecSHA256,
		ContainmentID: "containment", ProcessGeneration: "generation", EndpointGeneration: spec.EndpointGeneration, GateID: "gate"}
	permit := api.LaunchPermit{LaunchID: spec.LaunchID, PreparedID: prepared.ID,
		RecordSHA256: fixtureBlob("committed-record").SHA256, CommittedSeq: 8}
	source.binding = api.LaunchBindingRequest{Prepared: prepared,
		Identity: api.IdentityCommit{LaunchID: spec.LaunchID, EventID: "event", CommittedSeq: permit.CommittedSeq, RecordSHA256: permit.RecordSHA256},
		Record: api.LaunchRecord{Kind: "worker", ID: spec.LaunchID, Config: "demo", Target: spec.Target, UIDLeaseID: spec.UIDLeaseID,
			Actor:   api.Actor{Kind: "worker", ID: "worker", LifeID: spec.Target.LifeID},
			HostUID: 1001, ProcessGeneration: prepared.ProcessGeneration, ContainmentID: prepared.ContainmentID,
			GrantSetID: spec.Grants.ID, GrantsSHA256: spec.Grants.SHA256,
			PolicyGeneration: spec.PolicyGeneration, EndpointGeneration: spec.EndpointGeneration}}
	digest, err := canonicalDigest(source.binding.Record)
	if err != nil {
		t.Fatal(err)
	}
	permit.RecordSHA256 = digest
	source.binding.Identity.RecordSHA256 = digest
	source.open = api.HelperOpenRequest{Cause: fixtureCause(api.InternalHelperOpen, spec.Target),
		Prepared: prepared, Permit: permit, OperationID: "operation", EffectID: "effect"}
	return source, prepared, permit
}

func TestLaunchReconcilesBeforeOpen(t *testing.T) {
	source, prepared, permit := committedFixture(t)
	helper := &helperTripwire{}
	s, err := New(Dependencies{Helper: helper, RuntimeManifest: source.handoff.Spec.RuntimeManifest, Controls: source})
	if err != nil {
		t.Fatal(err)
	}
	handle, err := s.Launch(context.Background(), prepared, permit)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || !strings.Contains(typed.Message, "ReconcileGate") ||
		helper.calls != 1 || handle.ID != "" {
		t.Fatal("launch did not preserve the original-gate reconciliation refusal")
	}
	source.binding.Identity.CommittedSeq++
	helper.calls = 0
	_, err = s.Launch(context.Background(), prepared, permit)
	requireCode(t, err, api.CodeIntegrity)
	if helper.calls != 0 {
		t.Fatal("forged committed tuple reached the root helper")
	}
}

// This simulates a malformed helper protocol reply, not a successful release
// or confinement. No test using it may return a successful Launcher result.
type unmeasuredHelper struct {
	helperTripwire
	observation api.ProcessObservation
	releases    int
}

func (h *unmeasuredHelper) ObserveGate(context.Context, api.HelperObserveRequest) (api.ProcessObservation, error) {
	h.calls++
	return h.observation, nil
}

func (h *unmeasuredHelper) Release(context.Context, api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	h.releases++
	return api.ReleaseReceipt{}, nil
}

func TestCollectRejectsUnmeasured(t *testing.T) {
	source, prepared, _ := committedFixture(t)
	zero := uint64(0)
	exitCode := 0
	process := api.ProcessHandle{ID: "process", Target: prepared.Target,
		ContainmentID: prepared.ContainmentID, Generation: prepared.ProcessGeneration}
	claim := api.ProcessObservation{Handle: process, State: "exited", Survivors: &zero, ExitCode: &exitCode, PromptStatus: "unknown",
		ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	source.observation = api.HelperObserveRequest{LeaseID: "lease", Handle: process}
	source.release = api.HelperReleaseRequest{Cause: fixtureCause(api.InternalHelperRelease, prepared.Target),
		LeaseID: "lease", Observation: claim}
	helper := &unmeasuredHelper{observation: claim}
	s, err := New(Dependencies{Helper: helper, RuntimeManifest: source.handoff.Spec.RuntimeManifest, Controls: source})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Collect(context.Background(), "lease", claim); err == nil || helper.releases != 1 || source.recorded != 0 {
		t.Fatal("unmeasured helper reply became a reported release")
	}
	helper.releases = 0
	nonzero := uint64(1)
	helper.observation.Survivors = &nonzero
	err = s.Collect(context.Background(), "lease", claim)
	requireCode(t, err, api.CodeContainmentUnknown)
	if helper.releases != 0 || source.recorded != 0 {
		t.Fatal("fresh survivors reached release or completion")
	}
}

func handoffFixture(t *testing.T) (*fixtureControls, api.LaunchSpec) {
	t.Helper()
	spec := fixtureSpec()
	spec.Grants.Resources = []api.ResourceGrant{}
	spec.Grants.Data = []api.DataGrant{}
	spec.Grants.Secrets = []api.SecretGrant{}
	spec.Grants.Profiles = []api.ProfileGrant{}
	spec.Grants.Network = []api.NetworkGrant{}
	spec.Grants.Channels = []api.ChannelGrant{}
	spec.Materialization.Objects = []api.MaterializedObject{}
	spec.Injection.SlotIDs = []api.ID{}
	spec.Injection.TaskSecretNames = []string{}
	spec.Injection.TaskSecretFileNames = []string{}
	spec.Injection.GrantIDs = []api.ID{}
	spec.Injection.SourceVersions = []string{}
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	sum, canonicalSum := sha256.Sum256(data), sha256.Sum256(canonical)
	cause := api.InternalIntent{ID: "register", Kind: api.InternalHelperRegister, Config: "demo",
		Actor: api.Actor{ID: "service", Kind: "service"}, RequestedBy: api.Actor{ID: "starter", Kind: "lane"},
		CauseOperationID: "operation", CauseRequestID: "request", EffectID: "register-effect", Target: spec.Target}
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: "demo", Spec: spec,
		Original: api.BlobRef{ID: "original", Class: "spec", Bytes: int64(len(data)),
			SHA256: api.Digest(hex.EncodeToString(sum[:]))},
		SpecSHA256: api.Digest(hex.EncodeToString(canonicalSum[:])), OperationID: "operation", RequestID: "request"}
	return &fixtureControls{handoff: handoff, original: data}, spec
}

func TestPreparePropagatesRootRefusal(t *testing.T) {
	source, spec := handoffFixture(t)
	helper := &helperTripwire{}
	s, err := New(Dependencies{Helper: helper, RuntimeManifest: spec.RuntimeManifest, Controls: source})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := s.Prepare(context.Background(), spec)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || helper.calls != 1 || prepared.ID != "" {
		t.Fatal("valid retained spec did not reach the actual root registration refusal")
	}
	source, spec = handoffFixture(t)
	source.original = append(source.original, '\n')
	helper = &helperTripwire{}
	s, err = New(Dependencies{Helper: helper, RuntimeManifest: spec.RuntimeManifest, Controls: source})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Prepare(context.Background(), spec)
	requireCode(t, err, api.CodeIntegrity)
	if helper.calls != 0 {
		t.Fatal("changed original bytes contacted the root helper")
	}
}

func TestHandoffDigestAndCause(t *testing.T) {
	source, spec := handoffFixture(t)
	if err := validateHandoff(spec, source.handoff, source.original); err != nil {
		t.Fatal("retained byte/JCS control:", err)
	}
	for _, mutate := range []func(*api.PreparedSpecHandoff){
		func(h *api.PreparedSpecHandoff) { h.SpecSHA256 = fixtureBlob("other").SHA256 },
		func(h *api.PreparedSpecHandoff) { h.Spec.Target.Run++ },
		func(h *api.PreparedSpecHandoff) { h.OperationID = "other" },
		func(h *api.PreparedSpecHandoff) { h.Cause.Kind = api.InternalHelperPrepare },
		func(h *api.PreparedSpecHandoff) { h.Original.Bytes++ },
	} {
		changed := source.handoff
		mutate(&changed)
		if validateHandoff(spec, changed, source.original) == nil {
			t.Fatal("changed digest, original or cause accepted")
		}
	}
}

func TestNetworkLeaseBinding(t *testing.T) {
	spec := fixtureSpec()
	spec.Grants.Network = []api.NetworkGrant{{ID: "grant", EndpointID: "endpoint", Mode: "internet"}}
	lease := api.NetworkLease{ID: "network", GrantSetID: spec.Grants.ID, NamespaceID: "private",
		EndpointIDs: []api.ID{"endpoint"}, Generation: 1, PolicySHA256: fixtureBlob("packet-policy").SHA256,
		ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}
	if err := validateNetwork(spec, lease); err != nil {
		t.Fatal("network lease shape control:", err)
	}
	for _, mutate := range []func(*api.NetworkLease){
		func(n *api.NetworkLease) { n.NamespaceID = "" },
		func(n *api.NetworkLease) { n.GrantSetID = "other" },
		func(n *api.NetworkLease) { n.EndpointIDs = []api.ID{"ungranted"} },
		func(n *api.NetworkLease) { n.ExpiresAt = "2000-01-01T00:00:00Z" },
	} {
		changed := lease
		mutate(&changed)
		if validateNetwork(spec, changed) == nil {
			t.Fatal("missing private namespace or mismatched lease accepted")
		}
	}
}

func TestCausalHelperRequests(t *testing.T) {
	base := api.InternalIntent{ID: "intent", Kind: api.InternalHelperOpen,
		Config: "demo", Actor: api.Actor{ID: "service", Kind: "service"},
		RequestedBy: api.Actor{ID: "starter", Kind: "lane"}, CauseOperationID: "operation",
		CauseRequestID: "request", EffectID: "effect", Target: fixtureSpec().Target}
	if err := validateCause(base, api.InternalHelperOpen, base.Target); err != nil {
		t.Fatal("causal positive control:", err)
	}
	for _, mutate := range []func(*api.InternalIntent){
		func(c *api.InternalIntent) { c.Kind = api.InternalHelperRelease },
		func(c *api.InternalIntent) { c.CauseOperationID = "" },
		func(c *api.InternalIntent) { c.EffectID = "" },
		func(c *api.InternalIntent) { c.RequestedBy.ID = "" },
		func(c *api.InternalIntent) { c.Actor.Kind = "lane" },
		func(c *api.InternalIntent) { c.Target.Run++ },
	} {
		changed := base
		mutate(&changed)
		if validateCause(changed, api.InternalHelperOpen, base.Target) == nil {
			t.Fatal("incomplete or changed cause accepted")
		}
	}
}

func TestMeasuredReleaseReceipt(t *testing.T) {
	zero := uint64(0)
	exitCode := 0
	process := api.ProcessHandle{ID: "process", Target: fixtureSpec().Target,
		ContainmentID: "containment", Generation: "generation"}
	observed := api.ProcessObservation{Handle: process, State: "exited", Survivors: &zero, ExitCode: &exitCode, PromptStatus: "unknown",
		ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	request := api.HelperReleaseRequest{LeaseID: "lease", Observation: observed,
		Cause: api.InternalIntent{Config: "demo", CauseOperationID: "operation", EffectID: "effect"}}
	receipt := api.ReleaseReceipt{ID: "measured", LeaseID: request.LeaseID,
		ContainmentID: process.ContainmentID, Backend: backendName, OperationID: "operation",
		EffectID: "effect", Quiescence: observed, LiveConnections: &zero,
		QueuedJobs: &zero, WritableExports: &zero, ObservedAt: observed.ObservedAt}
	if err := validateReleased(request, receipt); err != nil {
		t.Fatal("complete measured-shape control:", err)
	}
	for _, mutate := range []func(*api.ReleaseReceipt){
		func(r *api.ReleaseReceipt) { r.LiveConnections = nil },
		func(r *api.ReleaseReceipt) { n := uint64(1); r.QueuedJobs = &n },
		func(r *api.ReleaseReceipt) { r.LeaseID = "other" },
		func(r *api.ReleaseReceipt) { r.OperationID = "other" },
		func(r *api.ReleaseReceipt) { r.EffectID = "other" },
		func(r *api.ReleaseReceipt) { r.Quiescence.Handle.Generation = "other" },
		func(r *api.ReleaseReceipt) { r.ObservedAt = "invalid" },
	} {
		changed := receipt
		mutate(&changed)
		if validateReleased(request, changed) == nil {
			t.Fatal("unknown, nonzero or mismatched measured release accepted")
		}
	}
}

func TestObservationKeepsUnknown(t *testing.T) {
	handle := api.ProcessHandle{ID: "process", Target: fixtureSpec().Target,
		ContainmentID: "containment", Generation: "generation"}
	observation := unknown(handle)
	if validateObservation(handle, observation, false) == nil {
		t.Fatal("unknown observation became a known process result")
	}
	observation.State = "running"
	n := uint64(1)
	observation.Survivors = &n
	if err := validateObservation(handle, observation, false); err != nil {
		t.Fatal("actual running-shape control:", err)
	}
	if validateObservation(handle, observation, true) == nil {
		t.Fatal("running process became a successful stop")
	}
	observation.State, n = "exited", 0
	exitCode := 0
	observation.ExitCode = &exitCode
	if err := validateObservation(handle, observation, true); err != nil {
		t.Fatal("known terminal-shape control:", err)
	}
	observation.Handle.Generation = "different"
	if validateObservation(handle, observation, true) == nil {
		t.Fatal("observation for another process generation accepted")
	}
}

func TestUnboundSourceNeverOpensGate(t *testing.T) {
	spec := fixtureSpec()
	helper := &helperTripwire{}
	s, err := New(Dependencies{Helper: helper, RuntimeManifest: spec.RuntimeManifest})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Prepare(context.Background(), spec)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || helper.calls != 0 {
		t.Fatal("missing protected context reached the root helper")
	}
}
