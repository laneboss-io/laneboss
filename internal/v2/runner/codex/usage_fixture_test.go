package codex

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type usageFixtureRefs struct{ Query, Evidence, Native, Principal, Enrollment api.BlobRef }
type usageMemory struct {
	usage map[api.LifeRef]usageFixtureRefs
}
type usageNative struct {
	Endpoint api.InstalledBinding
	Peer     api.PeerFacts
}
type usageEnrollment struct {
	Grant         api.ProfileGrant
	VendorProfile string
}

func (m *memoryStore) ReadUsageWindow(ctx context.Context, scope api.Scope, request api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	var evidence api.UsageWindowEvidence
	if m.readError != nil {
		return evidence, m.readError
	}
	refs, ok := m.usage[request.Target]
	if scope.Config != "case-codex" || !ok {
		return evidence, problem(api.CodeNotFound, "test usage result absent")
	}
	var query api.UsageWindowRequest
	if err := m.retainedInternal(refs.Query, &query); err != nil {
		return evidence, err
	}
	if query != request {
		return evidence, problem(api.CodeIntegrity, "test usage query differs from the causing run")
	}
	err := m.retainedObject(refs.Evidence, &evidence)
	return evidence, err
}

func (m *memoryStore) usageWorker(ctx context.Context, scope api.Scope, leaseID api.ID) (api.InstalledBinding, api.PeerFacts, error) {
	if m.readError != nil {
		return api.InstalledBinding{}, api.PeerFacts{}, m.readError
	}
	for _, refs := range m.usage {
		var native usageNative
		if err := m.retainedInternal(refs.Native, &native); err != nil {
			return native.Endpoint, native.Peer, err
		}
		if scope.Config == native.Endpoint.Config && native.Endpoint.WorkerLeaseID == leaseID {
			return native.Endpoint, native.Peer, nil
		}
	}
	return api.InstalledBinding{}, api.PeerFacts{}, problem(api.CodeNotFound, "test usage native mapping absent")
}

func (m *memoryStore) WorkerBinding(ctx context.Context, endpoint api.InstalledBinding, peer api.PeerFacts) (api.WorkerPrincipal, error) {
	if m.readError != nil {
		return api.WorkerPrincipal{}, m.readError
	}
	for _, refs := range m.usage {
		var principal api.WorkerPrincipal
		if err := m.retainedInternal(refs.Principal, &principal); err != nil {
			return principal, err
		}
		if reflect.DeepEqual(principal.Endpoint, endpoint) && principal.Peer == peer {
			return principal, nil
		}
	}
	return api.WorkerPrincipal{}, problem(api.CodeForbidden, "test usage worker lookup differs from native mapping")
}

func (m *memoryStore) usageProfile(ctx context.Context, grant api.ProfileGrant) (string, error) {
	if m.readError != nil {
		return "", m.readError
	}
	for _, refs := range m.usage {
		var enrollment usageEnrollment
		if err := m.retainedObject(refs.Enrollment, &enrollment); err != nil {
			return "", err
		}
		if reflect.DeepEqual(enrollment.Grant, grant) {
			return enrollment.VendorProfile, nil
		}
	}
	return "", problem(api.CodeForbidden, "test usage profile enrollment differs")
}

// These are explicitly synthetic protected records. No native worker or actual
// provider usage command executes, and no fixture proves authenticated quota.
func (f *runnerFixture) seedUsage(exit api.ProcessObservation) {
	f.t.Helper()
	m := f.store
	if m.usage == nil {
		m.usage = map[api.LifeRef]usageFixtureRefs{}
	}
	ended, err := timestamp(exit.ObservedAt)
	if err != nil {
		f.t.Fatal(err)
	}
	if f.clock.Now().Before(ended) {
		f.clock.now = ended.Add(time.Second)
		f.service.deps.Clock = f.clock
	}
	r := f.currentPlan().Reservation
	var profile api.ProfileGrant
	for _, grant := range m.grants.Profiles {
		if grant.ID == f.request.Slot.ProfileGrantID && grant.ProfileID == f.request.Slot.ProfileID {
			profile = grant
		}
	}
	if profile.ID == "" {
		f.t.Fatal("usage fixture has no selected profile")
	}
	query := api.UsageWindowRequest{Target: r.Target, LaunchID: r.LaunchID, OperationID: r.OperationID, ProfileGrantID: profile.ID,
		ProfileID: profile.ProfileID, Provider: profile.Provider, RunEndedAt: exit.ObservedAt, AdapterVersion: AdapterVersion,
		Executable: f.service.deps.Runtime.Executable, RuntimeManifest: m.runtimeManifest}
	suffix := strconv.FormatUint(uint64(r.Target.Run), 10)
	expires := api.Timestamp(f.clock.Now().Add(time.Hour).Format(time.RFC3339Nano))
	lease := api.WorkerLease{ID: api.ID("usage_worker_" + suffix), Kind: "usage", Target: r.Target, OperationID: r.OperationID,
		EffectID: api.ID("usage_effect_" + suffix), Input: f.keepJSON(query, "worker_input"), RuntimeManifest: m.runtimeManifest,
		GrantSetID: "usage_grants", Generation: 1, ExpiresAt: expires, ConsumedBy: api.ID("usage_launch_" + suffix)}
	record := api.LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: r.Config, Target: r.Target,
		RootLifeID: r.RootLifeID, StarterChain: []api.ID{},
		Actor: api.Actor{Kind: "worker", ID: api.ID("usage_principal_" + suffix), LifeID: r.Target.LifeID}, HostUID: 12002,
		UIDLeaseID: "usage_uid", ContainmentID: "usage_containment", ProcessGeneration: "synthetic_usage_leader", GrantSetID: lease.GrantSetID,
		EndpointGeneration: 1, PolicyGeneration: r.PolicyGeneration, GrantsSHA256: hashBytes([]byte("synthetic narrow usage grants"))}
	target := r.Target
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol,
		APISchema: api.SchemaVersion, Config: r.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1,
		ServiceUID: 11000, ServiceGID: 11000, Socket: "/runtime/usage.sock", ArtifactSHA256: m.runtimeManifest.SHA256,
		ServiceVersion: "fixture", Backend: "linux-bwrap-landlock", LaunchID: record.ID, Target: &target, WorkerLeaseID: lease.ID}
	cause := m.cause
	cause.ID, cause.Kind, cause.EffectID = api.ID("usage_intent_"+suffix), api.InternalObjectRetain, lease.EffectID
	producer := api.WorkerPrincipal{StageID: api.ID("usage_stage_" + suffix), Lease: lease, Record: record, Endpoint: endpoint,
		Peer:   api.PeerFacts{HostUID: record.HostUID, HostGID: 12002, HostPID: 100, ProcessGeneration: "synthetic_usage_connector", ContainmentID: record.ContainmentID},
		BootID: "synthetic_usage_boot", AllocationGeneration: 1, CancellationEpoch: r.CancellationEpoch,
		Claim: api.EffectLease{ClaimID: "usage_claim", ExpiresAt: expires, Record: api.EffectRecord{State: "claimed", Generation: 1,
			ClaimID: "usage_claim", ClaimantID: cause.Actor.ID, ClaimExpiresAt: expires,
			Effect: api.Effect{ID: lease.EffectID, OperationID: r.OperationID, Context: &cause}}}}
	enrollment := usageEnrollment{Grant: profile, VendorProfile: "fixture-profile"}
	m.usage[r.Target] = usageFixtureRefs{Query: f.keepJSON(query, "record"), Native: f.keepJSON(usageNative{endpoint, producer.Peer}, "record"),
		Principal: f.keepJSON(producer, "record"), Enrollment: f.keepJSON(enrollment, "record")}
	evidence := api.UsageWindowEvidence{Schema: "laneboss.usage-window.v2", Target: r.Target, LaunchID: r.LaunchID, OperationID: r.OperationID,
		ProfileGrantID: profile.ID, ProfileID: profile.ProfileID, Provider: profile.Provider, AdapterVersion: AdapterVersion,
		Executable: query.Executable, RuntimeManifest: query.RuntimeManifest, WorkerLeaseID: lease.ID, ProducerID: record.Actor.ID,
		ProducerGeneration: producer.Peer.ProcessGeneration, BootID: producer.BootID, ObservedAt: api.Timestamp(f.clock.Now().Format(time.RFC3339Nano)),
		Window: "current", UsedPercent: 100, ResetsAt: expires, Row: 1}
	raw := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n" + enrollment.VendorProfile + "\tsubscription\tcurrent\t100\t" + string(expires) + "\n")
	f.retainUsage(evidence, raw)
	f.service.deps.UsageWindows, f.service.deps.UsageWorker, f.service.deps.UsageProfile = m, m.usageWorker, m.usageProfile
	retained, _ := f.retainedUsage()
	if err := api.ValidateUsageWindow(retained, query, producer, f.clock.Now()); err != nil {
		f.t.Fatal("invalid outside usage fixture", err)
	}
	if err := api.ValidateUsageSource(retained, raw, enrollment.VendorProfile); err != nil {
		f.t.Fatal("invalid usage TSV fixture", err)
	}
}

func (f *runnerFixture) retainUsage(evidence api.UsageWindowEvidence, raw []byte) api.BlobRef {
	f.t.Helper()
	m := f.store
	evidence.Raw = m.keepClass(raw, "usage_raw")
	evidence.ID = api.ID("usage_window_" + strconv.Itoa(len(m.blobs)+1))
	encoded, err := json.Marshal(evidence)
	if err != nil {
		f.t.Fatal(err)
	}
	data, err := api.CanonicalJSON(encoded)
	if err != nil {
		f.t.Fatal(err)
	}
	ref := api.BlobRef{ID: evidence.ID, Class: "usage_window", SHA256: hashBytes(data), Bytes: int64(len(data))}
	m.blobs[ref.ID], m.refs[ref.ID] = data, ref
	for _, object := range []api.BlobRef{evidence.Raw, ref} {
		m.metadata[object.ID] = api.ObjectMetadata{Ref: object, Origin: "service", SourceOperationID: evidence.OperationID,
			ACL: api.ObjectACL{Config: f.service.deps.ReadScope.Config, LifeID: f.request.Target.LifeID, Audience: "service",
				Owner: f.service.deps.ReadScope.Actor, Participants: []api.ID{}, Generation: 1}}
	}
	refs := m.usage[f.request.Target]
	refs.Evidence = ref
	m.usage[f.request.Target] = refs
	return ref
}

func (f *runnerFixture) retainedUsage() (api.UsageWindowEvidence, []byte) {
	f.t.Helper()
	var evidence api.UsageWindowEvidence
	if err := f.store.retainedObject(f.store.usage[f.request.Target].Evidence, &evidence); err != nil {
		f.t.Fatal(err)
	}
	return evidence, append([]byte{}, f.store.blobs[evidence.Raw.ID]...)
}
