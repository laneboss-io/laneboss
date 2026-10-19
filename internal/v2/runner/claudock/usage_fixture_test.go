package claudock

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Private synthetic worker/native/enrollment records exercise the real shared
// validators. They establish no live kernel mapping or authenticated usage.
type usageNative struct {
	Endpoint api.InstalledBinding
	Peer     api.PeerFacts
}

type usageEnrollment struct {
	GrantID       api.ID
	ProfileID     api.ID
	Provider      string
	VendorProfile string
}

func usageKey(prefix string, target api.LifeRef) string {
	return fmt.Sprintf("%s-%s-%d", prefix, target.LifeID, target.Run)
}

func (d *launchFixtureStore) ReadUsageWindow(_ context.Context, scope api.Scope, query api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	var evidence api.UsageWindowEvidence
	if err := d.scope(scope); err != nil {
		return evidence, err
	}
	var retained api.UsageWindowRequest
	if err := d.read(usageKey("usage-query", query.Target), &retained); err != nil {
		return evidence, err
	}
	if retained != query {
		return evidence, failure(api.CodeIntegrity, "fixture outside query lost its causing pins")
	}
	err := d.read(usageKey("usage-result", query.Target), &evidence)
	return evidence, err
}

func (d *launchFixtureStore) usageWorker(_ context.Context, scope api.Scope, id api.ID) (api.InstalledBinding, api.PeerFacts, error) {
	var native usageNative
	if err := d.scope(scope); err != nil {
		return native.Endpoint, native.Peer, err
	}
	err := d.read("usage-native-"+string(id), &native)
	return native.Endpoint, native.Peer, err
}

func (d *launchFixtureStore) WorkerBinding(_ context.Context, endpoint api.InstalledBinding, peer api.PeerFacts) (api.WorkerPrincipal, error) {
	var principal api.WorkerPrincipal
	if err := d.read("usage-principal-"+string(endpoint.WorkerLeaseID), &principal); err != nil {
		return principal, err
	}
	if !reflect.DeepEqual(principal.Endpoint, endpoint) || principal.Peer != peer {
		return api.WorkerPrincipal{}, failure(api.CodeForbidden, "fixture native worker lookup was foreign")
	}
	return principal, nil
}

func (d *launchFixtureStore) usageProfile(_ context.Context, grant api.ProfileGrant) (string, error) {
	var enrollment usageEnrollment
	if err := d.read("usage-enrollment-"+string(grant.ID), &enrollment); err != nil {
		return "", err
	}
	if enrollment.GrantID != grant.ID || enrollment.ProfileID != grant.ProfileID || enrollment.Provider != grant.Provider {
		return "", failure(api.CodeForbidden, "fixture usage enrollment differs from delegated profile")
	}
	return enrollment.VendorProfile, nil
}

func (f *runnerFixture) seedUsage(t *testing.T, r api.LaunchReservation, sources api.LaunchSources) {
	t.Helper()
	d := f.launch
	// One run can have several measurements with different causing operations.
	// Keep each immutable input and its protected producer records distinct.
	suffix, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	query := api.UsageWindowRequest{Target: r.Target, LaunchID: r.LaunchID, OperationID: r.OperationID,
		ProfileGrantID: f.request.Slot.ProfileGrantID, ProfileID: f.request.Slot.ProfileID, Provider: "anthropic",
		RunEndedAt: f.observation.ObservedAt, AdapterVersion: AdapterVersion, Executable: f.request.Executable, RuntimeManifest: sources.Runtime.Manifest}
	lease := api.WorkerLease{ID: api.ID("usage-lease-" + suffix), Kind: "usage", Target: r.Target, OperationID: r.OperationID, EffectID: api.ID("usage-effect-" + suffix),
		Input:           d.object(api.ID("usage-input-"+suffix), "worker_input", mustJSON(t, query), r.OperationID, r.Target.LifeID),
		RuntimeManifest: sources.Runtime.Manifest, GrantSetID: "usage-grants", Generation: 1, ExpiresAt: "2026-10-15T13:00:00Z", ConsumedBy: api.ID("usage-launch-" + suffix)}
	record := api.LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: r.Config, Target: r.Target,
		Actor:   api.Actor{Kind: "worker", ID: api.ID("usage-principal-" + suffix), LifeID: r.Target.LifeID},
		HostUID: 12002, UIDLeaseID: "usage-uid", ContainmentID: "usage-containment", ProcessGeneration: "usage-leader", GrantSetID: lease.GrantSetID,
		EndpointGeneration: 1, PolicyGeneration: 3, GrantsSHA256: contentDigest([]byte("narrow usage grants"))}
	target := r.Target
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: r.Config,
		Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 11000, ServiceGID: 11000, Socket: "/runtime/usage.sock",
		ArtifactSHA256: sources.Runtime.Manifest.SHA256, ServiceVersion: "fixture", Backend: "linux-bwrap-landlock", LaunchID: record.ID, Target: &target, WorkerLeaseID: lease.ID}
	cause := api.InternalIntent{ID: api.ID("usage-cause-" + suffix), Kind: api.InternalObjectRetain, Config: r.Config, Actor: api.Actor{Kind: "service", ID: "service-a"}, RequestedBy: r.RequestedBy,
		Target: r.Target, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: lease.EffectID, CancellationEpoch: r.CancellationEpoch}
	expiry := api.Timestamp("2026-10-15T13:00:00Z")
	producer := api.WorkerPrincipal{StageID: api.ID("usage-stage-" + suffix), Lease: lease, Record: record, Endpoint: endpoint,
		Peer:   api.PeerFacts{HostUID: record.HostUID, HostGID: 12002, HostPID: 100, ProcessGeneration: "usage-connector", ContainmentID: record.ContainmentID},
		BootID: "usage-boot", AllocationGeneration: 1, CancellationEpoch: r.CancellationEpoch,
		Claim: api.EffectLease{ClaimID: "usage-claim", ExpiresAt: expiry, Record: api.EffectRecord{State: "claimed", Generation: 1, ClaimID: "usage-claim", ClaimantID: "service-a", ClaimExpiresAt: expiry,
			Effect: api.Effect{ID: lease.EffectID, OperationID: r.OperationID, Context: &cause}}}}
	d.write(usageKey("usage-query", r.Target), query)
	d.write("usage-native-"+string(lease.ID), usageNative{endpoint, producer.Peer})
	d.write("usage-principal-"+string(lease.ID), producer)
	d.write("usage-enrollment-"+string(query.ProfileGrantID), usageEnrollment{query.ProfileGrantID, query.ProfileID, query.Provider, "fixture-profile"})
	raw := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\nfixture-profile\tsubscription\tcurrent\t100\t2026-10-15T13:00:00Z\n")
	evidence := api.UsageWindowEvidence{Schema: "laneboss.usage-window.v2", Target: query.Target, LaunchID: query.LaunchID, OperationID: query.OperationID,
		ProfileGrantID: query.ProfileGrantID, ProfileID: query.ProfileID, Provider: query.Provider, AdapterVersion: query.AdapterVersion, Executable: query.Executable, RuntimeManifest: query.RuntimeManifest,
		WorkerLeaseID: lease.ID, ProducerID: record.Actor.ID, ProducerGeneration: producer.Peer.ProcessGeneration, BootID: producer.BootID,
		ObservedAt: "2026-10-15T12:00:05Z", Window: "current", UsedPercent: 100, ResetsAt: "2026-10-15T13:00:00Z", Row: 1}
	f.retainUsage(t, evidence, raw)
}

func (f *runnerFixture) retainedUsage(t *testing.T) (api.UsageWindowEvidence, []byte) {
	t.Helper()
	var evidence api.UsageWindowEvidence
	if err := f.launch.read(usageKey("usage-result", f.request.Target), &evidence); err != nil {
		t.Fatal(err)
	}
	return evidence, get(t, fmt.Sprintf("%s/%s.bytes", f.launch.dir, evidence.Raw.ID))
}

func (f *runnerFixture) retainUsage(t *testing.T, evidence api.UsageWindowEvidence, raw []byte) api.BlobRef {
	t.Helper()
	uuid, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	evidence.ID = api.ID("usage-window-" + uuid)
	evidence.Raw = f.launch.object(api.ID("usage-raw-"+uuid), "usage_raw", raw, evidence.OperationID, evidence.Target.LifeID)
	ref := f.launch.object(evidence.ID, "usage_window", mustJSON(t, evidence), evidence.OperationID, evidence.Target.LifeID)
	var producer api.WorkerPrincipal
	if err := f.launch.read("usage-principal-"+string(evidence.WorkerLeaseID), &producer); err != nil {
		t.Fatal(err)
	}
	for _, object := range []api.BlobRef{ref, evidence.Raw} {
		var metadata api.ObjectMetadata
		if err := f.launch.read("meta-"+string(object.ID), &metadata); err != nil {
			t.Fatal(err)
		}
		metadata.ACL.Owner = producer.Record.Actor
		f.launch.write("meta-"+string(object.ID), metadata)
	}
	f.launch.write(usageKey("usage-result", f.request.Target), evidence)
	return ref
}
