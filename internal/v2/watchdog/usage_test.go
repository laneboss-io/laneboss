package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *readStore) ObjectMetadata(_ context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	m.check(scope)
	metadata, found := m.metadata[id]
	if !found {
		return api.ObjectMetadata{}, problem(api.CodeNotFound, "test object metadata is absent")
	}
	return metadata, nil
}

func (r *testRig) resolveUsage(_ context.Context, scope api.Scope, ref api.BlobRef) (UsageProvenance, error) {
	r.store.check(scope)
	provenance, found := r.store.usage[ref.ID]
	if !found || provenance.Evidence != ref {
		return UsageProvenance{}, problem(api.CodeNotFound, "test usage provenance is absent")
	}
	return provenance, nil
}

func (r *testRig) retainUsage(evidence api.UsageWindowEvidence, provenance UsageProvenance) api.BlobRef {
	r.t.Helper()
	data, err := json.Marshal(evidence)
	if err != nil {
		r.t.Fatal(err)
	}
	ref := r.addClassBlob(evidence.ID, data, "usage_window")
	provenance.Evidence = ref
	r.store.usage[ref.ID] = provenance
	for _, object := range []api.BlobRef{ref, evidence.Raw} {
		r.store.metadata[object.ID] = api.ObjectMetadata{Ref: object, Origin: "service", SourceOperationID: evidence.OperationID,
			CommittedAt: api.Timestamp(r.clock.at.Format(time.RFC3339Nano)),
			ACL: api.ObjectACL{Config: r.store.launch.Config, LifeID: evidence.Target.LifeID,
				Owner: provenance.Producer.Record.Actor, Audience: "service", Generation: 1, Participants: []api.ID{}}}
	}
	return ref
}

// Shape-valid retained job/source data only. No fixture provides native worker
// authentication, a running command, credentials or an installed-service pass.
func (r *testRig) usageFixture(id api.ID) (api.UsageWindowEvidence, UsageProvenance) {
	target := r.signal.Target
	operation := r.store.events[0].OperationID
	manifest := r.addClassBlob("usage-runtime", []byte("pinned fixture usage runtime\n"), "manifest")
	executable := api.Executable{ID: "claudock-usage", Version: "fixture-v1", SHA256: digest([]byte("pinned fixture usage executable"))}
	expires := api.Timestamp(r.clock.at.Add(time.Hour).Format(time.RFC3339Nano))
	lease := api.WorkerLease{ID: api.ID(string(id) + "-lease"), Kind: "usage", Target: target, OperationID: operation,
		EffectID: api.ID(string(id) + "-effect"), GrantSetID: "usage-grants", Generation: 1, ExpiresAt: expires,
		ConsumedBy: api.ID(string(id) + "-launch"), RuntimeManifest: manifest}
	record := api.LaunchRecord{ID: lease.ConsumedBy, Kind: "worker", Config: r.store.launch.Config, Target: target,
		Actor:   api.Actor{Kind: "worker", ID: api.ID(string(id) + "-producer"), LifeID: target.LifeID},
		HostUID: 12002, GrantSetID: lease.GrantSetID, EndpointGeneration: 1, ContainmentID: "usage-containment", ProcessGeneration: "usage-leader"}
	endpoint := api.InstalledBinding{Config: record.Config, Class: api.EndpointWorker, Target: &target,
		WorkerLeaseID: lease.ID, LaunchID: record.ID, EndpointGeneration: record.EndpointGeneration}
	cause := api.InternalIntent{ID: api.ID(string(id) + "-cause"), Kind: api.InternalObjectRetain, Config: record.Config,
		Target: target, CauseOperationID: operation, CancellationEpoch: r.store.lane.CancellationEpoch}
	claimID := api.ID(string(id) + "-claim")
	producer := api.WorkerPrincipal{StageID: api.ID(string(id) + "-stage"), Lease: lease, Record: record, Endpoint: endpoint,
		Peer:   api.PeerFacts{HostUID: record.HostUID, HostGID: 12002, HostPID: 100, ProcessGeneration: "usage-connector", ContainmentID: record.ContainmentID},
		BootID: "fixture-boot", AllocationGeneration: 1, CancellationEpoch: cause.CancellationEpoch,
		Claim: api.EffectLease{ClaimID: claimID, ExpiresAt: expires, Record: api.EffectRecord{State: "claimed", ClaimID: claimID,
			ClaimExpiresAt: expires, Effect: api.Effect{ID: lease.EffectID, OperationID: operation, Context: &cause}}}}
	reset := api.Timestamp(r.clock.at.Add(30 * time.Minute).Format(time.RFC3339Nano))
	raw := []byte(fmt.Sprintf("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\nfixture-profile\tsubscription\tcurrent\t100\t%s\n", reset))
	evidence := api.UsageWindowEvidence{Schema: "laneboss.usage-window.v2", ID: id, Target: target,
		LaunchID: r.store.launch.ID, OperationID: operation, ProfileGrantID: r.store.lane.ProfileGrantID,
		ProfileID: r.signal.ProfileID, Provider: r.signal.Provider, AdapterVersion: r.signal.AdapterVersion,
		Executable: executable, RuntimeManifest: manifest, WorkerLeaseID: lease.ID, ProducerID: record.Actor.ID,
		ProducerGeneration: producer.Peer.ProcessGeneration, BootID: producer.BootID,
		ObservedAt: api.Timestamp(r.clock.at.Format(time.RFC3339Nano)), Window: "current", UsedPercent: 100,
		ResetsAt: reset, Raw: r.addClassBlob(api.ID(string(id)+"-raw"), raw, "usage_raw"), Row: 1}
	return evidence, UsageProvenance{Producer: producer, VendorProfile: "fixture-profile", Executable: executable, RuntimeManifest: manifest}
}

func (r *testRig) fix12Usage() {
	r.store.metadata = map[api.ID]api.ObjectMetadata{}
	r.store.usage = map[api.ID]UsageProvenance{}
	evidence, provenance := r.usageFixture("usage-one")
	ref := r.retainUsage(evidence, provenance)
	r.signal.UsageEvidence, r.runner.usageEvidence = &ref, &ref
}

func TestUsageEvidence(t *testing.T) {
	for _, fault := range []string{"stale", "pre-exit", "available", "producer", "profile", "pin", "kind", "tsv-percent", "acl", "raw-hash", "reset"} {
		t.Run(fault, func(t *testing.T) {
			r := newRig(t)
			evidence, provenance := r.usageFixture("usage-fault")
			code := api.CodeInvalid
			switch fault {
			case "stale":
				evidence.ObservedAt = api.Timestamp(r.clock.at.Add(-31 * time.Second).Format(time.RFC3339Nano))
				// Isolate age from post-exit ordering: this measurement follows
				// the actual older exit, but has aged beyond thirty seconds.
				r.signal.ObservedAt = api.Timestamp(r.clock.at.Add(-2 * time.Minute).Format(time.RFC3339Nano))
				r.capture(func(c *api.CaptureRecord) { c.ObservedAt = r.signal.ObservedAt })
				r.launcher.observation.ObservedAt = api.Timestamp(r.clock.at.Add(-time.Minute).Format(time.RFC3339Nano))
			case "pre-exit":
				evidence.ObservedAt = api.Timestamp(r.clock.at.Add(-2 * time.Second).Format(time.RFC3339Nano))
			case "available":
				evidence.UsedPercent = 99
				raw := []byte(strings.Replace(string(r.store.blobs[evidence.Raw.ID]), "\t100\t", "\t99\t", 1))
				evidence.Raw = r.addClassBlob(evidence.Raw.ID, raw, "usage_raw")
			case "producer":
				evidence.ProducerGeneration = "lane-local-writer"
			case "profile":
				evidence.ProfileID = "destination-profile"
			case "pin":
				evidence.Executable.SHA256 = digest([]byte("unapproved executable"))
			case "kind":
				provenance.Producer.Lease.Kind = "materialize"
			case "tsv-percent":
				raw := []byte(strings.Replace(string(r.store.blobs[evidence.Raw.ID]), "\t100\t", "\t99\t", 1))
				evidence.Raw = r.addClassBlob(evidence.Raw.ID, raw, "usage_raw")
			case "acl", "raw-hash":
				code = api.CodeIntegrity
			case "reset":
				r.signal.ObservedAt = api.Timestamp(r.clock.at.Add(-12 * time.Second).Format(time.RFC3339Nano))
				r.capture(func(c *api.CaptureRecord) { c.ObservedAt = r.signal.ObservedAt })
				r.launcher.observation.ObservedAt = api.Timestamp(r.clock.at.Add(-11 * time.Second).Format(time.RFC3339Nano))
				evidence.ObservedAt = api.Timestamp(r.clock.at.Add(-10 * time.Second).Format(time.RFC3339Nano))
				evidence.ResetsAt = api.Timestamp(r.clock.at.Add(-5 * time.Second).Format(time.RFC3339Nano))
				raw := []byte(fmt.Sprintf("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\nfixture-profile\tsubscription\tcurrent\t100\t%s\n", evidence.ResetsAt))
				evidence.Raw = r.addClassBlob(evidence.Raw.ID, raw, "usage_raw")
			}
			ref := r.retainUsage(evidence, provenance)
			r.signal.UsageEvidence = &ref
			if fault == "acl" {
				metadata := r.store.metadata[evidence.Raw.ID]
				metadata.ACL.Owner.Kind = "lane"
				r.store.metadata[evidence.Raw.ID] = metadata
			}
			if fault == "raw-hash" {
				data := append([]byte{}, r.store.blobs[evidence.Raw.ID]...)
				data[len(data)-1] = ' '
				r.store.blobs[evidence.Raw.ID] = data
			}
			_, err := r.s.assess(context.Background(), r.signal)
			requireCode(t, err, code)
			r.noEffects()
		})
	}
}

func TestUsageRetention(t *testing.T) {
	r, store, probe := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	intent := store.intents[probe.requests[0].IntentID]
	if intent.Swap.Limit.UsageEvidence == nil || *intent.Swap.Limit.UsageEvidence != *r.signal.UsageEvidence {
		t.Fatal("accepted continuation lost its exact normalized usage evidence")
	}
	r2 := newRig(t)
	r2.s.deps.ResolveUsage = nil
	_, err := r2.s.ObserveLimit(context.Background(), r2.signal)
	requireCode(t, err, api.CodeNotImplemented)
	r2.noEffects()
}
