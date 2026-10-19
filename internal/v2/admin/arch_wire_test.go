//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// External component tests use the real writer without creating an admin ->
// store -> admin import cycle. Only native allocation facts are declared here;
// query construction and epoch comparison are the production implementations.
type StopArchiveEpochProbe struct {
	record leaseRecord
}

// Derive the process identity exactly as openGate does, before the real
// writer records its first observation. No observed pin is rewritten later.
func StopArchiveLaunchHandle(binding api.LaunchBindingRequest) api.ProcessHandle {
	return gateHandle(leaseRecord{Spec: &specRegistration{Handoff: binding.Recovery.Handoff},
		Gate: &gateJournal{Prepared: binding.Prepared}, Lease: api.HelperLease{ContainmentID: binding.Record.ContainmentID}})
}

func NewStopArchiveEpochProbe(reservation api.LaunchReservation) *StopArchiveEpochProbe {
	record := leaseRecord{Request: api.HelperLeaseRequest{Config: reservation.Config},
		LaunchAllocations: []launchAllocation{{Reservation: reservation}},
		Gate: &gateJournal{Prepared: api.PreparedLaunch{Target: reservation.Target},
			Request: api.HelperLaunchRequest{Cause: api.InternalIntent{CancellationEpoch: reservation.CancellationEpoch}}}}
	return &StopArchiveEpochProbe{record: record}
}

func (p *StopArchiveEpochProbe) Stop(cause api.InternalIntent) error {
	// The reconciler's launcher must deliver the real writer cause here.
	// Construction and end observation never manufacture a native stop.
	return retainNativeStop(&p.record, cause)
}

func (p *StopArchiveEpochProbe) FirstStop() (api.InternalIntent, bool) {
	if p.record.Gate.Stop == nil {
		return api.InternalIntent{}, false
	}
	return *p.record.Gate.Stop, true
}

func (p *StopArchiveEpochProbe) MismatchStop(fence *archivejob.EpochFence, intent archivejob.Intent, field string) error {
	record, gate, cause := p.record, *p.record.Gate, *p.record.Gate.Stop
	switch field {
	case "epoch":
		cause.CancellationEpoch++
	case "operation":
		cause.CauseOperationID += "-other"
	case "request":
		cause.CauseRequestID += "-other"
	case "requester":
		cause.RequestedBy.ID += "-other"
	case "turn":
		cause.LogicalTurnID += "-other"
	default:
		return failure(api.CodeInvalid, "unknown stop mismatch control")
	}
	gate.Stop = &cause
	record.Gate, record.ArchiveEpoch = &gate, fence
	return archiveNativeEpoch(record, intent)
}

func (p *StopArchiveEpochProbe) RevokedCheck(fence *archivejob.EpochFence, cause api.InternalIntent) error {
	record := p.record
	record.Revoked, record.ArchiveEpoch = true, fence
	record.Credentials = &credentialJournal{State: "withdrawn", Stop: &credentialStop{Cause: cause, Reason: api.CredentialStopReason}}
	return validateArchiveEpoch(record)
}

func (p *StopArchiveEpochProbe) Probe(ctx context.Context, state api.StateStore, intent archivejob.Intent, lane api.Lane) (*archivejob.EpochFence, error) {
	client := &Service{deps: Dependencies{Store: state}}
	query, err := client.archiveFreezeQuery(ctx, intent, lane)
	if err != nil {
		return nil, err
	}
	if query.Epoch != nil {
		if err := archivejob.ValidateEpochFence(*query.Epoch); err != nil {
			return nil, err
		}
		record := p.record
		record.ArchiveEpoch = query.Epoch
		if err := validateArchiveEpoch(record); err != nil {
			return nil, err
		}
	}
	return query.Epoch, p.Check(query.Epoch, intent)
}

// These native ownership/counter facts are component inputs, not an installed
// release receipt. The release cause and measured end are the real writer's.
func (p *StopArchiveEpochProbe) Release(binding api.LaunchBindingRequest, request api.HelperReleaseRequest) error {
	record := &p.record
	record.Request.LifeID = binding.Record.Target.LifeID
	record.Lease = api.HelperLease{ID: binding.Record.UIDLeaseID, ContainmentID: binding.Record.ContainmentID}
	record.IssuedAt = request.Observation.ObservedAt
	record.Phase = "released"
	record.Storage = &launchStorageRecord{Ready: true, Withdrawn: true}
	record.Gate.Prepared = binding.Prepared
	record.Gate.State, record.Gate.Observation = "ended", &request.Observation
	record.Gate.Permit = &api.LaunchPermit{LaunchID: binding.Record.ID}
	record.Spec = &specRegistration{Handoff: binding.Recovery.Handoff}
	record.Release = &request
	zero := uint64(0)
	record.Receipt = &api.ReleaseReceipt{ID: api.ID(string(request.Cause.ID) + "-receipt"), LeaseID: request.LeaseID,
		ContainmentID: binding.Record.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: request.Cause.CauseOperationID,
		EffectID: request.Cause.EffectID, ObservedAt: request.Observation.ObservedAt, Quiescence: request.Observation,
		LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero}
	return validateReceipt(*record, request, *record.Receipt)
}

func (p *StopArchiveEpochProbe) Check(fence *archivejob.EpochFence, intent archivejob.Intent) error {
	record := p.record
	record.ArchiveEpoch = fence
	return archiveNativeEpoch(record, intent)
}

func (p *StopArchiveEpochProbe) WithoutNativeStop(fence *archivejob.EpochFence, intent archivejob.Intent) error {
	record := p.record
	gate := *record.Gate
	gate.Stop = nil
	record.Gate, record.ArchiveEpoch = &gate, fence
	return archiveNativeEpoch(record, intent)
}

func TestArchiveJournalWire(t *testing.T) {
	for _, mode := range []string{"archive", "allocated", "decided", "retained", "removed"} {
		t.Run(mode, func(t *testing.T) {
			m, memory, _ := testManager()
			if _, err := m.allocate(context.Background(), testAllocation()); err != nil {
				t.Fatal(err)
			}
			p := memory.records[0]
			r := archiveClaimFixture()
			p.Archive = &archiveJournal{Intent: r.Job.Intent, LaunchID: "original-launch", Phase: "withdrawing", Tree: api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}, Inventory: []storageInode{}}
			if mode != "archive" {
				p.Archive.Worker = &archiveWorker{Reg: r, Lease: p.Lease, State: "allocated", Created: gateTimestamp()}
			}
			_, current, old := cleanupClaimFixture(t)
			switch mode {
			case "decided":
				p.Cleanup = &cleanupJournal{Job: current, Phase: "decided", Before: old.Before}
			case "retained":
				kept := old.Before
				kept.ID = "retained-readback"
				p.Cleanup = &cleanupJournal{Job: current, Phase: "retained_unmerged", Before: old.Before, Retained: &kept, Refusal: cleanupUnmergedRefusal(current.Intent.Cause.CauseOperationID)}
			case "removed":
				p.Cleanup = &old
			}
			root, err := os.OpenRoot(privateTestDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			store := &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}
			writeErr := store.Save(p)
			actual, readErr := store.Records()
			if writeErr != nil || readErr != nil || len(actual) != 1 || !reflect.DeepEqual(p, actual[0]) {
				t.Fatalf("acceptance: archive cleanup journal failed strict native readback: mode=%s write=%v read=%v", mode, writeErr, readErr)
			}
			// Optional means absent, never explicit null. The frozen decoder
			// continues rejecting duplicate/unknown/null members.
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]any
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			object["archive"].(map[string]any)["Objects"] = nil
			raw, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			var decoded leaseRecord
			if err := decodeStrict(raw, &decoded); err == nil {
				t.Fatal("acceptance: archive journal accepted an explicit null member")
			}
		})
	}
}

func TestArchiveWriteReadback(t *testing.T) {
	m, memory, _ := testManager()
	if _, err := m.allocate(context.Background(), testAllocation()); err != nil {
		t.Fatal(err)
	}
	p := memory.records[0]
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	before, err := root.ReadFile(string(p.Lease.ID) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	r := archiveClaimFixture()
	r.Job.Plan.Argv = nil // A required array cannot encode as JSON null.
	p.Archive = &archiveJournal{Intent: r.Job.Intent, Tree: api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}, Inventory: []storageInode{}, Worker: &archiveWorker{Reg: r, Lease: p.Lease}}
	err = store.Save(p)
	after, readErr := root.ReadFile(string(p.Lease.ID) + ".json")
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "helper lease record cannot pass its strict readback" || readErr != nil || !bytes.Equal(before, after) {
		t.Fatal("acceptance: native helper published a record its strict reader refuses")
	}
}

func TestArchiveQueryWire(t *testing.T) {
	r := archiveClaimFixture()
	for _, value := range []any{archiveQuery{}, cleanupQuery{}, archiveRetireQuery{Job: r.Job, Claim: r.Claim}} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var target any
		switch value.(type) {
		case archiveQuery:
			target = &archiveQuery{}
		case cleanupQuery:
			target = &cleanupQuery{}
		case archiveRetireQuery:
			target = &archiveRetireQuery{}
		}
		if err := decodeStrict(raw, target); err != nil {
			t.Fatal("acceptance: archive cleanup query failed its strict wire shape")
		}
	}
}
