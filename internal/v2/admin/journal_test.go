package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type refusedLeaseStore struct {
	leaseStorage
	read, write bool
}

func (s refusedLeaseStore) Records() ([]leaseRecord, error) {
	if s.read {
		return nil, errors.New("private journal read detail")
	}
	return s.leaseStorage.Records()
}

func (s refusedLeaseStore) Save(record leaseRecord) error {
	if s.write {
		return errors.New("private journal write detail")
	}
	return s.leaseStorage.Save(record)
}

func TestLeaseSaveRuleReasons(t *testing.T) {
	for _, mode := range []string{"read", "write", "duplicate", "identity", "phase", "abort_state", "spec_state", "recovery_transition", "recovery_owner"} {
		t.Run(mode, func(t *testing.T) {
			m, memory, _ := testManager()
			if _, err := m.allocate(context.Background(), testAllocation()); err != nil {
				t.Fatal(err)
			}
			record := memory.records[0]
			before := memory.saveCount
			switch mode {
			case "read", "write":
				m.store = refusedLeaseStore{leaseStorage: memory, read: mode == "read", write: mode == "write"}
			case "duplicate":
				memory.records = append(memory.records, record)
			case "identity":
				record.Schema = "private-invalid-schema"
			case "phase":
				record.Phase = "private-invalid-phase"
			case "abort_state":
				record.Phase = "aborted"
			case "spec_state":
				record.SpecReceipt = &api.PreparedSpecReceipt{}
			case "recovery_transition":
				m.recovery = &journalRecovery{records: []leaseRecord{record}, allowed: map[api.ID]bool{record.Lease.ID: true}}
				record.Lease.ContainmentID = "private-replacement-containment"
			case "recovery_owner":
				m.recovery = &journalRecovery{records: []leaseRecord{record}, allowed: map[api.ID]bool{}}
			}
			err := m.save(record)
			want := "lease_" + mode
			if err == nil || api.HelperReason(err) != want || memory.saveCount != before {
				t.Fatalf("lease save did not retain its fixed failing rule: want=%s reason=%s", want, api.HelperReason(err))
			}
			var journal bytes.Buffer
			trace := helperRequestTrace{method: "data_open", check: "operation"}
			if err := trace.write(&journal, err); err != nil {
				t.Fatal(err)
			}
			var entry map[string]string
			if json.Unmarshal(journal.Bytes(), &entry) != nil || len(entry) != 4 || entry["reason"] != want || bytes.Contains(journal.Bytes(), []byte("private")) {
				t.Fatal("lease save diagnostic exposed values or lost its fixed rule")
			}
		})
	}
}

func TestActiveRecord(t *testing.T) {
	for _, fault := range []string{"revoked", "boot", "phase", "absent", "not-ready", "collecting", "collected"} {
		t.Run(fault, func(t *testing.T) {
			m, store, _ := testManager()
			lease, err := m.allocate(context.Background(), testAllocation())
			if err != nil {
				t.Fatal(err)
			}
			record := store.records[0]
			record.Storage = &launchStorageRecord{Ready: true}
			if err := m.requireActive(record, storageReady); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "revoked":
				record.Revoked = true
			case "boot":
				record.BootID += "-old"
			case "phase":
				record.Phase = "reserved"
			case "absent":
				record.Storage = nil
			case "not-ready":
				record.Storage.Ready = false
			case "collecting":
				record.Storage.Collecting = true
			case "collected":
				record.Storage.Collected = true
			}
			if err := m.requireActive(record, storageReady); err == nil {
				t.Fatal("acceptance: inactive record acquired launch resources")
			}
			if lease.ID == "" {
				t.Fatal("allocation fixture missing")
			}
		})
	}
}

func TestWriteIdentity(t *testing.T) {
	for _, fault := range []string{"stage-parent", "new-parent", "actor", "uid"} {
		t.Run(fault, func(t *testing.T) {
			m, store, _ := testManager()
			lease, err := m.allocate(context.Background(), testAllocation())
			if err != nil {
				t.Fatal(err)
			}
			before := store.saveCount
			record := store.records[0]
			switch fault {
			case "stage-parent":
				record.DataJobs = []dataJob{{Reg: dataReg{Request: api.StorageProjectionRequest{StageID: lease.ID}, Worker: api.WorkerLease{ID: "worker-new", EffectID: "worker-effect"}, LaunchID: "worker-launch"}, Lease: api.HelperLease{ID: "job-new", ContainmentID: "job-cg", UID: m.binding.Lanes[1].UID}}}
			case "new-parent":
				record.Lease.ID, record.Request.LifeID = "second-lease", "second-life"
				record.Request.Cause.Target.LifeID = record.Request.LifeID
			case "actor":
				record.DataJobs = []dataJob{{Reg: dataReg{Request: api.StorageProjectionRequest{StageID: "stage-new"}, Worker: api.WorkerLease{ID: "worker-new", EffectID: "worker-effect"}, LaunchID: "worker-launch"}, Lease: api.HelperLease{ID: "job-new", ContainmentID: "job-cg"}, Gate: &dataGate{Record: &api.LaunchRecord{Actor: record.Request.Cause.RequestedBy}}}}
			case "uid":
				record.Lease.ID, record.Lease.ContainmentID, record.Request.LifeID = "second-lease", "second-cg", "second-life"
				record.Request.Cause.Target.LifeID = record.Request.LifeID
			}
			if err := m.save(record); err == nil || store.saveCount != before {
				t.Fatal("acceptance: invalid proposed identity reached durable save")
			}
		})
	}
}

func TestRecoveryAcquire(t *testing.T) {
	m, store, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	finish, err := m.beginRecovery()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := finish(nil); err != nil {
			t.Error(err)
		}
	}()
	if _, err := m.find(lease.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.findActive(store.records[0].Lease.ID, storageInitializing); err == nil {
		t.Fatal("acceptance: recovery granted launch authority")
	}
}

func TestRecoveryFrozen(t *testing.T) {
	m, store, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	finish, err := m.beginRecovery()
	if err != nil {
		t.Fatal(err)
	}
	record, err := m.find(lease.ID)
	if err != nil {
		finish(err)
		t.Fatal(err)
	}
	before := store.saveCount
	record.Lease.ContainmentID = "replacement-group"
	err = m.save(record)
	if finalErr := finish(nil); finalErr != nil {
		t.Fatal(finalErr)
	}
	if err == nil || store.saveCount != before || store.records[0].Lease.ContainmentID == record.Lease.ContainmentID {
		t.Fatal("acceptance: recovery replaced a retained containment")
	}
}

func TestRecoveryUnrelated(t *testing.T) {
	m, store, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	bad := store.records[0]
	bad.Schema, bad.Lease.ID, bad.Lease.ContainmentID, bad.Request.LifeID = "broken", "bad-lease", "bad-cg", "bad-life"
	bad.Lease.UID, bad.Lease.GID = m.binding.Lanes[1].UID, m.binding.Lanes[1].GID
	bad.Request.Cause.Target.LifeID = bad.Request.LifeID
	store.records = append(store.records, bad)
	if _, err := m.records(); err == nil {
		t.Fatal("normal load accepted bad journal")
	}
	finish, err := m.beginRecovery()
	if err != nil {
		t.Fatal(err)
	}
	record, loadErr := m.find(lease.ID)
	if loadErr == nil {
		record.Revoked = true
		loadErr = m.save(record)
	}
	err = finish(loadErr)
	if loadErr != nil || !store.records[0].Revoked || store.records[1].Schema != "broken" || err == nil || !strings.Contains(err.Error(), "retained invalid helper owner bad-lease") {
		t.Fatal("acceptance: unrelated journal damage blocked or vanished during recovery")
	}
	if m.recovery != nil {
		t.Fatal("recovery scope leaked")
	}
}

func TestRecoveryConflict(t *testing.T) {
	m, store, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	other := store.records[0]
	other.Lease.ID, other.Request.LifeID, other.Request.Cause.Target.LifeID = "other-lease", "other-life", "other-life"
	// This owner aliases the selected containment and UID. Neither may be used.
	store.records = append(store.records, other)
	before := store.saveCount
	finish, err := m.beginRecovery()
	if err != nil {
		t.Fatal(err)
	}
	_, loadErr := m.find(lease.ID)
	err = finish(loadErr)
	if loadErr == nil || err == nil || store.saveCount != before {
		t.Fatal("acceptance: ambiguous recovery owner became usable")
	}
}

func TestRecoveryIdentityDamage(t *testing.T) {
	m, store, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	bad := store.records[0]
	bad.Lease.ID, bad.Lease.ContainmentID, bad.Request.LifeID, bad.Request.Cause.Target.LifeID = "bad-lease", "bad-cg", "bad-life", "bad-life"
	bad.Lease.UID, bad.Lease.GID = m.binding.Lanes[1].UID, m.binding.Lanes[1].GID
	bad.DataJobs = []dataJob{{Lease: api.HelperLease{ID: "duplicate", ContainmentID: "duplicate"}}}
	store.records = append(store.records, bad)
	finish, err := m.beginRecovery()
	if err != nil {
		t.Fatal(err)
	}
	record, loadErr := m.find(lease.ID)
	if loadErr == nil {
		record.Revoked = true
		loadErr = m.save(record)
	}
	err = finish(loadErr)
	if loadErr != nil || !store.records[0].Revoked || err == nil || !strings.Contains(err.Error(), "duplicate retained data") {
		t.Fatal("acceptance: unrelated identity poison disabled safe recovery")
	}
}

func TestRecoveryWire(t *testing.T) {
	m, store, _ := testManager()
	if _, err := m.allocate(context.Background(), testAllocation()); err != nil {
		t.Fatal(err)
	}
	bad := store.records[0]
	bad.Schema, bad.Lease.ID, bad.Lease.ContainmentID, bad.Request.LifeID, bad.Request.Cause.Target.LifeID = "broken", "bad-lease", "bad-cg", "bad-life", "bad-life"
	bad.Lease.UID, bad.Lease.GID = m.binding.Lanes[1].UID, m.binding.Lanes[1].GID
	store.records = append(store.records, bad)
	finish, err := m.beginRecovery()
	if err != nil {
		t.Fatal(err)
	}
	err = finish(failure(api.CodeContainmentUnknown, "selected stop failed"))
	var wire *api.Error
	if !errors.As(err, &wire) || wire.Code != api.CodeIntegrity || !strings.Contains(wire.Message, "bad-lease") || !strings.Contains(wire.Message, "selected stop failed") {
		t.Fatal("acceptance: helper wire error hid retained journal damage")
	}
}

func TestIdentityOwnerScope(t *testing.T) {
	records := identityRecords()
	records[1].DataJobs[0].Reg.Worker.ID = records[0].DataJobs[0].Reg.Worker.ID
	records = append(records, leaseRecord{Lease: api.HelperLease{ID: "safe-parent", ContainmentID: "safe-cg"}})
	if err := validateIdentityScope(records, "safe-parent"); err != nil {
		t.Fatal(err)
	}
	if err := validateIdentityScope(records, records[0].Lease.ID); err == nil {
		t.Fatal("acceptance: scoped validator ignored an affected owner")
	}
}
