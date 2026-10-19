//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestActiveParity(t *testing.T) {
	for _, handler := range []string{"capture", "spec", "runtime", "storage"} {
		t.Run(handler, func(t *testing.T) {
			root, record, reservation := storageFixture(t)
			if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
				t.Fatal(err)
			}
			binding := testBinding()
			record.Lease.UID, record.Lease.GID = binding.Lanes[0].UID, binding.Lanes[0].GID
			store := &memoryLeases{records: []leaseRecord{record}}
			m := &leaseManager{store: store, binding: binding, bootID: record.BootID, resources: &observedResources{}}
			if _, err := m.findActive(record.Lease.ID, storageReady); err != nil {
				t.Fatal(err)
			}
			store.records[0].Revoked = true
			var err error
			switch handler {
			case "capture":
				registration, _ := capturePlanFixture()
				registration.Reservation = reservation
				registration.Request.Cause = record.Request.Cause
				registration.Request.Cause.Kind = api.InternalLaunchPlan
				registration.Request.HelperLeaseID, registration.Request.ReservationID = record.Lease.ID, reservation.ID
				registration.Worker.Target, registration.Worker.OperationID, registration.Worker.GrantSetID = reservation.Target, reservation.OperationID, reservation.GrantSetID
				registration.Worker.RuntimeManifest = record.LaunchAllocations[0].Inputs.Sources.Runtime.Manifest
				registration.Worker.EffectID = registration.Request.Cause.EffectID
				registration.Policy = record.LaunchAllocations[0].Policy
				if err := validateCaptureRegistration(registration); err != nil {
					t.Fatal(err)
				}
				_, err = m.registerCapture(context.Background(), registration)
			case "spec":
				_, err = m.registerSpec(context.Background(), testSpecRegistration(record.Lease))
			case "runtime":
				_, err = m.resolvePreparedRuntime(context.Background(), testSpecRegistration(record.Lease).Handoff)
			case "storage":
				_, err = m.resolveStorage(context.Background(), launchStorageQuery{Reservation: reservation, Request: api.LaunchDataRequest{LeaseID: record.Lease.ID, ReservationID: reservation.ID, GrantSetID: reservation.GrantSetID}})
			}
			if err == nil || !strings.Contains(err.Error(), "current active unrevoked lease") || store.saveCount != 0 {
				t.Fatal("acceptance: revoked sibling missed the common acquisition gate")
			}
		})
	}
}

func TestProposedStage(t *testing.T) {
	parent, job, binding := dataTestReg(t)
	store := &memoryLeases{records: []leaseRecord{parent}}
	m := &leaseManager{store: store, binding: binding, bootID: parent.BootID}
	if _, err := m.records(); err != nil {
		t.Fatal(err)
	}
	job.Reg.Request.StageID = parent.Lease.ID
	// This is the concrete old preflight/read-validator differential.
	if err := newDataIdentity(store.records, job.Reg); err != nil {
		t.Fatal(err)
	}
	parent.DataJobs = []dataJob{job}
	before := store.saveCount
	err := m.save(parent)
	if err == nil || !strings.Contains(err.Error(), "duplicate retained data") || store.saveCount != before || len(store.records[0].DataJobs) != 0 {
		t.Fatal("acceptance: parent-alias stage poisoned the persisted journal")
	}
}

func TestRecoveryMalformed(t *testing.T) {
	m, memory, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTestDir(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}
	if err := store.Save(memory.records[0]); err != nil {
		t.Fatal(err)
	}
	bad := []byte("{incomplete protected record\n")
	badPath := filepath.Join(directory, "bad-lease.json")
	if err := os.WriteFile(badPath, bad, 0600); err != nil {
		t.Fatal(err)
	}
	m.store = store
	if _, err := m.records(); err == nil {
		t.Fatal("acceptance: normal load hid malformed journal bytes")
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
	retained, readErr := os.ReadFile(badPath)
	raw, goodErr := os.ReadFile(filepath.Join(directory, string(lease.ID)+".json"))
	var good leaseRecord
	decodeErr := json.Unmarshal(raw, &good)
	if loadErr != nil || err == nil || !strings.Contains(err.Error(), "retained malformed helper record bad-lease.json") || readErr != nil || !bytes.Equal(retained, bad) || goodErr != nil || decodeErr != nil || !good.Revoked {
		t.Fatal("acceptance: malformed neighbor blocked recovery or lost its evidence")
	}
}

func TestRevokeWithBadNeighbor(t *testing.T) {
	m, store, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	bad := store.records[0]
	bad.Schema, bad.Lease.ID, bad.Lease.ContainmentID, bad.Request.LifeID, bad.Request.Cause.Target.LifeID = "broken", "bad-lease", "bad-cg", "bad-life", "bad-life"
	bad.Lease.UID, bad.Lease.GID = m.binding.Lanes[1].UID, m.binding.Lanes[1].GID
	store.records = append(store.records, bad)
	matched, err := m.revokeNativeContainment(context.Background(), lease.ID)
	if !matched || !store.records[0].Revoked || err == nil || !strings.Contains(err.Error(), "retained invalid helper owner bad-lease") || !strings.Contains(err.Error(), "no kernel containment owner") {
		t.Fatal("acceptance: unrelated bad record prevented the native stop boundary")
	}
}

func TestDataRevokeNeighbor(t *testing.T) {
	parent, job, binding := dataTestReg(t)
	binding.Lanes = append(binding.Lanes, account{Name: "lb-lane-c", UID: 61003, GID: 61003})
	parent.DataJobs = []dataJob{job}
	bad := parent
	bad.Schema, bad.Lease.ID, bad.Lease.ContainmentID, bad.Request.LifeID, bad.Request.Cause.Target.LifeID = "broken", "bad-lease", "bad-cg", "bad-life", "bad-life"
	// Keep this neighbor unrelated: duplicated launch allocations are now
	// deliberately treated as an ambiguous owner by recovery.
	bad.Lease.UID, bad.Lease.GID, bad.DataJobs, bad.LaunchAllocations = 61003, 61003, nil, nil
	store := &memoryLeases{records: []leaseRecord{parent, bad}}
	resources := &observedResources{quietErr: failure(api.CodeContainmentUnknown, "injected data survivor")}
	m := &leaseManager{store: store, resources: resources, binding: binding, bootID: parent.BootID}
	matched, err := m.revokeData(context.Background(), job.Reg.Request.StageID)
	if !matched || store.records[0].DataJobs[0].State != "revoked" || len(resources.quiet) != 1 || resources.quiet[0] != job.Lease.ID || err == nil || !strings.Contains(err.Error(), "injected data survivor") || !strings.Contains(err.Error(), "retained invalid helper owner bad-lease") {
		t.Fatal("acceptance: bad neighbor blocked data revocation or hid a survivor")
	}
}

func TestStopBadNeighbor(t *testing.T) {
	m, registration, _, _, store := retainedGateFixture(t)
	records, err := store.Records()
	if err != nil {
		t.Fatal(err)
	}
	bad := records[0]
	bad.Schema, bad.Lease.ID, bad.Lease.ContainmentID, bad.Request.LifeID, bad.Request.Cause.Target.LifeID = "broken", "bad-lease", "bad-cg", "bad-life", "bad-life"
	bad.Lease.UID, bad.Lease.GID = m.binding.Lanes[1].UID, m.binding.Lanes[1].GID
	bad.Gate, bad.Spec, bad.SpecReceipt, bad.Captures, bad.Storage, bad.LaunchAllocations = nil, nil, nil, nil, nil, nil
	if err := store.Save(bad); err != nil {
		t.Fatal(err)
	}
	cause := testCause(api.InternalHelperStop, registration.Binding.Record.Target.LifeID)
	_, err = m.stopGate(context.Background(), api.HelperStopRequest{Cause: cause, Target: api.HelperObserveRequest{LeaseID: records[0].Lease.ID, Handle: gateHandle(records[0])}, Reason: "review control", OperationID: cause.CauseOperationID, EffectID: cause.EffectID})
	if err == nil || !strings.Contains(err.Error(), "no kernel containment owner") || !strings.Contains(err.Error(), "retained invalid helper owner bad-lease") {
		t.Fatal("acceptance: bad neighbor blocked the owned stop boundary")
	}
}
