//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRevokeAllocation(t *testing.T) {
	for _, selector := range []string{"launch", "reservation"} {
		t.Run(selector, func(t *testing.T) {
			parent, _, binding := dataTestReg(t)
			if parent.Spec != nil {
				t.Fatal("allocation fixture already has a registered spec")
			}
			store := &memoryLeases{records: []leaseRecord{parent}}
			m := &leaseManager{store: store, binding: binding, bootID: parent.BootID, resources: &observedResources{}}
			if _, err := m.records(); err != nil {
				t.Fatal(err)
			}
			id := parent.LaunchAllocations[0].Reservation.LaunchID
			if selector == "reservation" {
				id = parent.LaunchAllocations[0].Reservation.ID
			}
			matched, err := m.revokeNativeContainment(context.Background(), id)
			if !matched || !store.records[0].Revoked || err == nil || !strings.Contains(err.Error(), "no kernel containment owner") {
				t.Fatal("acceptance: pre-spec launch revocation skipped its parent lease")
			}
		})
	}
}

func TestRevokeTerminal(t *testing.T) {
	m, store, _ := testManager()
	if _, err := m.allocate(context.Background(), testAllocation()); err != nil {
		t.Fatal(err)
	}
	record := store.records[0]
	record.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{LaunchID: "terminal-launch"}}}
	record.Gate = &gateJournal{State: "aborted", Prepared: api.PreparedLaunch{Target: api.LifeRef{LifeID: record.Request.LifeID, Run: 1}, ProcessGeneration: "terminal-generation"}}
	calls := 0
	wait := func() error { calls++; return contextError(context.Background()) }
	if err := waitRevokedGate(context.Background(), record, nil, wait); err != nil || calls != 1 {
		t.Fatal("acceptance: retained terminal gate lost its revocation barrier")
	}
	record.Gate.State = "ended"
	observation := testObservation(record.Lease)
	observation.Handle = gateHandle(record)
	record.Gate.Observation = &observation
	if err := waitRevokedGate(context.Background(), record, nil, wait); err != nil || calls != 2 {
		t.Fatal("acceptance: retained terminal gate lost its revocation barrier")
	}
	want := failure(api.CodeContainmentUnknown, "population remains nonzero")
	if err := waitRevokedGate(context.Background(), record, nil, func() error { return want }); !errors.Is(err, want) {
		t.Fatal("terminal revocation swallowed the population barrier")
	}
	record.Gate.Observation = nil
	record.Gate.State = "opened"
	if err := waitRevokedGate(context.Background(), record, nil, wait); err == nil || calls != 3 {
		t.Fatal("acceptance: missing live owner bypassed population wait or fabricated success")
	}
}

func TestDamagedStop(t *testing.T) {
	base := privateTestDir(t)
	groups := []api.ID{"safe", "safe-worker", "safe-capture", "bad-a", "bad-b"}
	for _, id := range groups {
		if err := os.Mkdir(filepath.Join(base, string(id)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, string(id), "kill"), []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	records := []leaseRecord{{Lease: api.HelperLease{ID: "safe-owner", ContainmentID: "safe"}, DataJobs: []dataJob{{Lease: api.HelperLease{ContainmentID: "safe-worker"}}}, Captures: []captureJournal{{Native: &captureNativeJournal{Lease: api.HelperLease{ContainmentID: "safe-capture"}}}}}, {Schema: "damaged", Lease: api.HelperLease{ID: "bad-owner", ContainmentID: "bad-a"}}}
	want := errors.New("injected population wait failure")
	err := stopUnownedGroups(context.Background(), records, map[api.ID]bool{"safe-owner": true}, groups, func(id api.ID) error {
		if err := os.WriteFile(filepath.Join(base, string(id), "kill"), []byte("1\n"), 0600); err != nil {
			return err
		}
		if id == "bad-a" {
			return want
		}
		return nil
	})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "requested stop for unowned containment bad-b") {
		t.Fatal("acceptance: damaged owner stop skipped a containment or hid its failure")
	}
	for _, id := range groups {
		raw, readErr := os.ReadFile(filepath.Join(base, string(id), "kill"))
		expected := "0\n"
		if id == "bad-a" || id == "bad-b" {
			expected = "1\n"
		}
		if readErr != nil || string(raw) != expected {
			t.Fatal("acceptance: damaged owner stop skipped a containment or touched a safe owner")
		}
	}
	if records[1].Schema != "damaged" || records[1].Revoked {
		t.Fatal("damaged recovery rewrote an untrusted journal")
	}
}

func TestInitialDescriptor(t *testing.T) {
	base := privateTestDir(t)
	name := filepath.Join(base, "input")
	if err := os.WriteFile(name, []byte("original descriptor"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0444); err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	if err := os.Rename(name, name+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replacement path"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := readProtectedDescriptor(original, 1024, 0444, uint32(os.Geteuid()))
	if err != nil || string(raw) != "original descriptor" {
		t.Fatal("acceptance: immutable read followed a replacement path")
	}
	bad, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if err := os.Rename(name, name+"-writable"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("immutable replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedDescriptor(bad, 1024, 0444, uint32(os.Geteuid())); err == nil {
		t.Fatal("acceptance: immutable read accepted a writable opened descriptor")
	}
}
