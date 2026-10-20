//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func retainedUIDCase(t *testing.T, unmerged bool) (*leaseManager, cleanupEnrollment, cleanupQuery, leaseRecord) {
	t.Helper()
	m, e, q, _ := cleanupPathFixture(t, unmerged, !unmerged)
	removal, err := m.removeCleanup(context.Background(), q)
	if unmerged {
		var refused *api.Error
		if !errors.As(err, &refused) || refused.Code != CodeCleanupUnmerged {
			t.Fatal("unmerged lane was not retained", err)
		}
	} else if err != nil || removal.Action != "retain_dirty" {
		t.Fatal("dirty lane was not retained", err)
	}
	p, err := m.find(e.LeaseID)
	if err != nil || !p.Archive.Worker.Collected {
		t.Fatal("retention did not collect its archive worker", err)
	}
	return m, e, q, p
}

func nextUIDLife(t *testing.T, m *leaseManager, life api.ID) api.HelperLease {
	t.Helper()
	request := testAllocation()
	request.LifeID, request.Cause.Target.LifeID = life, life
	request.Cause.ID = api.ID(string(life) + "-intent")
	request.Cause.EffectID = api.ID(string(life) + "-effect")
	lease, err := m.allocate(context.Background(), request)
	if err != nil {
		t.Fatal("next life could not allocate", err)
	}
	return lease
}

func TestRetainedUIDReuse(t *testing.T) {
	for _, mode := range []string{"dirty", "unmerged"} {
		t.Run(mode, func(t *testing.T) {
			m, _, _, p := retainedUIDCase(t, mode == "unmerged")
			// Reopen the durable journal and use the real pool allocator. Only
			// creation of the next lane's resources is a component boundary.
			next := newLeaseManager(m.binding, m.bootID, m.store, &observedResources{})
			lease := nextUIDLife(t, next, "next-life")
			if lease.UID == p.Lease.UID {
				t.Fatal("retained life UID was handed to the next lane")
			}
			group := cleanupCgroup(t, m.binding, lease.ContainmentID)
			_, _, _ = cleanupHolder(t, group, lease, p.BootID)
			if err := m.terminalGateQuiet(context.Background(), p); err != nil {
				t.Fatal("another lane caused a false retained survivor", err)
			}
		})
	}
}

func TestRetainedUIDSurvivor(t *testing.T) {
	for _, mode := range []string{"dirty", "unmerged"} {
		t.Run(mode, func(t *testing.T) {
			m, _, q, p := retainedUIDCase(t, mode == "unmerged")
			// Escape the old (already empty) cgroup while retaining its UID.
			// This is a real process, synchronized by a pipe, never a count.
			group := cleanupCgroup(t, m.binding, "retained-survivor")
			command, hold, generation := cleanupHolder(t, group, p.Lease, p.BootID)
			trace := &helperRequestTrace{method: "reconcile_gate", check: "operation"}
			ctx := context.WithValue(context.Background(), helperTimingKey{}, trace)
			if err := m.terminalGateQuiet(ctx, p); api.HelperReason(err) != "uid_survivor" {
				t.Fatal("terminal gate ignored a real retained survivor", err)
			}
			_, _, err := m.cleanupParent(ctx, q.Job)
			if api.HelperReason(err) != "uid_survivor" {
				t.Fatal("retained cleanup ignored a real surviving process", err)
			}
			var journal bytes.Buffer
			if err := trace.write(&journal, err); err != nil {
				t.Fatal(err)
			}
			var entry struct {
				Reason string `json:"reason"`
				UID    uint32 `json:"uid"`
				PID    int    `json:"pid"`
				TID    int    `json:"tid"`
				Start  string `json:"start_time"`
				Life   api.ID `json:"life_id"`
				Lease  api.ID `json:"lease_id"`
			}
			if json.Unmarshal(journal.Bytes(), &entry) != nil || entry.Reason != "uid_survivor" || entry.UID != p.Lease.UID || entry.PID != command.Process.Pid || entry.TID <= 0 || entry.Start == "" || generation != p.BootID+":"+entry.Start || entry.Life != p.Request.LifeID || entry.Lease != p.Lease.ID {
				t.Fatalf("survivor journal lost its measured owner: %s", journal.Bytes())
			}
			if err := hold.Close(); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := m.cleanupParent(context.Background(), q.Job); err != nil {
				t.Fatal("exited survivor remained falsely live", err)
			}
		})
	}
}

func TestRetainedUIDCleanReuse(t *testing.T) {
	m, e, q, p := retainedUIDCase(t, false)
	if err := os.Remove(filepath.Join(e.Parent, string(e.Workspace.ID), "dirty.txt")); err != nil {
		t.Fatal(err)
	}
	q.Job = successorCleanupJob(q.Job)
	var err error
	q.Before, err = inspectNativeWorkspace(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	removal, err := m.removeCleanup(context.Background(), q)
	if err != nil || removal.Action != "remove_clean" {
		t.Fatal("repaired retained lane did not clean", err)
	}
	next := newLeaseManager(m.binding, m.bootID, m.store, &observedResources{})
	lease := nextUIDLife(t, next, "clean-successor")
	if lease.UID != p.Lease.UID || lease.ID == p.Lease.ID {
		t.Fatal("cleaned life did not release its UID for a new lease")
	}
	group := cleanupCgroup(t, m.binding, lease.ContainmentID)
	_, _, _ = cleanupHolder(t, group, lease, p.BootID)
	retired, err := m.find(e.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	// Recovery may already hold the old inventory when collection commits.
	// Its terminal native read must respect the completed ownership transfer.
	if err := m.terminalGateQuiet(context.Background(), retired); err != nil {
		t.Fatal("terminal recovery scanned a UID transferred after cleanup", err)
	}
	if _, _, err := m.cleanupParent(context.Background(), q.Job); err != nil {
		t.Fatal("cleaned replay mistook the new lane for a survivor", err)
	}
}
