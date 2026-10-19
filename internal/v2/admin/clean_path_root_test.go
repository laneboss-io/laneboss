//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCleanupNative(t *testing.T) {
	for _, mode := range []string{"retained", "dirty-unmerged", "legacy", "measured"} {
		t.Run(mode, func(t *testing.T) {
			m, e, q, group := cleanupPathFixture(t, mode != "measured", mode == "dirty-unmerged")
			ctx := context.Background()
			if mode == "measured" {
				deadline := time.Now().Add(5 * time.Second)
				q.Job.Claim.ExpiresAt = api.Timestamp(deadline.UTC().Format(time.RFC3339Nano))
				q.Job.Claim.Record.ClaimExpiresAt = q.Job.Claim.ExpiresAt
				enrolled, p, err := m.cleanupParent(ctx, q.Job)
				if err != nil {
					t.Fatal("native measured-time fixture did not enter with a live claim")
				}
				p, result, err := m.performCleanup(ctx, enrolled, p, q)
				if err != nil || result.Action != "remove_clean" || result.After.WorktreeState != "absent" || result.After.BranchState != "absent" {
					t.Fatal("native measured-time fixture did not finish under its live claim")
				}
				measured, err := time.Parse(time.RFC3339Nano, string(result.After.ObservedAt))
				if err != nil || !measured.Before(deadline) {
					t.Fatal("native result was not measured before the claim expired")
				}
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				<-timer.C
				p, err = m.find(e.LeaseID)
				if err != nil {
					t.Fatal(err)
				}
				if p.Cleanup == nil || p.Cleanup.Phase != "worktree_removed" || p.Cleanup.Removal != nil {
					t.Fatal("native result fixture was already published before its delayed write")
				}
				// Delay the first completion write after the actual native result
				// was measured. The production producer/writer are unchanged.
				original := p.Cleanup.Job
				got, err := m.finishCleanup(p, q.Job, result)
				p, readErr := m.find(e.LeaseID)
				if err != nil || readErr != nil || p.Cleanup == nil || p.Cleanup.Phase != "complete" || p.Cleanup.Removal == nil || !reflect.DeepEqual(got, result) || !reflect.DeepEqual(original, p.Cleanup.Job) || !reflect.DeepEqual(result, *p.Cleanup.Removal) {
					t.Fatalf("acceptance: cleanup rejected a finished measured result after claim expiry: %v", err)
				}
				return
			}
			p, err := m.find(e.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "legacy" {
				// Reproduce the older ordering using the actual ancestry proof
				// and retention writer; no terminal journal is built by hand.
				ancestry := requireCleanupMerged(ctx, e, q.Before)
				retained := m.retainCleanupRefusal(&p, q.Job, ancestry)
				var typed *api.Error
				if !errors.As(retained, &typed) || typed.Code != CodeCleanupUnmerged {
					t.Fatal("legacy retained fixture did not use the native retention writer")
				}
			}
			blocker, hold, _ := cleanupHolder(t, group, p.Archive.Worker.Lease, p.BootID)
			_, refused := m.removeCleanup(ctx, q)
			p, err = m.find(e.LeaseID)
			var typed *api.Error
			used := map[uint32]bool{}
			reserveArchiveUIDs([]leaseRecord{p}, used)
			_, groupErr := os.Stat(group)
			if err != nil || !errors.As(refused, &typed) || typed.Code != api.CodeContainmentUnknown || mode != "legacy" && p.Cleanup != nil || p.Archive.Worker.Collected || !used[p.Lease.UID] || !used[p.Archive.Worker.Lease.UID] || groupErr != nil {
				t.Fatal("acceptance: retained cleanup bypassed native worker collection")
			}
			if err := hold.Close(); err != nil {
				t.Fatal(err)
			}
			if err := blocker.Wait(); err != nil {
				t.Fatal(err)
			}
			_, refused = m.removeCleanup(ctx, q)
			p, err = m.find(e.LeaseID)
			typed = nil
			if err != nil || !errors.As(refused, &typed) || typed.Code != CodeCleanupUnmerged || typed.Retryable || p.Cleanup == nil || p.Cleanup.Phase != "retained_unmerged" || p.Cleanup.Reason != "branch_not_merged" || p.Cleanup.Retained == nil || p.Cleanup.Removal != nil || !sameWorkspaceObservation(p.Cleanup.Before, *p.Cleanup.Retained) {
				t.Fatalf("acceptance: native unmerged refusal lost its persisted retention proof: mode=%s refusal=%v journal_read=%v", mode, refused, err)
			}
			used = map[uint32]bool{}
			reserveArchiveUIDs([]leaseRecord{p}, used)
			_, groupErr = os.Stat(group)
			if !p.Archive.Worker.Collected || p.Archive.Worker.Collecting || used[p.Lease.UID] || used[p.Archive.Worker.Lease.UID] || !errors.Is(groupErr, os.ErrNotExist) {
				t.Fatal("acceptance: retained cleanup kept a native UID or cgroup")
			}
			// A terminal label alone cannot release either reservation when
			// the durable worker-collection fact is missing.
			p.Archive.Worker.Collected = false
			used = map[uint32]bool{}
			reserveArchiveUIDs([]leaseRecord{p}, used)
			if !used[p.Lease.UID] || !used[p.Archive.Worker.Lease.UID] {
				t.Fatal("acceptance: terminal retention released an uncollected worker UID")
			}
			p, err = m.find(e.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "dirty-unmerged" {
				kept, err := os.ReadFile(filepath.Join(e.Parent, string(e.Workspace.ID), "dirty.txt"))
				if err != nil || string(kept) != "uncommitted work stays\n" || p.Cleanup.Before.Dirty == nil || !*p.Cleanup.Before.Dirty {
					t.Fatal("acceptance: dirty unmerged cleanup lost its kept bytes or ancestry-first reason")
				}
			}
			journal, err := m.store.Records()
			if err != nil || len(journal) != 1 {
				t.Fatal("native cleanup journal could not be independently reopened")
			}
			original := encodeLaunchFixture(t, journal[0].Cleanup)
			// A released UID can now belong to another process. Retained replay
			// reads namespaces and the original journal without reclaiming it.
			reuse := cleanupCgroup(t, m.binding, api.ID(string(e.LeaseID)+"-reuse"))
			_, _, _ = cleanupHolder(t, reuse, p.Lease, p.BootID)
			q.Job.Claim.ClaimID = "retained-reader"
			q.Job.Claim.Record.ClaimID = q.Job.Claim.ClaimID
			q.Job.Claim.Record.Generation++
			_, replayErr := m.removeCleanup(ctx, q)
			typed = nil
			after, readErr := m.store.Records()
			if !errors.As(replayErr, &typed) || typed.Code != CodeCleanupUnmerged || readErr != nil || len(after) != 1 || !bytes.Equal(original, encodeLaunchFixture(t, after[0].Cleanup)) {
				t.Fatal("acceptance: retained replay changed its original journal or reclaimed a released UID")
			}
			p, err = m.find(e.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			p.Cleanup.Reason = "unmeasured"
			if err := m.save(p); err == nil {
				t.Fatal("acceptance: terminal cleanup retained an unmeasured reason")
			}
			p, err = m.find(e.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			p.Cleanup.Retained.ObservedAt = api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
			typed = nil
			if err := m.save(p); !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "cleanup retained time is invalid or in the future" {
				t.Fatal("acceptance: retained journal accepted a future native result time")
			}
			changed := filepath.Join(e.Parent, string(e.Workspace.ID), "replay-change")
			if mode == "dirty-unmerged" {
				if err := os.Remove(filepath.Join(e.Parent, string(e.Workspace.ID), "dirty.txt")); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(changed, []byte("changed retained decision\n"), 0600); err != nil {
				t.Fatal(err)
			}
			_, replayErr = m.removeCleanup(ctx, q)
			typed = nil
			if !errors.As(replayErr, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "terminal retained cleanup changed its kept namespaces" {
				t.Fatal("acceptance: retained replay accepted a changed native decision")
			}
		})
	}
}

func TestCleanupRetainedDirtySupersede(t *testing.T) {
	m, e, q, _ := cleanupPathFixture(t, false, true)
	ctx := context.Background()
	enrolled, p, err := m.cleanupParent(ctx, q.Job)
	if err != nil {
		t.Fatal(err)
	}
	p, first, err := m.performCleanup(ctx, enrolled, p, q)
	if err != nil || first.Action != "retain_dirty" {
		t.Fatalf("initial dirty cleanup did not retain its measured workspace: %v", err)
	}
	if _, err := m.finishCleanup(p, q.Job, first); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.Parent, string(e.Workspace.ID), "dirty.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.Parent, string(e.Workspace.ID), "merged.txt"), []byte("merged lane work\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := gitSuccess(ctx, e, true, "add", "--", "merged.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitSuccess(ctx, e, true, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "-m", "merged lane work"); err != nil {
		t.Fatal(err)
	}
	tip, present, err := cleanupBranch(ctx, e)
	if err != nil || !present || tip == e.Workspace.Head {
		t.Fatal("merged supersede fixture has no moved lane tip")
	}
	if _, code, err := cleanupGit(ctx, e, false, "update-ref", "HEAD", tip); err != nil || code != 0 {
		t.Fatal("merged supersede fixture could not fast-forward repository HEAD", err, code)
	}
	successor := successorCleanupJob(q.Job)
	successor.Intent.Workspace.Head = tip
	q2 := q
	q2.Job = successor
	enrolled, _, err = m.cleanupParent(ctx, q2.Job)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := inspectNativeWorkspace(ctx, enrolled)
	if err != nil {
		t.Fatal(err)
	}
	q2.Before = fresh
	if enrolled.Workspace.Head != fresh.Head {
		t.Fatalf("clean_parent refused the fresh clean supersede: %v", err)
	}
	removal, err := m.removeCleanup(ctx, q2)
	if err != nil || removal.Action != "remove_clean" || removal.After.WorktreeState != "absent" || removal.After.BranchState != "absent" {
		t.Fatalf("clean supersede did not remove the clean workspace: %v", err)
	}
	record, err := m.find(e.LeaseID)
	if err != nil || record.Cleanup == nil || len(record.Cleanup.History) != 1 || record.Cleanup.History[0].Removal == nil ||
		record.Cleanup.History[0].Removal.Action != "retain_dirty" || record.Cleanup.Removal == nil || record.Cleanup.Removal.Action != "remove_clean" {
		t.Fatalf("clean supersede lost its retained history: %v", err)
	}
}

func TestCleanDirtySupersedeUnmerged(t *testing.T) {
	m, e, q, _ := cleanupPathFixture(t, false, true)
	ctx := context.Background()
	enrolled, p, err := m.cleanupParent(ctx, q.Job)
	if err != nil {
		t.Fatal(err)
	}
	p, first, err := m.performCleanup(ctx, enrolled, p, q)
	if err != nil || first.Action != "retain_dirty" {
		t.Fatalf("initial dirty cleanup did not retain its measured workspace: %v", err)
	}
	if _, err := m.finishCleanup(p, q.Job, first); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.Parent, string(e.Workspace.ID), "dirty.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.Parent, string(e.Workspace.ID), "unmerged.txt"), []byte("unmerged lane work\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := gitSuccess(ctx, e, true, "add", "--", "unmerged.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitSuccess(ctx, e, true, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "-m", "unmerged lane work"); err != nil {
		t.Fatal(err)
	}
	tip, present, err := cleanupBranch(ctx, e)
	if err != nil || !present || tip == e.Workspace.Head {
		t.Fatal("unmerged supersede fixture has no moved lane tip")
	}
	successor := successorCleanupJob(q.Job)
	successor.Intent.Workspace.Head = tip
	q2 := q
	q2.Job = successor
	enrolled, _, err = m.cleanupParent(ctx, q2.Job)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := inspectNativeWorkspace(ctx, enrolled)
	if err != nil {
		t.Fatal(err)
	}
	q2.Before = fresh
	_, refused := m.removeCleanup(ctx, q2)
	var typed *api.Error
	if !errors.As(refused, &typed) || typed.Code != CodeCleanupUnmerged {
		t.Fatalf("unmerged supersede lost its ancestry refusal: %v", refused)
	}
	record, err := m.find(e.LeaseID)
	if err != nil || record.Cleanup == nil || record.Cleanup.Phase != "retained_unmerged" ||
		len(record.Cleanup.History) != 1 || record.Cleanup.History[0].Removal == nil || record.Cleanup.History[0].Removal.Action != "retain_dirty" {
		t.Fatalf("unmerged supersede lost retained dirty history: %v", err)
	}
	kept, err := inspectNativeWorkspace(ctx, enrolled)
	if err != nil || kept.WorktreeState != "present" || kept.BranchState != "present" {
		t.Fatalf("unmerged supersede removed its namespaces: %v", err)
	}
}
