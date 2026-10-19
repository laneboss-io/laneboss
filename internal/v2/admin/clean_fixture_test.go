//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// This supplies the already released lane/archive protocol inputs. Git,
// enrollment, helper journal, worker wait, UID scan and cgroup are native;
// it is not an installed launch/archive-service composition proof.
func cleanupPathFixture(t *testing.T, unmerged, dirty bool) (*leaseManager, cleanupEnrollment, cleanupQuery, string) {
	return cleanupPathWorker(t, unmerged, dirty, cleanupWorker)
}

func cleanupPathWorker(t *testing.T, unmerged, dirty bool, makeWorker func(*testing.T, installation, leaseRecord, api.ID, string) *archiveWorker) (*leaseManager, cleanupEnrollment, cleanupQuery, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("cleanup path canary requires the disposable root Linux host")
	}
	_, p, _ := storageFixture(t)
	b := testBinding()
	id, err := randomID("lb-v2-admin-clean-")
	if err != nil {
		t.Fatal(err)
	}
	// Each native fixture owns its UID pair. Other canaries and test jobs must
	// remain visible to uidQuiescent without sharing this fixture's identity.
	nonce, err := randomID("")
	if err != nil {
		t.Fatal(err)
	}
	uidPart, err := strconv.ParseUint(string(nonce[:6]), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(1000000 + uidPart*2)
	b.Lanes[0].UID, b.Lanes[0].GID = uid, uid
	b.Lanes[1].UID, b.Lanes[1].GID = uid+1, uid+1
	p.Lease.ID, p.Lease.UID, p.Lease.GID = id, b.Lanes[0].UID, b.Lanes[0].GID
	p.Lease.ContainmentID = api.ID(string(id) + "-lane")
	p.Storage.Binding.LeaseID = id
	p.IssuedAt = api.Timestamp(time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano))
	e, _ := nativeCleanFixtureFor(t, p.Storage.Binding.WorkspaceID, p.Request.LifeID)
	e.Schema, e.Config, e.LeaseID = "laneboss.workspace-native.v2", b.Config, id
	parent := storageBase(b, p)
	if err := os.MkdirAll(filepath.Dir(parent), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Error(err)
		}
	})
	old := filepath.Join(e.Parent, string(e.Workspace.ID))
	work := filepath.Join(parent, string(e.Workspace.ID))
	if _, err := gitSuccess(context.Background(), e, false, "worktree", "move", "--", old, work); err != nil {
		t.Fatal(err)
	}
	e.Parent = parent
	var workspaceInode storageInode
	for index, item := range p.Storage.Directories {
		name := filepath.Join(parent, string(item.ID))
		if index > 0 {
			if err := os.Mkdir(name, 0500); err != nil {
				t.Fatal(err)
			}
		}
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		_, st, readErr := dataIdentity(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("cleanup storage identity measurement failed")
		}
		p.Storage.Directories[index].Device = strconv.FormatUint(uint64(st.Dev), 10)
		p.Storage.Directories[index].Inode = strconv.FormatUint(st.Ino, 10)
		if index == 0 {
			workspaceInode = storageInode{Device: uint64(st.Dev), Inode: st.Ino}
		}
	}
	file, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	e.Workspace.RootIdentity, _, err = dataIdentity(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("cleanup parent identity measurement failed")
	}
	if unmerged {
		if err := os.WriteFile(filepath.Join(work, "owned.txt"), []byte("own unmerged lane commit\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"add", "--", "owned.txt"}, {"-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "-m", "lane work"}} {
			if _, err := gitSuccess(context.Background(), e, true, args...); err != nil {
				t.Fatal(err)
			}
		}
		tip, present, err := cleanupBranch(context.Background(), e)
		if err != nil || !present || tip == e.Workspace.Head {
			t.Fatal("cleanup path fixture has no own unmerged commit")
		}
		e.Workspace.Head = tip
	}
	if dirty {
		if err := os.WriteFile(filepath.Join(work, "dirty.txt"), []byte("uncommitted work stays\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(work, 0500); err != nil {
		t.Fatal(err)
	}
	p.Storage.Ready, p.Storage.Withdrawn = true, true
	observation := testObservation(p.Lease)
	observation.ObservedAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	release := testRelease(p.Lease, observation)
	zero := uint64(0)
	p.Release = &release
	p.Receipt = &api.ReleaseReceipt{ID: "native-release", LeaseID: p.Lease.ID, ContainmentID: p.Lease.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: release.Cause.CauseOperationID, EffectID: release.Cause.EffectID, Quiescence: observation, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: observation.ObservedAt}
	p.Phase = "released"
	tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "workspace", Kind: "directory", Mode: 0700}}}
	body, err := canonicalValue(tree)
	if err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "native-archive", Class: "manifest", Bytes: int64(len(body)), SHA256: digestBytes(body)}
	intent := archivejob.Intent{Request: api.ArchiveRequest{Target: p.Request.Cause.Target, ExpectedGeneration: 7}, OperationID: "archive-operation", CancellationEpoch: p.Request.Cause.CancellationEpoch, EndEventID: "native-ended", EndSeq: 1}
	p.Archive = &archiveJournal{Intent: intent, LaunchID: "original-launch", Phase: "frozen", Tree: tree, Inventory: []storageInode{workspaceInode}, Freeze: archivejob.Freeze{Target: intent.Request.Target, LaunchID: "original-launch", CancellationEpoch: intent.CancellationEpoch, Snapshot: ref, Writers: &zero, WritableExports: &zero, ObservedAt: gateTimestamp()}}
	group := api.ID(string(id) + "-archive")
	groupPath := cleanupCgroup(t, b, group)
	p.Archive.Worker = makeWorker(t, b, p, group, groupPath)
	journalDir := filepath.Join(filepath.Dir(e.Repository), "helper-journal")
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := os.OpenRoot(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	m := newLeaseManager(b, p.BootID, &fileLeaseStore{root: journal, owner: 0}, &linuxResources{binding: b})
	if err := m.save(p); err != nil {
		t.Fatal(err)
	}
	dir := workspaceRegistryDirectory(b.Config)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	enrollment := filepath.Join(dir, string(e.Workspace.ID)+".json")
	if err := os.WriteFile(enrollment, encodeLaunchFixture(t, e), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(enrollment); err != nil {
			t.Error(err)
		}
	})
	job, live, _ := cleanupClaimFixture(t)
	job.Intent.Cause.Target, job.Intent.Cause.CancellationEpoch = e.Workspace.Target, intent.CancellationEpoch
	job.Intent.Workspace, job.Intent.Release, job.Intent.ArchiveRequest = e.Workspace, *p.Receipt, intent.Request
	job.Intent.Archive.LifeID, job.Intent.Archive.Manifest = e.Workspace.Target.LifeID, ref
	job.Intent.Archive.VerifiedAt = gateTimestamp()
	job.Claim.ExpiresAt, job.Claim.Record.ClaimExpiresAt = live.Claim.ExpiresAt, live.Claim.ExpiresAt
	cause := job.Intent.Cause
	job.Claim.Record.Effect.Context = &cause
	job.Claim.Record.Effect.Clean = &api.CleanRequest{Target: cause.Target, ExpectedGeneration: job.Intent.ExpectedGeneration, ArchiveReceiptID: job.Intent.Archive.ID}
	if err := api.ValidateCleanupJob(job, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, err := inspectNativeWorkspace(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	return m, e, cleanupQuery{Job: job, Before: before}, groupPath
}

func cleanupCgroup(t *testing.T, b installation, group api.ID) string {
	t.Helper()
	var created []string
	for _, name := range []string{filepath.Dir(b.cgroupPath()), b.cgroupPath(), filepath.Join(b.cgroupPath(), string(group))} {
		if err := os.Mkdir(name, 0755); err == nil {
			created = append(created, name)
		} else if !errors.Is(err, os.ErrExist) || name == filepath.Join(b.cgroupPath(), string(group)) {
			t.Fatal("cleanup cgroup fixture could not create its own hierarchy")
		}
	}
	t.Cleanup(func() {
		for index := len(created) - 1; index >= 0; index-- {
			if err := unix.Rmdir(created[index]); err != nil && !errors.Is(err, unix.ENOENT) {
				t.Error("cleanup fixture retained an uncollected cgroup")
			}
		}
	})
	return filepath.Join(b.cgroupPath(), string(group))
}
