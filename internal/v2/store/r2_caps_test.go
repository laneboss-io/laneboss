//go:build linux

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func manySnapshot(t *testing.T, f *archFixture, count int) archivejob.Snapshot {
	t.Helper()
	objects := make([]api.ObjectWrite, 0, count+1)
	entries := make([]api.ObjectEntry, 0, count)
	for i := 0; i < count; i++ {
		data := []byte(fmt.Sprintf("current file %d", i))
		ref := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest(data), Bytes: int64(len(data))}
		entries = append(entries, api.ObjectEntry{Path: fmt.Sprintf("files/%d", i), Kind: "file", Mode: 0600, Content: &ref})
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: data, SHA256: ref.SHA256, Origin: "service", ACL: f.s.archiveACL(f.record)})
	}
	// Parent directory and all actual content references are retained in the
	// same native snapshot, rather than inflating a count with duplicate IDs.
	entries = append(entries, api.ObjectEntry{Path: "files", Kind: "directory", Mode: 0700})
	body := archJSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: entries})
	manifest := api.BlobRef{ID: testID(t), Class: "manifest", SHA256: testDigest(body), Bytes: int64(len(body))}
	objects = append(objects, api.ObjectWrite{ObjectKey: manifest.ID, Class: manifest.Class, Bytes: body, SHA256: manifest.SHA256, Origin: "service", ACL: f.s.archiveACL(f.record)})
	for _, object := range f.native.objects {
		if object.ObjectKey == f.record.Job.Lease.RuntimeManifest.ID {
			objects = append(objects, object)
		}
	}
	freeze := f.native.freeze
	freeze.Snapshot = manifest
	return archivejob.Snapshot{Freeze: freeze, Objects: objects}
}

func TestArchiveConfiguredCaps(t *testing.T) {
	f := newFreshArch(t)
	snapshot := manySnapshot(t, f, 4097)
	f.native.freeze, f.native.objects = snapshot.Freeze, snapshot.Objects
	f.record.Limits = ArchiveLimits{SnapshotObjects: 8192, CollectionObjects: 32768}
	archSave(t, f.s, f.record)
	if _, err := f.s.sealArchive(context.Background(), f.record); err != nil {
		t.Fatal("installation budget could not archive a normal dependency-sized snapshot", err)
	}
	g := newFreshArch(t)
	g.record.Limits = ArchiveLimits{SnapshotObjects: 4096, CollectionObjects: 4096}
	// Bind the refused input to this job so only the configured cap decides.
	snapshot.Freeze.Target, snapshot.Freeze.LaunchID, snapshot.Freeze.CancellationEpoch = g.record.Job.Intent.Request.Target, g.record.Lane.LaunchID, g.record.Job.Intent.CancellationEpoch
	if err := validateArchiveFreeze(g.record, snapshot, time.Now()); err == nil {
		t.Fatal("configured snapshot object refusal was bypassed")
	} else {
		expectCode(t, err, api.CodeBudget)
	}
}

func TestArchiveBudgetDeadline(t *testing.T) {
	f := newArch(t)
	now := time.Now()
	budget := f.record.Job.Plan.Budget
	budget.WallMS = 5 * 60 * 1000
	end, err := archiveDeadline(now, budget, ArchiveLimits{})
	if err != nil || end.Sub(now) < 6*time.Minute {
		t.Fatal("archive lease still imposed the old sixty-second cap", err)
	}
	r := f.record
	r.Job.Lease.ExpiresAt = api.Timestamp(end.UTC().Format(timeFormat))
	archSave(t, f.s, r)
	deadline, err := f.s.OwnedEffectDeadline(context.Background(), f.executor, r.Job.Lease.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := time.Parse(time.RFC3339Nano, string(deadline))
	if err != nil || actual.Before(end) {
		t.Fatal("archive claim still imposed the old thirty-second cap", err)
	}
	budget.WallMS = 1<<63 - 1
	if _, err := archiveDeadline(now, budget, ArchiveLimits{}); err == nil {
		t.Fatal("non-finite archive deadline budget was accepted")
	} else {
		expectCode(t, err, api.CodeBudget)
	}
}

func TestArchiveLimitFloors(t *testing.T) {
	for _, limits := range []ArchiveLimits{{SnapshotObjects: 4095}, {CollectionObjects: 4095}, {PreparationMS: 59999}} {
		if err := limits.validate(); err == nil {
			t.Fatal("installation limits weakened an existing safety floor")
		}
	}
	if err := (ArchiveLimits{SnapshotObjects: 4096, CollectionObjects: 8192, PreparationMS: 60000}).validate(); err != nil {
		t.Fatal("valid installation limit configuration refused", err)
	}
}

func TestCollectConfiguredCap(t *testing.T) {
	f := newCollect(t)
	f.arch.s.deps.ArchiveLimits.CollectionObjects = 4096
	tx, err := f.arch.s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4097; i++ {
		if _, err := f.arch.s.archiveBytes(context.Background(), tx, f.arch.record, "artifact", []byte(fmt.Sprintf("owned transient %d", i))); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.arch.s.collectionGraph(context.Background(), f.job, nil); err == nil {
		t.Fatal("configured collection object budget was bypassed")
	} else {
		expectCode(t, err, api.CodeBudget)
	}
	f.arch.s.deps.ArchiveLimits.CollectionObjects = 16384
	objects, _, _, err := f.arch.s.collectionGraph(context.Background(), f.job, nil)
	if err != nil || len(objects) < 4097 {
		t.Fatal("installation collection budget still imposed the old constant cap", err)
	}
}
