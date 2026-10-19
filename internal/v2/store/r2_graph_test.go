//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCollectConcurrentWrites(t *testing.T) {
	f := newCollect(t)
	written := make(chan error, 1)
	go func() {
		// This is an independent lane/heartbeat writer between inventory and
		// collection, using the same serialized store transaction as live writes.
		f.arch.s.mu.Lock()
		tx, err := f.arch.s.db.BeginTx(context.Background(), nil)
		if err != nil {
			f.arch.s.mu.Unlock()
			written <- err
			return
		}
		err = put(context.Background(), tx, "other-lane-heartbeat", "unrelated-life", 1, struct{ Count int }{1})
		if err == nil {
			err = tx.Commit()
		} else {
			if rollback := tx.Rollback(); rollback != nil {
				err = rollback
			}
		}
		f.arch.s.mu.Unlock()
		written <- err
	}()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	receipt := f.collect(t)
	late := make(chan error, 1)
	go func() {
		f.arch.s.mu.Lock()
		defer f.arch.s.mu.Unlock()
		tx, err := f.arch.s.db.BeginTx(context.Background(), nil)
		if err != nil {
			late <- err
			return
		}
		err = put(context.Background(), tx, "other-capture-position", "unrelated-capture", 1, struct{ Offset int }{19})
		if err == nil {
			err = tx.Commit()
		} else {
			if rollback := tx.Rollback(); rollback != nil {
				err = rollback
			}
		}
		late <- err
	}()
	if err := <-late; err != nil {
		t.Fatal(err)
	}
	verified, err := api.VerifyCleanup(context.Background(), f.arch.s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, f.arch.s.deps.Clock)
	if err != nil {
		t.Fatal("unrelated concurrent write invalidated collection", err)
	}
	if _, err := f.arch.s.CompleteCleanup(context.Background(), f.arch.executor, f.job, verified); err != nil {
		t.Fatal("unrelated concurrent write prevented lane.cleaned", err)
	}
	var lane api.Lane
	if err := storedProjection(context.Background(), f.arch.s.db, "lane", f.job.Intent.Cause.Target.LifeID, &lane); err != nil || !lane.Cleaned {
		t.Fatal("concurrent collection did not reach lane.cleaned", err)
	}
}

func TestCollectConcurrentReference(t *testing.T) {
	f := newCollect(t)
	fixtureProjection(t, f.arch.s, "other-lane-reference", testID(t), 1, f.scratch)
	if _, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory); err == nil {
		t.Fatal("new selected-object reference bypassed the subgraph fence")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
	if _, _, err := objectRow(context.Background(), f.arch.s.db, f.scratch.ID); err != nil {
		t.Fatal("referenced owned bytes were removed", err)
	}
}
