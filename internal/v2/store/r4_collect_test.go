//go:build linux

package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCollectPassBounded(t *testing.T) {
	f := newCollect(t)
	receipt := f.collect(t)
	var reads atomic.Int64
	countCollectionReads(t, f.arch.s, &reads)
	ctx := context.Background()
	source := f.arch.s.CleanupReadbacks(f.arch.executor)
	if _, err := api.VerifyCleanup(ctx, source, f.job, f.inventory, receipt, f.arch.s.deps.Clock); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("verification repeatedly decoded its complete collection record: reads=%d", got)
	}
	foreign := f.inventory.Objects[0]
	foreign.Ref.ID = testID(t)
	if _, err := source.ReadCleanupObject(ctx, f.job, foreign); err == nil {
		t.Fatal("verification cache authorized a foreign inventory member")
	} else {
		expectCode(t, err, api.CodeForbidden)
	}
	written := make(chan error, 1)
	go func() {
		s := f.arch.s
		s.mu.Lock()
		defer s.mu.Unlock()
		var record collectionRecord
		err := storedProjection(context.Background(), s.db, "collection", f.job.Intent.Cause.EffectID, &record)
		if err == nil {
			var txErr error
			tx, beginErr := s.db.BeginTx(context.Background(), nil)
			if beginErr != nil {
				err = beginErr
			} else {
				txErr = s.saveCollection(context.Background(), tx, record)
				if txErr == nil {
					txErr = tx.Commit()
				} else if rollback := tx.Rollback(); rollback != nil {
					txErr = rollback
				}
				err = txErr
			}
		}
		written <- err
	}()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if _, err := source.ReadCleanupObjectResult(ctx, f.job, f.scratch.ID); err == nil {
		t.Fatal("verification cache survived a concurrent writer generation change")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
}

// Only the test binary wraps SQLite's actual query boundary. Product queries,
// decoding, locks and generation checks execute unchanged, with no context hook.
type collectionCountConnector struct {
	driver driver.Driver
	dsn    string
	reads  *atomic.Int64
}

func (c collectionCountConnector) Driver() driver.Driver { return c.driver }
func (c collectionCountConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	query, ok := conn.(driver.QueryerContext)
	if !ok {
		closeErr := conn.Close()
		return nil, fmt.Errorf("SQLite has no context query boundary: %v", closeErr)
	}
	return collectionCountConn{Conn: conn, query: query, reads: c.reads}, nil
}

type collectionCountConn struct {
	driver.Conn
	query driver.QueryerContext
	reads *atomic.Int64
}

func (c collectionCountConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.query.QueryContext(ctx, query, args)
	if err == nil && query == "SELECT data FROM projections WHERE kind=? AND id=?" && len(args) == 2 && args[0].Value == "collection" {
		c.reads.Add(1)
	}
	return rows, err
}

func countCollectionReads(t *testing.T, s *Service, reads *atomic.Int64) {
	t.Helper()
	original := s.db
	uri := url.URL{Scheme: "file", Path: filepath.Join(s.deps.Directory, "state.sqlite")}
	db := sql.OpenDB(collectionCountConnector{driver: original.Driver(), dsn: uri.String(), reads: reads})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s.db = db
	t.Cleanup(func() {
		s.db = original
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{"PRAGMA busy_timeout=5000", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			t.Fatal(err)
		}
	}
}

func retainConcurrent(t *testing.T, f *collectFixture) api.BlobRef {
	t.Helper()
	type result struct {
		ref api.BlobRef
		err error
	}
	done := make(chan result, 1)
	go func() {
		s := f.arch.s
		s.mu.Lock()
		defer s.mu.Unlock()
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			done <- result{err: err}
			return
		}
		ref, err := s.archiveBytes(context.Background(), tx, f.arch.record, "artifact", []byte("concurrently retained owned artifact"))
		if err == nil {
			err = tx.Commit()
		} else if rollback := tx.Rollback(); rollback != nil {
			err = rollback
		}
		done <- result{ref: ref, err: err}
	}()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.ref
}

func TestCollectRefreshBeforeJournals(t *testing.T) {
	f := newCollect(t)
	added := retainConcurrent(t, f)
	inventory, err := f.arch.s.CleanupInventory(context.Background(), f.arch.executor, f.job)
	if err != nil || inventory.ID == f.inventory.ID {
		t.Fatal("unstarted cleanup did not refresh its moved ownership graph", err)
	}
	found := false
	for _, object := range inventory.Objects {
		found = found || object.Ref == added
	}
	if !found {
		t.Fatal("refreshed inventory omitted the actual concurrent owned bytes")
	}
	if _, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory); err == nil {
		t.Fatal("collector used the superseded inventory after refresh")
	}
	f.inventory = inventory
	f.collect(t)
}

func TestCollectMovedGraphFails(t *testing.T) {
	f := newCollect(t)
	ctx := context.Background()
	if _, err := f.arch.s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory); err != nil {
		t.Fatal(err)
	}
	added := retainConcurrent(t, f)
	if _, err := f.arch.s.CleanupInventory(ctx, f.arch.executor, f.job); err == nil {
		t.Fatal("journaled cleanup silently replaced its original inventory")
	} else {
		expectCode(t, err, api.CodePrerequisite)
	}
	failure, err := f.arch.s.OwnedFenceFailure(ctx, f.arch.executor, f.job.Claim)
	if err != nil || failure == nil || failure.Code != api.CodePrerequisite {
		t.Fatal("permanent cleanup fence remained an endless retry", err)
	}
	commit, err := callOwnedFailure(f.arch.s, ctx, f.arch.executor, f.job.Claim, failure, nil)
	if err != nil || commit.Operation.Status != "failed" {
		t.Fatal("pre-removal moved graph could not fail its original cleanup", err)
	}
	if _, _, err := objectRow(ctx, f.arch.s.db, added.ID); err != nil {
		t.Fatal("failed original cleanup deleted the newly owned artifact", err)
	}
}

func TestCleanDirtyCanFail(t *testing.T) {
	f := newCollect(t)
	ctx := context.Background()
	if _, err := f.arch.s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory); err != nil {
		t.Fatal(err)
	}
	f.native.dirty = true
	failure := &api.Error{Code: api.CodeInvalid, Message: "workspace became dirty before removal", Instead: "Preserve the dirty workspace and request a fresh cleanup after review."}
	commit, err := callOwnedFailure(f.arch.s, ctx, f.arch.executor, f.job.Claim, failure, nil)
	if err != nil || commit.Operation.Status != "failed" || commit.Operation.Error == nil || commit.Operation.Error.Message != failure.Message {
		t.Fatal("pre-removal dirty cleanup remained immortal", err)
	}
	if f.native.removed {
		t.Fatal("dirty cleanup removed the workspace")
	}
}

func TestCleanDirtyRetentionCanFail(t *testing.T) {
	f := newCollect(t)
	f.native.dirty = true
	ctx := context.Background()
	if _, err := f.arch.s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory); err != nil {
		t.Fatal("dirty collection stopped before the native retention decision", err)
	}
	failure := &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-admin",
		Message: "cleanup retained dirty work (retain_dirty)",
		Instead: "Merge or discard the uncommitted work (unmerged commits on an abandoned branch are retained), then clean the lane again."}
	commit, err := callOwnedFailure(f.arch.s, ctx, f.arch.executor, f.job.Claim, failure, nil)
	if err != nil || commit.Operation.Status != "failed" || commit.Operation.Error == nil ||
		commit.Operation.Error.Message != failure.Message {
		t.Fatal("dirty retention could not seal its measured cleanup refusal", err)
	}
	var lane api.Lane
	if err := storedProjection(ctx, f.arch.s.db, "lane", f.job.Intent.Cause.Target.LifeID, &lane); err != nil || lane.Cleaned {
		t.Fatal("dirty retention failure was counted as cleaned", err)
	}
}
