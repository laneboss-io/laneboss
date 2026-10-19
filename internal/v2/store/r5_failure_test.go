//go:build linux

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type changedWorkspaceNative struct {
	*collectNative
	change func(*api.WorkspaceReadback)
}

func (n changedWorkspaceNative) ReadCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	read, err := n.collectNative.ReadCleanupWorkspace(ctx, job)
	if err == nil {
		n.change(&read)
	}
	return read, err
}

func TestCleanChangedFail(t *testing.T) {
	for _, row := range []struct {
		name   string
		change func(*api.WorkspaceReadback)
		accept bool
	}{
		{"head", func(r *api.WorkspaceReadback) { r.Head = strings.Repeat("b", 40) }, true},
		{"rename", func(r *api.WorkspaceReadback) { r.DirectoryIdentity = "renamed-original-directory" }, true},
		{"workspace", func(r *api.WorkspaceReadback) { r.WorkspaceID = testID(t) }, false},
		{"root", func(r *api.WorkspaceReadback) { r.RootIdentity = "foreign-root" }, false},
		{"git", func(r *api.WorkspaceReadback) { r.GitIdentity = "foreign-git" }, false},
		{"absent", func(r *api.WorkspaceReadback) { r.WorktreeState, r.BranchState = "absent", "absent" }, false},
		{"unknown", func(r *api.WorkspaceReadback) { r.WorktreeState = "unknown" }, false},
		{"branch", func(r *api.WorkspaceReadback) { r.BranchState = "unknown" }, false},
		{"dirty_unknown", func(r *api.WorkspaceReadback) { r.Dirty = nil }, false},
		{"stale", func(r *api.WorkspaceReadback) {
			r.ObservedAt = api.Timestamp(time.Now().Add(-time.Hour).UTC().Format(timeFormat))
		}, false},
		{"future", func(r *api.WorkspaceReadback) {
			r.ObservedAt = api.Timestamp(time.Now().Add(time.Hour).UTC().Format(timeFormat))
		}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newCollect(t)
			ctx := context.Background()
			if _, err := f.arch.s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory); err != nil {
				t.Fatal(err)
			}
			before := f.native.reads
			f.arch.s.deps.CleanupNative = changedWorkspaceNative{collectNative: f.native, change: row.change}
			failure := &api.Error{Code: api.CodeInvalid, Message: "workspace changed before removal", Instead: "Preserve the measured workspace for review."}
			commit, err := callOwnedFailure(f.arch.s, ctx, f.arch.executor, f.job.Claim, failure, nil)
			current, readErr := f.arch.s.Effect(ctx, f.arch.executor, f.job.Claim.Record.Effect.ID)
			if readErr != nil || f.native.reads <= before || f.native.removed {
				t.Fatal("workspace failure did not preserve an independently measured original workspace", readErr)
			}
			if row.accept {
				if err != nil || commit.Operation.Status != "failed" || commit.Operation.Error == nil || commit.Operation.Error.Message != failure.Message || current.State != api.EffectFailed || current.Outcome == nil {
					t.Fatal("changed present original workspace could not fail terminally", err)
				}
			} else {
				if err == nil || current.Outcome != nil || current.State != api.EffectClaimed {
					t.Fatal("foreign or unmeasured workspace sealed a cleanup failure", err)
				}
				expectCode(t, err, api.CodeConflict)
			}
		})
	}
}

func TestRetirementDiagnostics(t *testing.T) {
	for _, row := range []struct {
		name, message string
		change        func(*archivejob.Retirement)
	}{
		{"timestamp", "retirement timestamp mismatch", func(p *archivejob.Retirement) { p.ObservedAt = "invalid" }},
		{"selector", "retirement selector mismatch", func(p *archivejob.Retirement) { p.JobID = testID(t) }},
		{"allocation", "retirement binding mismatch", func(p *archivejob.Retirement) { p.Allocation.UID++ }},
		{"release_time", "release timestamp mismatch", func(p *archivejob.Retirement) { p.Release.ObservedAt = "invalid" }},
		{"release_selector", "release selector mismatch", func(p *archivejob.Retirement) { p.Release.EffectID = testID(t) }},
		{"launch", "release selector mismatch", func(p *archivejob.Retirement) { p.Release.Quiescence.Handle.ID = testID(t) }},
		{"generation", "release binding mismatch", func(p *archivejob.Retirement) { p.Release.Quiescence.Handle.Generation += ":foreign" }},
		{"backend", "release binding mismatch", func(p *archivejob.Retirement) { p.Release.Backend = "unknown" }},
		{"survivors", "release counter mismatch", func(p *archivejob.Retirement) { one := uint64(1); p.Release.Quiescence.Survivors = &one }},
		{"connections", "release counter mismatch", func(p *archivejob.Retirement) { p.Release.LiveConnections = nil }},
		{"jobs", "release counter mismatch", func(p *archivejob.Retirement) { one := uint64(1); p.Release.QueuedJobs = &one }},
		{"exports", "release counter mismatch", func(p *archivejob.Retirement) { p.Release.WritableExports = nil }},
		{"terminal", "terminal selector mismatch", func(p *archivejob.Retirement) { signal := 9; p.Release.Quiescence.Signal = &signal }},
		{"signal", "terminal selector mismatch", func(p *archivejob.Retirement) {
			signal := 65
			p.Release.Quiescence.Signal, p.Release.Quiescence.ExitCode = &signal, nil
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newArch(t)
			proof := retiredProof(t, f)
			row.change(&proof)
			err := f.s.RecordArchiveRetirement(context.Background(), f.executor, f.record.Claim, proof)
			var failure *api.Error
			if !errors.As(err, &failure) || !strings.Contains(failure.Message, row.message) {
				t.Fatal("retirement mismatch lost its distinct diagnostic", err, row.message)
			}
			state, err := f.s.ArchiveRecovery(context.Background(), f.executor, f.record.Claim)
			if err != nil || state.Retirement != nil {
				t.Fatal("rejected retirement retained native evidence", err)
			}
			if err := f.s.RecordArchiveRetirement(context.Background(), f.executor, f.record.Claim, retiredProof(t, f)); err != nil {
				t.Fatal("diagnostic refusal blocked a corrected measured retirement", err)
			}
		})
	}
}
