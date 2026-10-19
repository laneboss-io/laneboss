//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type workspaceResolutionControl struct {
	CleanupNative
	edit  func(*api.CleanupWorkspace)
	calls int
}

func (n *workspaceResolutionControl) ResolveCleanupWorkspace(ctx context.Context, target api.LifeRef, id api.ID) (api.CleanupWorkspace, error) {
	n.calls++
	w, err := n.CleanupNative.ResolveCleanupWorkspace(ctx, target, id)
	if err == nil && n.edit != nil {
		n.edit(&w)
	}
	return w, err
}

// The writer, archive verification, original request, clean claim and SQL
// projections are real. Native substitution is a controlled input boundary;
// the corresponding native producer is exercised by the root admin canary.
func TestCleanupWorkspaceResolution(t *testing.T) {
	for _, mode := range []string{"valid", "foreign-workspace", "foreign-target", "branch", "alias", "generation", "identity", "head", "missing-native", "stale-claim"} {
		t.Run(mode, func(t *testing.T) {
			f := newCollect(t)
			ctx := context.Background()
			s := f.arch.s
			if _, err := s.db.ExecContext(ctx, "DELETE FROM projections WHERE kind='collection' AND id=?", string(f.job.Intent.Cause.EffectID)); err != nil {
				t.Fatal(err)
			}
			native := &workspaceResolutionControl{CleanupNative: f.native}
			s.deps.CleanupNative = native
			native.edit = func(w *api.CleanupWorkspace) {
				switch mode {
				case "foreign-workspace":
					w.ID = testID(t)
				case "foreign-target":
					w.Target.Run++
				case "branch":
					w.Branch = "lane/foreign"
				case "alias":
					w.RepositoryID = w.RootID
				case "generation":
					w.Generation = 0
				case "identity":
					w.GitIdentity = w.DirectoryIdentity
				case "head":
					w.Head = "not-a-native-head"
				}
			}
			lease := f.job.Claim
			if mode == "missing-native" {
				s.deps.CleanupNative = nil
			}
			if mode == "stale-claim" {
				lease.ClaimID = testID(t)
			}
			_, err := s.BeginCleanup(ctx, f.arch.executor, lease)
			if mode == "valid" {
				// G1's resolver must reach the independent release-receipt gate.
				// This fixture deliberately supplies no agent release effect.
				if !errors.Is(err, sql.ErrNoRows) || native.calls != 1 {
					t.Fatal("valid protected workspace did not reach the measured release prerequisite", err)
				}
				return
			}
			var typed *api.Error
			want := api.CodeIntegrity
			if mode == "missing-native" {
				want = api.CodeNotImplemented
			}
			if mode == "stale-claim" {
				want = api.CodeConflict
			}
			if !errors.As(err, &typed) || typed.Code != want {
				t.Fatalf("workspace resolution accepted %s or reached a later gate: %v", mode, err)
			}
			if (mode == "missing-native" || mode == "stale-claim") && native.calls != 0 {
				t.Fatal("workspace resolution crossed a missing prerequisite or stale claim")
			}
			var count int
			if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='collection' AND id=?", string(f.job.Intent.Cause.EffectID)).Scan(&count); err != nil || count != 0 {
				t.Fatal("refused native workspace published a cleanup intent", err)
			}
		})
	}
}
