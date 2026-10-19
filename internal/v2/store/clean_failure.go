package store

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type cleanupFailureRead struct {
	intent  api.ID
	remover api.ID
	present bool
}

// Native reads occur outside the SQL lock. The terminal writer rechecks the
// retained journal/remover; the administrator fences deletion by current claim.
func (s *Service) readCleanupFailure(ctx context.Context, scope api.Scope, lease api.EffectLease) (cleanupFailureRead, error) {
	var read cleanupFailureRead
	if lease.Record.Effect.Clean == nil {
		return read, nil
	}
	s.mu.RLock()
	var r collectionRecord
	err := storedProjection(ctx, s.db, "collection", lease.Record.Effect.ID, &r)
	s.mu.RUnlock()
	if absent(err) {
		return read, nil
	}
	if err != nil {
		return read, err
	}
	read.intent = r.Intent.ID
	if r.RemovalClaim == nil {
		return read, nil
	}
	read.remover = r.RemovalClaim.ClaimID
	if r.RemovalJournal != nil && r.RemovalJournal.Action == "remove_clean" {
		return read, nil
	}
	if s.deps.CleanupNative == nil {
		return read, nil
	}
	job := api.CleanupJob{Intent: r.Intent, Claim: lease}
	requested := s.deps.Clock.Now()
	workspace, err := s.deps.CleanupNative.ReadCleanupWorkspace(ctx, job)
	if err != nil {
		return read, &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "cleanup failure awaits an independent current workspace measurement", Instead: "Retain the original cleanup and reconcile native workspace presence before sealing failure."}
	}
	w := r.Intent.Workspace
	at, err := time.Parse(time.RFC3339Nano, string(workspace.ObservedAt))
	read.present = err == nil && !at.IsZero() && !at.Before(requested) && !at.After(s.deps.Clock.Now()) && workspace.WorkspaceID == w.ID &&
		workspace.RootIdentity == w.RootIdentity && workspace.GitIdentity == w.GitIdentity &&
		workspace.WorktreeState == "present" && workspace.BranchState == "present" && workspace.Dirty != nil
	if journal, err := s.deps.CleanupNative.ReadWorkspaceRemoval(ctx, job); err == nil && journal.Action == "remove_clean" {
		read.present = false
	}
	return read, nil
}
