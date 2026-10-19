package admin

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type cleanupJournal struct {
	Job                           api.CleanupJob
	Phase                         string
	Before                        api.WorkspaceReadback
	Removal                       *api.WorkspaceRemoval  `json:",omitempty"`
	Retained                      *api.WorkspaceReadback `json:",omitempty"`
	Refusal                       *api.Error             `json:",omitempty"`
	History                       []cleanupJournal       `json:",omitempty"`
	Reason, BranchTip, CommonHead string
}

type cleanupQuery struct {
	Target      api.LifeRef
	WorkspaceID api.ID
	Job         api.CleanupJob        `json:",omitempty,omitzero"`
	Before      api.WorkspaceReadback `json:",omitempty,omitzero"`
}

var _ api.WorkspaceCollector = (*Service)(nil)

// Terminal workspace retention releases identities only after the independent
// native worker collector has proved quiescence and durably collected it.
func cleanupReleasesUIDs(r leaseRecord) bool {
	return r.Cleanup != nil && (r.Cleanup.Phase == "complete" || r.Cleanup.Phase == "retained_unmerged") &&
		r.Archive != nil && r.Archive.Worker != nil && r.Archive.Worker.Collected
}

func validateCleanupRecord(r leaseRecord) error {
	j := r.Cleanup
	if j == nil {
		return nil
	}
	if r.Storage == nil || !r.Storage.Withdrawn || j.Job.Intent.Workspace.ID != r.Storage.Binding.WorkspaceID || j.Job.Intent.Cause.Target.LifeID != r.Request.LifeID || !validID(j.Before.ID) || j.Before.WorkspaceID != j.Job.Intent.Workspace.ID {
		return failure(api.CodeIntegrity, "cleanup journal changed its protected native owner")
	}
	if err := validateCleanupHistory(j); err != nil {
		return err
	}
	switch j.Phase {
	case "decided", "retaining_dirty", "removing", "worktree_removed", "complete", "retained_unmerged":
	default:
		return failure(api.CodeIntegrity, "cleanup journal has an unknown native operation phase")
	}
	when, err := time.Parse(time.RFC3339Nano, string(j.Before.ObservedAt))
	if err != nil || when.After(time.Now()) {
		return failure(api.CodeIntegrity, "cleanup journal lost its actual decision time")
	}
	if j.Phase == "retained_unmerged" {
		if j.Retained == nil {
			return failure(api.CodeIntegrity, "cleanup retained state has no native after observation")
		}
		when, err = time.Parse(time.RFC3339Nano, string(j.Retained.ObservedAt))
		if err != nil || when.After(time.Now()) {
			return failure(api.CodeIntegrity, "cleanup retained time is invalid or in the future")
		}
		return validateCleanupRetention(j, when)
	}
	if j.Refusal != nil || j.Retained != nil || j.Reason != "" || j.BranchTip != "" || j.CommonHead != "" {
		return failure(api.CodeIntegrity, "cleanup journal has a competing retained outcome")
	}
	if j.Removal != nil {
		when, err = time.Parse(time.RFC3339Nano, string(j.Removal.After.ObservedAt))
		if err != nil || when.After(time.Now()) || j.Phase != "complete" || !reflect.DeepEqual(j.Before, j.Removal.Before) {
			return failure(api.CodeIntegrity, "cleanup journal changed its original native before observation")
		}
		if err := originalCleanupClaim(j); err != nil {
			return err
		}
		return api.ValidateWorkspaceRemoval(j.Job, *j.Removal, when)
	}
	if j.Phase == "complete" {
		return failure(api.CodeIntegrity, "completed cleanup has no durable removal journal")
	}
	return api.ValidateCleanupJob(j.Job, when)
}

func validateCleanupHistory(j *cleanupJournal) error {
	if len(j.History) > 15 {
		return failure(api.CodeIntegrity, "cleanup journal history exceeds its bounded retention")
	}
	for _, old := range j.History {
		oldWorkspace, currentWorkspace := old.Job.Intent.Workspace, j.Job.Intent.Workspace
		oldWorkspace.Head, currentWorkspace.Head = "", ""
		if len(old.History) != 0 || old.Phase != "complete" || old.Removal == nil || old.Removal.Action != "retain_dirty" ||
			oldWorkspace != currentWorkspace || old.Removal.IntentID != old.Job.Intent.ID ||
			old.Removal.ClaimID != old.Job.Claim.ClaimID || !old.Removal.Unforced || !old.Removal.Synced ||
			old.Refusal != nil || old.Retained != nil || old.Reason != "" || old.BranchTip != "" || old.CommonHead != "" ||
			!reflect.DeepEqual(old.Before, old.Removal.Before) ||
			!sameWorkspaceObservation(old.Removal.Before, old.Removal.After) {
			return failure(api.CodeIntegrity, "cleanup journal history changed its retained dirty decision")
		}
		when, err := time.Parse(time.RFC3339Nano, string(old.Removal.After.ObservedAt))
		if err != nil || when.After(time.Now()) {
			return failure(api.CodeIntegrity, "cleanup journal history has an invalid retained time")
		}
		if err := api.ValidateWorkspaceRemoval(old.Job, *old.Removal, when); err != nil {
			return err
		}
	}
	return nil
}

func cleanupHistoryForSuccessor(j *cleanupJournal) []cleanupJournal {
	if j == nil {
		return nil
	}
	history := append([]cleanupJournal{}, j.History...)
	if j.Removal != nil && j.Removal.Action == "retain_dirty" {
		if len(history) >= 15 {
			history = history[len(history)-14:]
		}
		previous := *j
		previous.History = nil
		history = append(history, previous)
	}
	return history
}

func sameWorkspaceObservation(a, b api.WorkspaceReadback) bool {
	a.ID, b.ID = "", ""
	a.ObservedAt, b.ObservedAt = "", ""
	return reflect.DeepEqual(a, b)
}

func sameRetainedWorkspace(a, b api.WorkspaceReadback) bool {
	if a.WorkspaceID != b.WorkspaceID || a.RootIdentity != b.RootIdentity ||
		a.DirectoryIdentity != b.DirectoryIdentity || a.GitIdentity != b.GitIdentity ||
		a.WorktreeState != "present" || a.BranchState != "present" ||
		b.WorktreeState != "present" || b.BranchState != "present" ||
		a.Dirty == nil || b.Dirty == nil {
		return false
	}
	a.Head, b.Head, a.Dirty, b.Dirty = "", "", nil, nil
	return sameWorkspaceObservation(a, b)
}

func validateCleanupRetention(j *cleanupJournal, now time.Time) error {
	if err := api.ValidateCleanupJob(j.Job, now); err != nil {
		return err
	}
	w := j.Job.Intent.Workspace
	if j.Phase != "retained_unmerged" || j.Removal != nil || j.Refusal == nil || j.Retained == nil || j.Reason != "branch_not_merged" || j.BranchTip != w.Head || !cleanupGitHead(j.CommonHead) ||
		j.Refusal.Code != CodeCleanupUnmerged || j.Refusal.Owner != owner || j.Refusal.Retryable || j.Refusal.OperationID != j.Job.Intent.Cause.CauseOperationID ||
		j.Before.WorkspaceID != w.ID || j.Before.RootIdentity != w.RootIdentity || j.Before.DirectoryIdentity != w.DirectoryIdentity || j.Before.GitIdentity != w.GitIdentity || j.Before.Head != w.Head ||
		j.Before.WorktreeState != "present" || j.Before.BranchState != "present" || j.Before.Dirty == nil || !sameWorkspaceObservation(j.Before, *j.Retained) || j.Before.ID == j.Retained.ID || !validID(j.Retained.ID) {
		return failure(api.CodeIntegrity, "cleanup retained outcome lost its original reason or kept namespaces")
	}
	before, be := time.Parse(time.RFC3339Nano, string(j.Before.ObservedAt))
	after, ae := time.Parse(time.RFC3339Nano, string(j.Retained.ObservedAt))
	if be != nil || ae != nil || after.Before(before) || after.After(now) {
		return failure(api.CodeIntegrity, "cleanup retained outcome lost its measured time order")
	}
	return nil
}

func cleanupGitHead(head string) bool {
	if len(head) != 40 && len(head) != 64 {
		return false
	}
	for _, c := range head {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

// A current claim is authenticated separately by cleanupAuthority. Joining it
// to this protected journal never edits the job or claim that did the work.
func validateCleanupSuccessor(j *cleanupJournal, current api.CleanupJob, now time.Time) error {
	if err := api.ValidateCleanupJob(current, now); err != nil {
		return err
	}
	if j == nil || !reflect.DeepEqual(j.Job.Intent, current.Intent) || !reflect.DeepEqual(j.Job.Claim.Record.Effect, current.Claim.Record.Effect) {
		return failure(api.CodeConflict, "cleanup successor changed the original intent or effect")
	}
	old, next := j.Job.Claim, current.Claim
	if old.ClaimID == next.ClaimID {
		if !reflect.DeepEqual(old, next) {
			return failure(api.CodeConflict, "cleanup original claim changed its sealed record")
		}
	} else if next.Record.Generation <= old.Record.Generation {
		return failure(api.CodeConflict, "cleanup successor did not advance the original claim generation")
	}
	return nil
}

func validateCleanupSuccessorOrRetainedDirty(j *cleanupJournal, current api.CleanupJob, fresh *api.WorkspaceReadback, now time.Time) error {
	if j != nil && j.Phase == "complete" && j.Removal != nil && j.Removal.Action == "retain_dirty" {
		if err := api.ValidateCleanupJob(current, now); err != nil {
			return err
		}
		currentWorkspace, oldWorkspace := current.Intent.Workspace, j.Job.Intent.Workspace
		currentWorkspace.Head, oldWorkspace.Head = "", ""
		if currentWorkspace != oldWorkspace || fresh == nil || !sameRetainedWorkspace(*fresh, j.Removal.After) {
			return failure(api.CodeIntegrity, "retained dirty cleanup changed its kept namespaces")
		}
		return nil
	}
	return validateCleanupSuccessor(j, current, now)
}

func validateCleanupRemovalJournal(j *cleanupJournal, current api.CleanupJob, now time.Time) error {
	if err := validateCleanupSuccessor(j, current, now); err != nil {
		return err
	}
	if j.Phase != "complete" || j.Removal == nil || j.Refusal != nil || !reflect.DeepEqual(j.Before, j.Removal.Before) {
		return failure(api.CodeIntegrity, "cleanup has no original completed removal journal")
	}
	if err := originalCleanupClaim(j); err != nil {
		return err
	}
	when, err := time.Parse(time.RFC3339Nano, string(j.Removal.After.ObservedAt))
	if err != nil || when.After(now) {
		return failure(api.CodeIntegrity, "cleanup original removal time is invalid")
	}
	// Historical authority is checked at the measured operation time. Current
	// authority was checked above; an expired original claim is not revived.
	return api.ValidateWorkspaceRemoval(j.Job, *j.Removal, when)
}

func originalCleanupClaim(j *cleanupJournal) error {
	if j.Removal == nil || j.Removal.ClaimID != j.Job.Claim.ClaimID {
		return failure(api.CodeIntegrity, "cleanup removal differs from the claim in its original native journal")
	}
	return nil
}

// Resolve and readback are installed writer callbacks. They must not call
// back into a writer that is already holding its own transaction fence.
func (s *Service) ResolveCleanupWorkspace(ctx context.Context, target api.LifeRef, id api.ID) (api.CleanupWorkspace, error) {
	var result api.CleanupWorkspace
	if !validID(id) || !validID(target.LifeID) || target.Run == 0 {
		return result, failure(api.CodeInvalid, "invalid protected workspace selector")
	}
	err := s.call(ctx, "cleanup_resolve", cleanupQuery{Target: target, WorkspaceID: id}, &result)
	return result, err
}

func (s *Service) cleanupAuthority(ctx context.Context, job api.CleanupJob) error {
	if err := api.ValidateCleanupJob(job, time.Now()); err != nil {
		return err
	}
	store, ok := s.deps.Store.(api.CleanupObjectStore)
	if !ok {
		return api.NotImplemented("lb-v2-service", "retained cleanup authority")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: job.Claim.Record.ClaimantID}, Source: "service"}
	current, err := s.deps.Store.Effect(ctx, scope, job.Intent.Cause.EffectID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, job.Claim.Record) {
		return failure(api.CodeConflict, "cleanup requires the actual live current claim")
	}
	actual, err := store.BeginCleanup(ctx, scope, job.Claim)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, job) {
		return failure(api.CodeConflict, "cleanup changed its original intent or current effect claim")
	}
	return nil
}

func (s *Service) InspectCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	if err := s.cleanupAuthority(ctx, job); err != nil {
		return api.WorkspaceReadback{}, err
	}
	return s.ReadCleanupWorkspace(ctx, job)
}

func (s *Service) ReadCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	var result api.WorkspaceReadback
	if err := s.cleanupAuthority(ctx, job); err != nil {
		return result, err
	}
	err := s.call(ctx, "cleanup_read", cleanupQuery{Job: job}, &result)
	return result, err
}

func (s *Service) RemoveCleanupWorkspace(ctx context.Context, job api.CleanupJob, before api.WorkspaceReadback) (api.WorkspaceRemoval, error) {
	if err := s.cleanupAuthority(ctx, job); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	var result api.WorkspaceRemoval
	if err := s.call(ctx, "cleanup_remove", cleanupQuery{Job: job, Before: before}, &result); err != nil {
		return result, err
	}
	if err := s.cleanupAuthority(ctx, job); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	original, err := s.ReadWorkspaceRemoval(ctx, job)
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if !reflect.DeepEqual(original, result) {
		return api.WorkspaceRemoval{}, failure(api.CodeIntegrity, "cleanup replay changed its authenticated original journal")
	}
	return result, nil
}

func (s *Service) ReadWorkspaceRemoval(ctx context.Context, job api.CleanupJob) (api.WorkspaceRemoval, error) {
	var journal cleanupJournal
	if err := s.cleanupAuthority(ctx, job); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if err := s.call(ctx, "cleanup_journal", cleanupQuery{Job: job}, &journal); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if journal.Refusal != nil {
		if err := validateCleanupSuccessor(&journal, job, time.Now()); err != nil {
			return api.WorkspaceRemoval{}, err
		}
		if journal.Retained == nil {
			return api.WorkspaceRemoval{}, failure(api.CodeIntegrity, "retained cleanup journal lost its after read")
		}
		at, err := time.Parse(time.RFC3339Nano, string(journal.Retained.ObservedAt))
		if err != nil || at.After(time.Now()) {
			return api.WorkspaceRemoval{}, failure(api.CodeIntegrity, "retained cleanup journal has an invalid measurement time")
		}
		if err := validateCleanupRetention(&journal, at); err != nil {
			return api.WorkspaceRemoval{}, err
		}
		return api.WorkspaceRemoval{}, journal.Refusal
	}
	if err := validateCleanupRemovalJournal(&journal, job, time.Now()); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	return *journal.Removal, nil
}
