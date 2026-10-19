package admin

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Protected-record component fixtures, never native removal observations.
func cleanupClaimFixture(t *testing.T) (api.CleanupJob, api.CleanupJob, cleanupJournal) {
	t.Helper()
	now := time.Now().UTC()
	stamp := func(d time.Duration) api.Timestamp { return api.Timestamp(now.Add(d).Format(time.RFC3339Nano)) }
	zero, exit, clean := uint64(0), 0, false
	target := api.LifeRef{LifeID: "clean-life", Run: 1}
	cause := testCause(api.InternalLifecycleEffect, target.LifeID)
	cause.Config = "admin-case"
	cause.Target = target
	cause.EffectID = "clean-effect"
	cause.CauseOperationID = "clean-operation"
	cause.CauseRequestID = "clean-request"
	ref := api.BlobRef{ID: "archive-manifest", Class: "manifest", Bytes: 7, SHA256: testDigest("fixture")}
	archive := api.ArchiveReceipt{ID: "archive-receipt", LifeID: target.LifeID, Manifest: ref, ArchiveSHA256: testDigest("archive"), ReadBackSHA256: testDigest("archive"), StoreID: "archive-store", VerifiedAt: stamp(-time.Minute)}
	release := api.ReleaseReceipt{ID: "release", LeaseID: "agent-lease", ContainmentID: "agent-cg", Backend: "linux-bwrap-landlock", OperationID: "release-operation", EffectID: "release-effect", LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: stamp(-70 * time.Second), Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{ID: "agent-process", Target: target, ContainmentID: "agent-cg", Generation: "original-generation"}, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "completed", ObservedAt: stamp(-70 * time.Second)}}
	w := api.CleanupWorkspace{ID: "workspace", RootID: "root", RepositoryID: "repository", Target: target, Generation: 1, RootIdentity: "root-inode", DirectoryIdentity: "directory-inode", GitIdentity: "git-inode", Branch: "lane/clean-life", Head: strings.Repeat("a", 40)}
	intent := api.CleanupIntent{ID: "clean-intent", Cause: cause, ExpectedGeneration: 7, Decision: "abandoned", Archive: archive, ArchiveRequest: api.ArchiveRequest{Target: target, ExpectedGeneration: 7}, Release: release, Workspace: w}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Clean: &api.CleanRequest{Target: target, ExpectedGeneration: 7, ArchiveReceiptID: archive.ID}}
	original := api.CleanupJob{Intent: intent, Claim: api.EffectLease{ClaimID: "original-claim", ExpiresAt: stamp(-30 * time.Second), Record: api.EffectRecord{Effect: effect, Generation: 2, State: api.EffectClaimed, ClaimID: "original-claim", ClaimantID: "original-service", ClaimExpiresAt: stamp(-30 * time.Second)}}}
	current := original
	current.Claim.ClaimID = "successor-claim"
	current.Claim.Record.ClaimID = current.Claim.ClaimID
	current.Claim.Record.ClaimantID = "successor-service"
	current.Claim.Record.Generation++
	current.Claim.ExpiresAt = stamp(2 * time.Minute)
	current.Claim.Record.ClaimExpiresAt = current.Claim.ExpiresAt
	before := api.WorkspaceReadback{ID: "before", WorkspaceID: w.ID, RootIdentity: w.RootIdentity, DirectoryIdentity: w.DirectoryIdentity, GitIdentity: w.GitIdentity, WorktreeState: "present", BranchState: "present", Head: w.Head, Dirty: &clean, ObservedAt: stamp(-50 * time.Second)}
	after := api.WorkspaceReadback{ID: "after", WorkspaceID: w.ID, RootIdentity: w.RootIdentity, GitIdentity: w.GitIdentity, WorktreeState: "absent", BranchState: "absent", ObservedAt: stamp(-40 * time.Second)}
	removal := api.WorkspaceRemoval{IntentID: intent.ID, ClaimID: original.Claim.ClaimID, Action: "remove_clean", Before: before, After: after, Unforced: true, Synced: true}
	j := cleanupJournal{Job: original, Phase: "complete", Before: before, Removal: &removal}
	if err := api.ValidateCleanupJob(current, now); err != nil {
		t.Fatal(err)
	}
	return original, current, j
}

func TestCleanupSuccessor(t *testing.T) {
	for _, fault := range []string{"intent", "effect", "generation", "expired", "journal-claim"} {
		t.Run(fault, func(t *testing.T) {
			_, current, j := cleanupClaimFixture(t)
			original := *j.Removal
			if err := validateCleanupRemovalJournal(&j, current, time.Now()); err != nil {
				t.Fatalf("acceptance: same-effect successor could not read original removal: %v", err)
			}
			if !reflect.DeepEqual(original, *j.Removal) || j.Removal.ClaimID == current.Claim.ClaimID {
				t.Fatal("acceptance: successor relabeled the original native removal claim")
			}
			switch fault {
			case "intent":
				current.Intent.ID = "another-intent"
			case "effect":
				current.Intent.Cause.EffectID = "another-effect"
				current.Claim.Record.Effect.ID = "another-effect"
				cause := current.Intent.Cause
				current.Claim.Record.Effect.Context = &cause
			case "generation":
				current.Claim.Record.Generation = j.Job.Claim.Record.Generation
			case "expired":
				current.Claim.ExpiresAt = j.Job.Claim.ExpiresAt
				current.Claim.Record.ClaimExpiresAt = current.Claim.ExpiresAt
			case "journal-claim":
				j.Removal.ClaimID = current.Claim.ClaimID
				if err := originalCleanupClaim(&j); err == nil {
					t.Fatal("acceptance: cleanup accepted a foreign or unproven successor journal")
				}
			}
			if err := validateCleanupRemovalJournal(&j, current, time.Now()); err == nil {
				t.Fatal("acceptance: cleanup accepted a foreign or unproven successor journal")
			}
		})
	}
}

func successorCleanupJob(current api.CleanupJob) api.CleanupJob {
	cause := current.Intent.Cause
	cause.ID, cause.CauseOperationID, cause.CauseRequestID, cause.EffectID = "successor-cause", "successor-operation", "successor-request", "successor-effect"
	intent := current.Intent
	intent.ID, intent.Cause = "successor-intent", cause
	effect := current.Claim.Record.Effect
	effect.ID, effect.OperationID, effect.Context = cause.EffectID, cause.CauseOperationID, &cause
	effect.Clean = &api.CleanRequest{Target: cause.Target, ExpectedGeneration: intent.ExpectedGeneration, ArchiveReceiptID: intent.Archive.ID}
	claim := current.Claim
	claim.Record.Effect = effect
	return api.CleanupJob{Intent: intent, Claim: claim}
}

func TestCleanupRetainedDirtySuccessor(t *testing.T) {
	original, current, journal := cleanupClaimFixture(t)
	now := time.Now()
	dirty := true
	before := journal.Removal.Before
	before.Dirty = &dirty
	after := before
	after.ID = "dirty-after"
	after.ObservedAt = api.Timestamp(now.Add(-time.Second).Format(time.RFC3339Nano))
	removal := *journal.Removal
	removal.Action, removal.Before, removal.After = "retain_dirty", before, after
	journal.Before, journal.Removal = before, &removal
	journal.Phase = "complete"
	expires := api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))
	journal.Job.Claim.ExpiresAt, journal.Job.Claim.Record.ClaimExpiresAt = expires, expires
	successor := successorCleanupJob(current)
	fresh := after
	clean := false
	fresh.ID, fresh.Dirty = "fresh-clean", &clean
	fresh.ObservedAt = api.Timestamp(now.Format(time.RFC3339Nano))
	if err := validateCleanupSuccessorOrRetainedDirty(&journal, successor, &fresh, now); err != nil {
		t.Fatalf("discarded dirty successor was refused: %v", err)
	}
	moved := fresh
	moved.Head = strings.Repeat("b", 40)
	movedSuccessor := successorCleanupJob(current)
	movedSuccessor.Intent.Workspace.Head = moved.Head
	if err := validateCleanupSuccessorOrRetainedDirty(&journal, movedSuccessor, &moved, now); err != nil {
		t.Fatalf("committed and merged successor was refused: %v", err)
	}
	for _, mutate := range []func(*api.WorkspaceReadback){
		func(read *api.WorkspaceReadback) { read.DirectoryIdentity += "-changed" },
		func(read *api.WorkspaceReadback) { read.GitIdentity += "-changed" },
		func(read *api.WorkspaceReadback) { read.WorktreeState = "absent" },
	} {
		bad := fresh
		mutate(&bad)
		if err := validateCleanupSuccessorOrRetainedDirty(&journal, successor, &bad, now); err == nil {
			t.Fatal("retain_dirty successor accepted a changed workspace identity")
		}
	}

	cleanJournal := cleanupJournal{Job: original, Phase: "complete", Before: journal.Before}
	cleanJournal.Removal = &api.WorkspaceRemoval{IntentID: original.Intent.ID, ClaimID: original.Claim.ClaimID,
		Action: "remove_clean", Before: journal.Before, After: api.WorkspaceReadback{ID: "clean-after",
			WorkspaceID: journal.Before.WorkspaceID, RootIdentity: journal.Before.RootIdentity,
			GitIdentity: journal.Before.GitIdentity, WorktreeState: "absent", BranchState: "absent",
			ObservedAt: fresh.ObservedAt}, Unforced: true, Synced: true}
	if err := validateCleanupSuccessorOrRetainedDirty(&cleanJournal, successor, nil, now); err == nil {
		t.Fatal("remove_clean journal accepted a different intent")
	}

	retained := cleanJournal
	retained.Phase, retained.Removal = "retained_unmerged", nil
	retained.Retained = &after
	retained.Refusal = cleanupUnmergedRefusal(original.Intent.Cause.CauseOperationID)
	retained.Reason, retained.BranchTip, retained.CommonHead = "branch_not_merged", before.Head, strings.Repeat("b", 40)
	if err := validateCleanupSuccessorOrRetainedDirty(&retained, successor, nil, now); err == nil {
		t.Fatal("retained_unmerged journal accepted a different intent")
	}
}

func TestCleanupHistoryBound(t *testing.T) {
	journal := cleanupJournal{History: make([]cleanupJournal, 16)}
	err := validateCleanupHistory(&journal)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Message != "cleanup journal history exceeds its bounded retention" {
		t.Fatal("cleanup history accepted more than its bounded retention")
	}
}

func TestCleanupHistoryMergedHead(t *testing.T) {
	_, current, journal := cleanupClaimFixture(t)
	now := time.Now()
	dirty := true
	before := journal.Removal.Before
	before.Dirty = &dirty
	after := before
	after.ID = "dirty-after"
	after.ObservedAt = api.Timestamp(now.Add(-time.Second).Format(time.RFC3339Nano))
	removal := *journal.Removal
	removal.Action, removal.Before, removal.After = "retain_dirty", before, after
	journal.Before, journal.Removal, journal.Phase = before, &removal, "complete"
	expires := api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))
	journal.Job.Claim.ExpiresAt, journal.Job.Claim.Record.ClaimExpiresAt = expires, expires
	moved := after
	moved.Head = strings.Repeat("b", 40)
	successor := successorCleanupJob(current)
	successor.Intent.Workspace.Head = moved.Head
	history := cleanupJournal{Job: successor, Phase: "decided", Before: moved, History: []cleanupJournal{journal}}
	if err := validateCleanupHistory(&history); err != nil {
		t.Fatalf("merged successor history was refused: %v", err)
	}
}

type cleanupFixturePorts interface {
	api.StateStore
	api.CleanupObjectStore
}
type cleanupClaimStore struct {
	cleanupFixturePorts
	live api.CleanupJob
}

func (s *cleanupClaimStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if err := ctx.Err(); err != nil {
		return api.EffectRecord{}, err
	}
	if scope.Config != s.live.Intent.Cause.Config || scope.Actor.Kind != "service" || scope.Actor.ID != s.live.Claim.Record.ClaimantID || id != s.live.Intent.Cause.EffectID {
		return api.EffectRecord{}, failure(api.CodeForbidden, "fixture current claim lookup is foreign")
	}
	return s.live.Claim.Record, nil
}
func (s *cleanupClaimStore) BeginCleanup(ctx context.Context, scope api.Scope, claim api.EffectLease) (api.CleanupJob, error) {
	actual, err := s.Effect(ctx, scope, claim.Record.Effect.ID)
	if err != nil {
		return api.CleanupJob{}, err
	}
	if !reflect.DeepEqual(actual, claim.Record) || claim.ClaimID != actual.ClaimID || claim.ExpiresAt != actual.ClaimExpiresAt {
		return api.CleanupJob{}, failure(api.CodeConflict, "fixture retained cleanup does not own its live claim")
	}
	job := api.CleanupJob{Intent: s.live.Intent, Claim: claim}
	return job, api.ValidateCleanupJob(job, time.Now())
}

func TestCleanupLive(t *testing.T) {
	_, current, _ := cleanupClaimFixture(t)
	store := &cleanupClaimStore{live: current}
	s := &Service{deps: Dependencies{Store: store, Config: current.Intent.Cause.Config}}
	if err := s.cleanupAuthority(context.Background(), current); err != nil {
		t.Fatalf("acceptance: actual successor claimant was refused: %v", err)
	}
	store.live.Claim.ClaimID = "next-current-claim"
	store.live.Claim.Record.ClaimID = store.live.Claim.ClaimID
	store.live.Claim.Record.Generation++
	if err := s.cleanupAuthority(context.Background(), current); err == nil {
		t.Fatal("acceptance: nominal successor bypassed the live current claim")
	}
}
