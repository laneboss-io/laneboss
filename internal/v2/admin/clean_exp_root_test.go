//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func nativeCleanupJob(t *testing.T, e cleanupEnrollment) api.CleanupJob {
	t.Helper()
	job, live, _ := cleanupClaimFixture(t)
	// The original claimant is live when collection begins. Expiry cases keep
	// this same sealed claim rather than manufacturing a successor removal.
	job.Claim.ExpiresAt = live.Claim.ExpiresAt
	job.Claim.Record.ClaimExpiresAt = job.Claim.ExpiresAt
	job.Intent.Workspace = e.Workspace
	if err := api.ValidateCleanupJob(job, time.Now()); err != nil {
		t.Fatal(err)
	}
	return job
}

func testCleanupExpiry(t *testing.T, mode string, e cleanupEnrollment, job api.CleanupJob, before api.WorkspaceReadback, persist func(string) error) {
	t.Helper()
	ctx := context.Background()
	if err := requireCleanupMerged(ctx, e, before); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	if mode == "expired" {
		deadline = time.Now().Add(-time.Second)
	}
	job.Claim.ExpiresAt = api.Timestamp(deadline.UTC().Format(time.RFC3339Nano))
	job.Claim.Record.ClaimExpiresAt = job.Claim.ExpiresAt
	original := job.Claim
	if mode != "expired" {
		if err := api.ValidateCleanupJob(job, time.Now()); err != nil {
			t.Fatal("expiry fixture did not begin with a live original claim")
		}
	}
	phaseReached := false
	lastPhase := ""
	_, _, err := nativeWorkspaceAction(ctx, e, job, before, func(phase string) error {
		if err := persist(phase); err != nil {
			return err
		}
		lastPhase = phase
		if mode == "expiry-worktree" && phase == "removing" || mode == "expiry-branch" && phase == "worktree_removed" {
			if err := api.ValidateCleanupJob(job, time.Now()); err != nil {
				t.Fatal("expiry fixture reached its journal phase after the claim expired")
			}
			phaseReached = true
			// Actual wall-clock expiry after the preflights/journal write;
			// production's clock, job bytes and Git executable are unchanged.
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()
			<-timer.C
		}
		return nil
	})
	var typed *api.Error
	after, inspectErr := inspectNativeWorkspace(ctx, e)
	wantWorktree, wantPhase := "present", "removing"
	if mode == "expiry-branch" {
		wantWorktree, wantPhase = "absent", "worktree_removed"
	}
	if mode != "expired" && !phaseReached || !reflect.DeepEqual(original, job.Claim) || time.Now().Before(deadline) ||
		!errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != "native cleanup removal claim expired" || typed.Owner != owner || typed.Retryable || typed.OperationID != job.Intent.Cause.CauseOperationID ||
		inspectErr != nil || after.WorktreeState != wantWorktree || after.BranchState != "present" || lastPhase != wantPhase {
		t.Fatalf("acceptance: expired cleanup claim crossed a native deletion boundary: mode=%s phase=%s err=%v", mode, lastPhase, err)
	}
	if wantWorktree == "present" && !sameWorkspaceObservation(before, after) {
		t.Fatal("acceptance: expired cleanup claim crossed a native deletion boundary")
	}
	tip, present, readErr := cleanupBranch(ctx, e)
	if readErr != nil || !present || tip != before.Head {
		t.Fatal("acceptance: expired cleanup claim crossed a native deletion boundary")
	}
}
