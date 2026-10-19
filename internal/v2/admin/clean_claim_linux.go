//go:build linux

package admin

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func cleanupExpiredClaim(job api.CleanupJob) *api.Error {
	return &api.Error{Code: api.CodeConflict, Owner: owner, OperationID: job.Intent.Cause.CauseOperationID,
		Message: "native cleanup removal claim expired", Retryable: false,
		Instead: "Retain the original native journal and remaining namespaces; an unfinished removal cannot restart under a successor claim."}
}

// Entry authorization can expire during collection, Git preflights or durable
// journal writes. Every destructive Git call independently fences the original
// job and uses its deadline, including after worktree removal and before branch
// deletion. Metadata/executable checks run inside that deadline too.
func cleanupGitRemoval(ctx context.Context, e cleanupEnrollment, job api.CleanupJob, args ...string) ([]byte, error) {
	deadline, err := time.Parse(time.RFC3339Nano, string(job.Claim.ExpiresAt))
	if err != nil {
		return nil, failure(api.CodeInvalid, "native cleanup removal claim has an invalid expiry")
	}
	now := time.Now()
	if !deadline.After(now) {
		return nil, cleanupExpiredClaim(job)
	}
	if err := api.ValidateCleanupJob(job, now); err != nil {
		return nil, err
	}
	if job.Intent.Workspace != e.Workspace {
		return nil, failure(api.CodeForbidden, "native cleanup removal claim selects another workspace")
	}
	removalCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	output, err := gitSuccess(removalCtx, e, false, args...)
	if !deadline.After(time.Now()) {
		return nil, cleanupExpiredClaim(job)
	}
	return output, err
}
