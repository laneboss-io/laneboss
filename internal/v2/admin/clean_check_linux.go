//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

type cleanupRetainedError struct {
	Cause         *api.Error
	Before, After api.WorkspaceReadback
	Tip, Common   string
}

func (e *cleanupRetainedError) Error() string { return e.Cause.Error() }
func (e *cleanupRetainedError) Unwrap() error { return e.Cause }
func (e *cleanupRetainedError) CleanupRetention() (api.WorkspaceReadback, api.WorkspaceReadback, string, string) {
	return e.Before, e.After, e.Tip, e.Common
}

// Resolve both actual tips before any removal. An abandoned or squash-merged
// lane with unreachable commits has no authorized removal disposition today.
func requireCleanupMerged(ctx context.Context, e cleanupEnrollment, before api.WorkspaceReadback) error {
	tip, present, err := cleanupBranch(ctx, e)
	if err != nil {
		return err
	}
	if !present || tip != before.Head || tip != e.Workspace.Head {
		return failure(api.CodeConflict, "cleanup branch tip changed before ancestry measurement")
	}
	raw, err := gitSuccess(ctx, e, false, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return err
	}
	common := strings.TrimSpace(string(raw))
	if !cleanupGitHead(common) {
		return failure(api.CodeIntegrity, "cleanup common HEAD is malformed")
	}
	_, code, err := cleanupGit(ctx, e, false, "merge-base", "--is-ancestor", tip, common)
	if err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	if code != 1 {
		return failure(api.CodeContainmentUnknown, "cleanup branch ancestry could not be measured")
	}
	after, err := inspectNativeWorkspace(ctx, e)
	if err != nil {
		return err
	}
	if !sameWorkspaceObservation(before, after) {
		return failure(api.CodeConflict, "unmerged cleanup could not verify both original namespaces retained")
	}
	return &cleanupRetainedError{Cause: cleanupUnmergedRefusal(""), Before: before, After: after, Tip: tip, Common: common}
}

func (m *leaseManager) retainCleanupRefusal(p *leaseRecord, job api.CleanupJob, err error) error {
	var retained *cleanupRetainedError
	if !errors.As(err, &retained) {
		return err
	}
	cause := cleanupUnmergedRefusal(job.Intent.Cause.CauseOperationID)
	p.Cleanup = &cleanupJournal{Job: job, Phase: "retained_unmerged", Before: retained.Before, Retained: &retained.After, Refusal: cause, Reason: "branch_not_merged", BranchTip: retained.Tip, CommonHead: retained.Common, History: cleanupHistoryForSuccessor(p.Cleanup)}
	if err := m.save(*p); err != nil {
		return err
	}
	return cause
}

// No nested repository is consulted by git status until the whole bounded
// index has been classified. A gitlink is unknown work, including a missing
// submodule directory; no lane-authored nested configuration runs as root.
func checkCleanupIndex(raw []byte) error {
	if len(raw) > api.MaxFrameBytes || len(raw) > 0 && raw[len(raw)-1] != 0 {
		return failure(api.CodeIntegrity, "cleanup index observation is incomplete")
	}
	for _, entry := range bytes.Split(raw, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		header, name, ok := bytes.Cut(entry, []byte{'\t'})
		fields := bytes.Fields(header)
		if !ok || len(name) == 0 || len(fields) != 3 || !cleanupGitHead(string(fields[1])) {
			return failure(api.CodeIntegrity, "cleanup index entry is malformed")
		}
		if string(fields[0]) == "160000" {
			return failure(api.CodeContainmentUnknown, "cleanup index contains a gitlink; work remains unknown")
		}
		if string(fields[0]) != "100644" && string(fields[0]) != "100755" && string(fields[0]) != "120000" || string(fields[2]) != "0" {
			return failure(api.CodeContainmentUnknown, "cleanup index has an unsupported mode or unresolved stage")
		}
	}
	return nil
}
