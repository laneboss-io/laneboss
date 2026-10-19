package admin

import (
	"fmt"

	"laneboss.io/laneboss/internal/v2/api"
)

// Private native outcome codes. These distinguish a completed measurement
// from an unavailable observation; they confer no cleanup or retry authority.
const (
	CodeArchiveLiveWriter api.ErrorCode = "archive_live_writer"
	CodeCleanupUnmerged   api.ErrorCode = "cleanup_branch_unmerged"
)

func archiveWriterRefusal(count uint64) *api.Error {
	return &api.Error{Code: CodeArchiveLiveWriter, Owner: owner, Retryable: false,
		Message: fmt.Sprintf("archive freeze measured %d live storage references; writable access remains", count),
		Instead: "Retain the original archive job and storage; reconcile the measured references before an authorized retry."}
}

func cleanupUnmergedRefusal(operation api.ID) *api.Error {
	return &api.Error{Code: CodeCleanupUnmerged, Owner: owner, OperationID: operation, Retryable: false,
		Message: "cleanup branch is not merged into common HEAD; worktree and branch retained",
		Instead: "Record failed cleanup and retain both namespaces; a different collection disposition requires an approved contract."}
}
