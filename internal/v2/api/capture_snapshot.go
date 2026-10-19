package api

const CaptureSnapshotPendingMessage = "capture snapshot update is in progress"

// Only the fixed helper's live checkpoint contention is a progressing wait.
// An unavailable dependency or a joined integrity failure is not this state.
func CaptureSnapshotPending(cause error) bool {
	switch typed := cause.(type) {
	case *Error:
		return typed != nil && typed.Code == CodeUnavailable && typed.Retryable && typed.Owner == "lb-v2-admin" && typed.Message == CaptureSnapshotPendingMessage
	case interface{ Unwrap() error }:
		return CaptureSnapshotPending(typed.Unwrap())
	}
	return false
}
