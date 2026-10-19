package assembly

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only the installed host's requested shutdown is successful cancellation.
// Startup errors, deadlines, foreign cancellations and any joined cleanup or
// runtime failure remain errors. Serve still checks host.Close afterward.
func serveOutcome(ctx context.Context, err error) error {
	if ctx.Err() == context.Canceled && stopCancellation(err) {
		return nil
	}
	return err
}

func stopCancellation(err error) bool {
	if err == context.Canceled {
		return true
	}
	if typed, ok := err.(*api.Error); ok {
		return typed.Code == api.CodeCancelled && typed.Owner == "lb-v2-service"
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !stopCancellation(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return stopCancellation(wrapped.Unwrap())
	}
	return false
}
