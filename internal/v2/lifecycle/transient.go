package lifecycle

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// A retryable or uncertain stage keeps its original journal and resources.
// Reconciliation may fill the missing result; it may never acquire again.
func transientPlan(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if typed, ok := err.(*api.Error); ok {
		return typed != nil && (typed.Retryable || typed.Code == api.CodeCancelled || typed.Code == api.CodeDeadline ||
			typed.Code == api.CodeUnavailable || typed.Code == api.CodeContainmentUnknown)
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if transientPlan(child) {
				return true
			}
		}
	} else if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return transientPlan(wrapped.Unwrap())
	}
	return false
}

func planError(err error) *api.Error {
	typed := failure(err).(*api.Error)
	if transientPlan(err) && !transientPlan(typed) {
		copy := *typed
		copy.Retryable = true
		return &copy
	}
	return typed
}
