package service

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// A driver interruption may not wrap the context cause. Only failed work is
// normalized; successful reads and explicit integrity refusals keep their result.
func materializationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var typed *api.Error
	if errors.As(err, &typed) {
		return err
	}
	if cause := ctx.Err(); cause != nil {
		return contextError(cause)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextError(err)
	}
	return err
}
