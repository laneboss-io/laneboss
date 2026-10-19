package approval

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

func contextFailure(ctx context.Context) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	code := api.CodeCancelled
	message := "approval operation was cancelled"
	if errors.Is(err, context.DeadlineExceeded) {
		code = api.CodeDeadline
		message = "approval operation deadline elapsed"
	}
	return &api.Error{Code: code, Message: message,
		Instead: "Inspect the original operation receipt before retrying the same request.", Owner: "lb-v2-approval"}
}
