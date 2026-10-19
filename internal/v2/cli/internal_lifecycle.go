package cli

import (
	"context"

	"laneboss.io/laneboss/internal/v2/lifecycle"
)

func runInternalSupervisor(ctx context.Context, call Invocation) error {
	return lifecycle.RunInternal(ctx, call.Config, call.Args)
}
