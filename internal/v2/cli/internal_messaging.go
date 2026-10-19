package cli

import (
	"context"

	"laneboss.io/laneboss/internal/v2/dataworker"
)

func runInternalChannel(ctx context.Context, call Invocation) error {
	return dataworker.RunInternal(ctx, call.Config, call.Args)
}
