package cli

import (
	"context"

	"laneboss.io/laneboss/internal/v2/judge"
)

func runInternalJudge(ctx context.Context, call Invocation) error {
	args := append([]string{}, call.Args...)
	if len(args) == 2 && args[0] == "--lease" && call.integrateSocket != nil && call.integrateSocket.options.BindingFile == "/runtime/laneboss-worker.json" {
		args = append([]string{"--binding", call.integrateSocket.options.BindingFile}, args...)
	}
	return judge.RunInternal(ctx, call.Config, args)
}
