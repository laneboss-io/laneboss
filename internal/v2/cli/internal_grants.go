package cli

import (
	"context"

	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/orgrender"
)

func runInternalWorker(ctx context.Context, call Invocation) error {
	if len(call.Args) == 1 && call.Args[0] == "org-render" {
		return orgrender.RenderTree(ctx, "/job/tree", "/job/input.json")
	}
	args := append([]string{}, call.Args...)
	if len(args) == 2 && args[0] == "--lease" && call.integrateSocket != nil && call.integrateSocket.options.BindingFile == "/runtime/laneboss-worker.json" {
		args = append([]string{"--binding", call.integrateSocket.options.BindingFile}, args...)
	}
	return dataworker.RunInternal(ctx, call.Config, args)
}
