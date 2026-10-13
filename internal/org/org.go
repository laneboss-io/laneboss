// Package org dispatches the structured-org command group.
package org

import (
	"fmt"
	"io"

	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/orgdiscord"
	"laneboss.io/laneboss/internal/orghook"
	"laneboss.io/laneboss/internal/orgtree"
)

// Run is shared by the unified launcher and the per-group harness executable.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: laneboss org [-h] ACTION ...")
		fmt.Fprintln(stderr, "laneboss org: error: the following arguments are required: ACTION")
		return 2
	}
	action, rest := args[0], args[1:]
	switch action {
	case "init", "instance", "render", "validate":
		return orgtree.Run(action, rest, stdout, stderr)
	case "hook", "refusals", "check-hooks":
		return orghook.Run(action, rest, stdin, stdout, stderr)
	case "channel":
		return orgdiscord.Run(rest, stdout, stderr)
	case "hook-history", "capture-decision", "history-worker", "serve":
		return decisionsrv.Run(args, stdin, stdout, stderr)
	case "--help", "-h":
		fmt.Fprint(stdout, "usage: laneboss org [-h] ACTION ...\n\nActions:\n  init, instance, render, validate\n  hook, refusals, check-hooks\n  channel, hook-history, capture-decision\n")
		return 0
	}
	fmt.Fprintln(stderr, "usage: laneboss org [-h] ACTION ...")
	fmt.Fprintln(stderr, "laneboss org: error: argument ACTION: not accepted; a typed value is never repeated here, see the usage line above or run with --help")
	return 2
}
