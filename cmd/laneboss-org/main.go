// Command laneboss-org is the Go implementation of `laneboss org`. The Python launcher forwards
// `laneboss org ...` here, unchanged, when LANEBOSS_ORG_GO_BIN names this binary. Output, exit codes
// and refusals must match the Python implementation byte for byte: the same black-box tests prove both.
package main

import (
	"fmt"
	"os"

	"laneboss.io/laneboss/internal/orgdiscord"
	"laneboss.io/laneboss/internal/orghook"
	"laneboss.io/laneboss/internal/orgtree"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: laneboss org [-h] ACTION ...")
		fmt.Fprintln(os.Stderr, "laneboss org: error: the following arguments are required: ACTION")
		return 2
	}
	action, rest := args[0], args[1:]
	switch action {
	case "init", "instance", "render", "validate":
		return orgtree.Run(action, rest, os.Stdout, os.Stderr)
	case "hook", "refusals", "check-hooks":
		return orghook.Run(action, rest, os.Stdin, os.Stdout, os.Stderr)
	case "channel":
		return orgdiscord.Run(rest, os.Stdout, os.Stderr)
	}
	fmt.Fprintln(os.Stderr, "usage: laneboss org [-h] ACTION ...")
	fmt.Fprintf(os.Stderr, "laneboss org: error: argument ACTION: invalid choice: %q\n", action)
	return 2
}
