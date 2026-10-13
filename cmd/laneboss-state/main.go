// Command laneboss-state is the Go implementation of `laneboss state`. The Python launcher forwards
// `laneboss state ...` here, unchanged, when LANEBOSS_STATE_GO_BIN names this binary.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"laneboss.io/laneboss/internal/state"
)

func main() {
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(state.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
