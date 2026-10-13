// Command laneboss-state is retained for the GO_GROUPS migration harness.
// The installed laneboss binary calls the same internal command entry points.
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
