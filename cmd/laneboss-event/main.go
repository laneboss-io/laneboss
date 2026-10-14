// Command laneboss-event is retained for the GO_GROUPS migration harness.
// The installed laneboss binary calls the same internal command entry points.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"laneboss.io/laneboss/internal/event"
)

func main() {
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(event.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
