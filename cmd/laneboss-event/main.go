// Command laneboss-event is the Go implementation of `laneboss event`. The Python launcher forwards
// `laneboss event ...` here, unchanged, when LANEBOSS_EVENT_GO_BIN names this binary.
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
