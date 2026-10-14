// Command laneboss-config is retained for the GO_GROUPS migration harness.
// The installed laneboss binary calls the same internal command entry points.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"laneboss.io/laneboss/internal/config"
)

func main() {
	// Let Run handle a consumer closing stdout with the launcher's exit code 0.
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(config.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
