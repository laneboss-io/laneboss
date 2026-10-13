// Command laneboss-config is the Go implementation of `laneboss config`. The Python launcher forwards
// `laneboss config ...` here, unchanged, when LANEBOSS_CONFIG_GO_BIN names this binary.
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
