// Command laneboss dispatches every command group inside one Go executable.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"laneboss.io/laneboss/internal/cli"
	"laneboss.io/laneboss/internal/selfexec"
)

func main() {
	// Command handlers turn a closed output pipe into the launcher's exit code.
	signal.Ignore(syscall.SIGPIPE)
	selfexec.UseUnifiedBinary()
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
