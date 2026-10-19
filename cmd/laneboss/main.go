// Command laneboss dispatches every command group inside one Go executable.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/installation"
	"laneboss.io/laneboss/internal/v2/cli"
)

func main() {
	if handled, code := cli.RunBootstrapEntry(context.Background(), os.Args[1:]); handled {
		os.Exit(code)
	}
	// Command handlers turn a closed output pipe into the launcher's exit code.
	signal.Ignore(syscall.SIGPIPE)
	// The bootstrap calls this only after verifying the release archive. Check
	// the compiled version before publishing anything under the chosen prefix.
	if len(os.Args) > 1 && os.Args[1] == "--install-release" {
		if len(os.Args) != 5 || os.Args[4] != identity.Version {
			fmt.Fprintln(os.Stderr, "install: release version does not match this binary, or invalid installer arguments")
			os.Exit(2)
		}
		binary, err := os.Executable()
		if err == nil {
			err = installation.Install(os.Args[2], os.Args[3], binary, os.Stdout)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "install: "+err.Error())
			os.Exit(2)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := cli.RunContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
