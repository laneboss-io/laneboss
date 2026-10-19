//go:build linux && laneboss_root_canary

package admin_test

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/cli"
)

// The enrolled artifact must enter through the installed CLI, including common
// option parsing. Calling RunInternal directly hides missing launch arguments.
func init() {
	if len(os.Args) < 3 || os.Args[1] != "internal" || os.Args[2] != "worker" {
		return
	}
	// Match the installed command's signal setup, including its Go runtime
	// tasks, before dispatching the real fixed worker CLI.
	signal.Ignore(syscall.SIGPIPE)
	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(signals, 15*time.Second)
	code := cli.RunContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	cancel()
	stop()
	os.Exit(code)
}
