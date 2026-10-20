//go:build linux

package admin

import (
	"context"
	"errors"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// RunBootstrapEntry is called before signal setup and general CLI parsing.
// Recognition reads only argv; the first setup pins the inherited reason route.
func RunBootstrapEntry(ctx context.Context, args []string) (bool, int) {
	if len(args) == 3 && args[0] == restoreChildEntry {
		return true, runRestoreChild(ctx, args[1:])
	}
	if len(args) == 0 || args[0] != FixedBootstrapEntry {
		return false, 0
	}
	err := withBootstrapRoute(func() error {
		if len(args) != 4 || args[2] != "--config" || args[1] != "prepared-gate" && args[1] != "capture-spool" && args[1] != "credential-probe" {
			return failure(api.CodeInvalid, "fixed bootstrap entry arguments differ")
		}
		if !validConfig(args[3]) {
			return failure(api.CodeInvalid, "fixed bootstrap entry configuration differs")
		}
		return executeFixedBootstrap(ctx, args[3], args[1])
	})
	if err == nil {
		return true, 0
	}
	code, known := bootstrapStageCodes[bootstrapErrorReason(err)]
	if !known || code <= 0 {
		code = bootstrapUnknownExit
	}
	return true, code
}

func pinBootstrapRoute() (int, error) {
	fd, err := unix.FcntlInt(5, unix.F_DUPFD_CLOEXEC, 6)
	if err != nil {
		return -1, failure(api.CodePrerequisite, "fixed bootstrap failure route is unavailable")
	}
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_SEQPACKET {
		closeErr := unix.Close(fd)
		if closeErr != nil {
			return -1, failure(api.CodeIntegrity, "fixed bootstrap failure route could not close")
		}
		return -1, failure(api.CodePrerequisite, "fixed bootstrap failure route is unavailable")
	}
	return fd, nil
}

func withBootstrapRoute(run func() error) (resultErr error) {
	route, err := pinBootstrapRoute()
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			if err := reportBootstrapFailure(route, resultErr); err != nil {
				resultErr = errors.Join(resultErr, failure(api.CodeUnavailable, "bootstrap failure reason could not be delivered"))
			}
		}
		if err := unix.Close(route); err != nil {
			resultErr = errors.Join(resultErr, failure(api.CodeIntegrity, "fixed bootstrap failure route could not close"))
		}
	}()
	signal.Ignore(syscall.SIGPIPE)
	return run()
}
