package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// RunInternal is a trusted worker mode, never an arbitrary command endpoint.
// A label/argument cannot replace an installed binding and authenticated lease.
func RunInternal(ctx context.Context, config string, args []string) error {
	if len(args) == 1 && args[0] == "isolation-canary" && validConfig(config) {
		return runIsolationCanary(ctx, config)
	}
	if len(args) == 1 && (args[0] == "prepared-gate" || args[0] == "capture-spool") {
		if !validConfig(config) {
			return failure(api.CodeForbidden, "invalid installed bootstrap configuration")
		}
		return runFixedBootstrap(ctx, config, args[0])
	}
	if !validConfig(config) || len(args) != 0 {
		return failure(api.CodeForbidden, "internal helper accepts only its installed configuration; no argv, path or setuid mode")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	return runPlatformHelper(ctx, config)
}
