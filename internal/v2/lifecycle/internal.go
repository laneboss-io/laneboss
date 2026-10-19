package lifecycle

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// RunInternal is a trusted worker mode, never an arbitrary command endpoint.
// A label/argument cannot replace an installed binding and authenticated lease.
func RunInternal(ctx context.Context, config string, args []string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if !validID(api.ID(config)) {
		return invalid("explicit supervisor configuration required")
	}
	if len(args) != 2 || args[0] != "--lease" || !validID(api.ID(args[1])) {
		return invalid("supervisor requires one installed capture lease")
	}
	bootstrap, _ := ctx.Value(supervisorKey{}).(SupervisorBootstrap)
	if absent(bootstrap) {
		return api.NotImplemented("lb-v2-service", "authenticated supervisor bootstrap")
	}
	return runSupervisor(ctx, config, api.ID(args[1]), bootstrap)
}
