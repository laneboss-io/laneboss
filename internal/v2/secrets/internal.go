package secrets

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// RunInternal is a trusted worker mode, never an arbitrary command endpoint.
// A label/argument cannot replace an installed binding and authenticated lease.
func RunInternal(ctx context.Context, config string, args []string) error {
	// draft.3 supplies InstalledBinding and StateStore.WorkerLease lookup.
	// This entry still has no fixed credential-job dispatcher/atomic claim or
	// protected material channel. Lookup or an argv lease label cannot perform
	// that missing work. No input is executed or echoed here.
	if err := wire.Context(ctx); err != nil {
		return err
	}
	return api.NotImplemented("lb-v2-secrets", "internal.credential fixed job claim and protected material channel")
}
