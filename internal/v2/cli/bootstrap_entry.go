package cli

import (
	"context"

	"laneboss.io/laneboss/internal/v2/admin"
)

// RunBootstrapEntry recognizes only the installed descriptor bootstrap marker.
// It runs before ordinary command parsing or installation/configuration reads.
func RunBootstrapEntry(ctx context.Context, args []string) (bool, int) {
	return admin.RunBootstrapEntry(ctx, args)
}
