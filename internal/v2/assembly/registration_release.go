//go:build !laneboss_partial

package assembly

import "laneboss.io/laneboss/internal/v2/api"

func unavailableRoutes(_ string, _ []api.Method, missing api.Method) (*moduleRoutes, error) {
	return nil, missingHandler(missing)
}
