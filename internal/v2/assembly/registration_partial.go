//go:build laneboss_partial

package assembly

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// Development only. These routes supply no successful result, stream, peer
// identity or runtime substitute. The installed host still owns every gate.
// No owner is statically disabled here. An incomplete Register result selects this
// fallback. Individual unfinished methods keep their real owner's handler.
func unavailableRoutes(owner string, methods []api.Method, _ api.Method) (*moduleRoutes, error) {
	routes := newModuleRoutes()
	for _, method := range methods {
		routes.handlers[method] = func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
			return nil, api.NotImplemented(owner, string(method))
		}
		if streamMethod(method) {
			routes.streams[method] = func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) {
				return nil, api.NotImplemented(owner, string(method))
			}
		}
	}
	return routes, nil
}
