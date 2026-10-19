// Package objectread binds a complete internal object read to one read lifetime.
package objectread

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// Beginner is a private, optional in-process capability. It is not an RPC and
// must be forwarded by hosted stores that want verified object read views.
type Beginner interface {
	BeginObjectRead(context.Context, api.Scope) (api.ReadView, error)
}

// Bind borrows an existing request view, or owns a new view until release.
// Backends without the capability retain their ordinary checked Blob path;
// no digest or authority check is skipped in that case.
func Bind(ctx context.Context, source any, scope api.Scope) (api.Scope, func(*error), error) {
	unchanged := func(*error) {}
	if scope.ReadView != nil {
		return scope, unchanged, nil
	}
	port, ok := source.(Beginner)
	if !ok {
		return scope, unchanged, nil
	}
	view, err := port.BeginObjectRead(ctx, scope)
	if err != nil {
		return scope, unchanged, err
	}
	if view == nil {
		return scope, unchanged, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-service", Message: "object read view is missing"}
	}
	scope.ReadView = view
	return scope, func(resultErr *error) { *resultErr = errors.Join(*resultErr, view.Close()) }, nil
}
