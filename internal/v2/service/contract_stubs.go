// Service-owned dispatch storage is not a public RPC or shared API extension.
package service

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.ServiceHost = (*Server)(nil)
var _ api.DispatchControl = (*Server)(nil)

type dispatchStore interface {
	ActiveDispatchFreeze(context.Context) (*api.FreezeReceipt, error)
	FreezeDispatch(context.Context, api.Scope, api.FreezeRequest) (api.FreezeReceipt, error)
	ThawDispatch(context.Context, api.Scope, api.FreezeReceipt) error
	DispatchEffects(context.Context) ([]api.EffectRecord, error)
	DispatchRequests(context.Context) ([]api.ID, error)
	DispatchTargets(context.Context) ([]api.LifeRef, error)
}
