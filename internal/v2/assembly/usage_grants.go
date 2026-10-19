package assembly

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// A credential query has a separate private grant set, not the lane's own
// projection. Only the durable usage owner can recognize and revalidate it.
type usageGrantResolver struct {
	api.GrantResolver
	state  api.StateStore
	config string
}

func (r usageGrantResolver) Revalidate(ctx context.Context, input api.GrantSet) (api.GrantSet, error) {
	owner, ok := r.state.(interface {
		UsageGrant(context.Context, api.Scope, api.GrantSet) (bool, error)
	})
	if ok {
		found, err := owner.UsageGrant(ctx, api.Scope{Config: r.config, Actor: api.Actor{Kind: "service", ID: "usage-grants"}, Source: "worker"}, input)
		if err != nil {
			return api.GrantSet{}, err
		}
		if found {
			return input, nil
		}
	}
	return r.GrantResolver.Revalidate(ctx, input)
}
