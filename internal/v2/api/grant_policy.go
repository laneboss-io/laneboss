package api

import "context"

// GrantPolicyRequest selects protected target metadata, never an authenticated
// actor. It is an in-process read port and is absent from the RPC catalog.
type GrantPolicyRequest struct {
	ReservationID    ID
	Target           LifeRef
	GrantSetID       ID
	Context          RoleContext
	PolicyGeneration Generation
}

type GrantPolicyReader interface {
	GrantPolicy(context.Context, Scope, GrantPolicyRequest) (EffectivePolicy, error)
}
