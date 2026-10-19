package service

import (
	"context"
	"encoding/json"
	"sync/atomic"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This concrete private port keeps the public ReceiptStore contract unchanged.
// Wrappers must forward the store's actual atomic insertion result.
type mutationReservationStore interface {
	ReserveMutation(context.Context, api.RequestReservation) (api.MutationReceipt, bool, error)
}

type mutationOwnerKey struct{}

type mutationOwner struct {
	server    *Server
	config    string
	actor     api.Actor
	launch    api.ID
	endpoint  api.Generation
	key       api.RequestKey
	operation api.ID
	request   api.ID
	active    atomic.Bool
}

// OwnsMutation implements lifecycle's private MutationDispatch capability. A
// request ID, frame, connection or retained operation alone grants no ownership.
func (s *Server) OwnsMutation(ctx context.Context, scope api.Scope, key api.RequestKey, operation api.ID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, contextError(err)
	}
	owner, _ := ctx.Value(mutationOwnerKey{}).(*mutationOwner)
	if owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {
		return false, nil
	}
	actual := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	if actual != key || wire.ValidateRequest(scope.Request) != nil {
		return false, nil
	}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return false, err
	}
	return owner.active.Load() && receipt.Config == scope.Config && receipt.Actor == scope.Actor && receipt.Key == key && receipt.Operation.ID == operation && receipt.Operation.Status == "pending" && receipt.Reply == nil, nil
}

func (s *Server) invokeOwnedMutation(ctx context.Context, scope api.Scope, receipt api.MutationReceipt, handler api.Handler) (json.RawMessage, error) {
	owner := &mutationOwner{server: s, config: scope.Config, actor: scope.Actor, launch: scope.LaunchID, endpoint: scope.EndpointGeneration, key: receipt.Key, operation: receipt.Operation.ID, request: scope.Request.RequestID}
	owner.active.Store(true)
	defer owner.active.Store(false)
	return handler(context.WithValue(ctx, mutationOwnerKey{}, owner), scope, scope.Request.Params)
}
