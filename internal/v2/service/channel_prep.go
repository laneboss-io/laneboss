package service

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Server) PrepareChannelJob(ctx context.Context, caller api.Scope, request api.ChannelPrepareRequest) (api.ChannelJob, error) {
	s.mu.RLock()
	ready := s.verified && s.bound && !s.closed
	s.mu.RUnlock()
	if !ready || caller.Config != s.options.Config {
		return api.ChannelJob{}, serviceError(api.CodePrerequisite, "channel coordinator is not installed and bound")
	}
	owner, ok := s.deps.Store.(interface {
		OwnsMutation(context.Context, api.Scope, api.RequestKey, api.ID) (bool, error)
	})
	if !ok {
		return api.ChannelJob{}, serviceError(api.CodePrerequisite, "channel preparation requires its actual pending invocation")
	}
	owned, err := owner.OwnsMutation(ctx, caller, api.RequestKey{Method: caller.Request.Method, IdempotencyKey: caller.Request.IdempotencyKey, RequestSHA256: caller.Request.RequestSHA256}, request.OperationID)
	if err != nil {
		return api.ChannelJob{}, err
	}
	if !owned {
		return api.ChannelJob{}, serviceError(api.CodeConflict, "channel preparation belongs to another invocation")
	}
	scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: s.controller}}
	return s.deps.Store.PrepareChannelJob(ctx, scope, request)
}
