package service

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type checkPreparationStore interface {
	PrepareCheckWorker(context.Context, api.Scope, api.Scope, api.TestChildRequest, api.GrantSet) (archivejob.Job, error)
	PublishCheckInputs(context.Context, api.Scope, archivejob.Job) (api.Operation, error)
}

func (s *Server) pendingCheck(ctx context.Context, caller api.Scope, request api.TestChildRequest) (api.MutationReceipt, api.Scope, error) {
	control, err := s.controlScope()
	if err != nil {
		return api.MutationReceipt{}, control, err
	}
	if caller.Config != control.Config || caller.Request.Method != "grants.test-child" || caller.Actor.Kind != "lane" || caller.Actor.LifeID == request.Child.LifeID || caller.Connection == nil || caller.Frame == nil {
		return api.MutationReceipt{}, control, serviceError(api.CodeUnauthenticated, "child checker requires its actual distinct supervising caller")
	}
	if err := caller.Frame.Verify(ctx, caller.Connection); err != nil {
		return api.MutationReceipt{}, control, err
	}
	var original api.Request
	var decoded api.TestChildRequest
	if api.DecodeObject(caller.Frame.Bytes(), &original) != nil || !reflect.DeepEqual(original, caller.Request) || api.DecodeObject(original.Params, &decoded) != nil || decoded != request {
		return api.MutationReceipt{}, control, serviceError(api.CodeIntegrity, "child checker lost its exact original request")
	}
	current, err := s.authenticateConnection(ctx, caller.Connection)
	if err != nil {
		return api.MutationReceipt{}, control, err
	}
	if current.Actor != caller.Actor || current.Config != caller.Config || current.LaunchID != caller.LaunchID || current.EndpointGeneration != caller.EndpointGeneration || current.PolicyGeneration != caller.PolicyGeneration {
		return api.MutationReceipt{}, control, serviceError(api.CodeUnauthenticated, "child checker caller changed")
	}
	if err := s.deps.Authenticator.Authorize(ctx, caller, caller.Request); err != nil {
		return api.MutationReceipt{}, control, err
	}
	key := api.RequestKey{Method: caller.Request.Method, IdempotencyKey: caller.Request.IdempotencyKey, RequestSHA256: caller.Request.RequestSHA256}
	retained, err := s.deps.Store.LookupReceipt(ctx, caller, key)
	if err != nil {
		return retained, control, err
	}
	owner, ok := s.deps.Store.(interface {
		OwnsMutation(context.Context, api.Scope, api.RequestKey, api.ID) (bool, error)
	})
	if !ok {
		return retained, control, serviceError(api.CodePrerequisite, "child checker requires actual dispatcher ownership")
	}
	owned, err := owner.OwnsMutation(ctx, caller, key, retained.Operation.ID)
	if err != nil {
		return retained, control, err
	}
	if !owned || retained.Reply != nil || retained.Operation.Status != "pending" {
		return retained, control, serviceError(api.CodeConflict, "child checker lost its original pending operation")
	}
	return retained, control, nil
}

// This private composition port is reached only after grants validates the
// real child-owned candidate and bounded declaration under the original frame.
func (s *Server) TestChildScoped(ctx context.Context, caller api.Scope, request api.TestChildRequest, grants api.GrantSet) (api.Operation, error) {
	_, control, err := s.pendingCheck(ctx, caller, request)
	if err != nil {
		return api.Operation{}, err
	}
	state, ok := s.deps.Store.(checkPreparationStore)
	if !ok {
		return api.Operation{}, serviceError(api.CodePrerequisite, "native child checker writer is unavailable")
	}
	job, err := state.PrepareCheckWorker(ctx, caller, control, request, grants)
	if err != nil {
		return api.Operation{}, err
	}
	if err := s.ExecuteReviewWorker(ctx, caller, job); err != nil {
		return api.Operation{}, err
	}
	// The original connection remains authenticated; publication independently
	// joins the actual completed test effect, acknowledgement and retirement.
	current, err := s.authenticateConnection(ctx, caller.Connection)
	if err != nil {
		return api.Operation{}, err
	}
	if current.Actor != caller.Actor || current.LaunchID != caller.LaunchID || current.PolicyGeneration != caller.PolicyGeneration {
		return api.Operation{}, serviceError(api.CodeConflict, "child checker caller changed before publication")
	}
	return state.PublishCheckInputs(ctx, caller, job)
}
