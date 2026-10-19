package service

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Fixed authenticated outside-job ingress, never public Method registration.
var _ api.CaptureStore = (*Server)(nil)

func (s *Server) captureScope(ctx context.Context, transport api.Scope) (api.Scope, error) {
	s.mu.RLock()
	installed := s.verified && s.bound && !s.closed
	s.mu.RUnlock()
	if !installed || transport.Connection == nil || transport.Frame == nil || transport.Connection.Peer() == nil {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "capture ingress requires the fixed authenticated worker connection and frame")
	}
	connection := transport.Connection
	if err := transport.Frame.Verify(ctx, connection); err != nil {
		return api.Scope{}, err
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return api.Scope{}, err
	}
	// The supplied Scope contributes only transport evidence. None of its
	// actor, requester, operation or target labels become authority.
	scope, err := s.authenticateConnection(ctx, connection)
	if err != nil {
		return api.Scope{}, err
	}
	binding := connection.Binding()
	if scope.Actor.Kind != "worker" || binding.Class != api.EndpointWorker || scope.Config != s.options.Config || binding.Config != scope.Config ||
		scope.EndpointGeneration != binding.EndpointGeneration || scope.LaunchID != binding.LaunchID || binding.Target == nil || binding.WorkerLeaseID == "" {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "capture connection is not its installed worker endpoint")
	}
	scope.Connection, scope.Frame, scope.Request, scope.Source = connection, transport.Frame, api.Request{}, "worker"
	return scope, nil
}

func (s *Server) CaptureState(ctx context.Context, transport api.Scope, id api.ID) (api.CaptureState, error) {
	if !wire.ValidID(string(id)) {
		return api.CaptureState{}, wire.Invalid("capture state requires its binding selector")
	}
	scope, err := s.captureScope(ctx, transport)
	if err != nil {
		return api.CaptureState{}, err
	}
	return s.deps.Store.CaptureState(ctx, scope, id)
}

func (s *Server) AppendCapture(ctx context.Context, transport api.Scope, request api.CaptureAppendRequest) (api.CaptureAppendReceipt, error) {
	scope, err := s.captureScope(ctx, transport)
	if err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	if request.Intent != (api.InternalIntent{}) {
		return api.CaptureAppendReceipt{}, serviceError(api.CodeForbidden, "capture ingress cannot supply an internal intent principal or cause")
	}
	state, err := s.deps.Store.CaptureState(ctx, scope, request.BindingID)
	if err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	control, err := s.controlScope()
	if err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, control, state.Binding.ReservationID)
	if err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	// A range of another run would write into that run's output: that stays refused.
	if state.Binding.Target != *scope.Connection.Binding().Target {
		return api.CaptureAppendReceipt{}, serviceError(api.CodeForbidden, "capture range belongs to another registered producer or run")
	}
	if state.Binding.ProducerID != scope.Actor.ID {
		allowAndLog("capture_producer")
	}
	id, err := wire.NewID()
	if err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	binding := state.Binding
	request.Intent = api.InternalIntent{ID: id, Kind: api.InternalCaptureAppend, Config: scope.Config, Actor: scope.Actor, RequestedBy: binding.RequestedBy,
		CauseOperationID: binding.OperationID, CauseRequestID: binding.RequestID, EffectID: binding.EffectID, Target: binding.Target, CancellationEpoch: plan.Reservation.CancellationEpoch}
	return s.deps.Store.AppendCapture(ctx, scope, request)
}

// RetainCapture is the narrow byte-upload half of the fixed outside-job
// channel. The producer supplies neither an object ID/class/ACL nor a source
// operation. It adds no public BlobBegin or Methods authority.
func (s *Server) RetainCapture(ctx context.Context, transport api.Scope, bindingID api.ID, data []byte) (api.BlobRef, error) {
	if len(data) == 0 || len(data) > api.MaxChunkBytes {
		return api.BlobRef{}, wire.Invalid("capture upload requires one bounded nonempty pipe range")
	}
	scope, err := s.captureScope(ctx, transport)
	if err != nil {
		return api.BlobRef{}, err
	}
	state, err := s.deps.Store.CaptureState(ctx, scope, bindingID)
	if err != nil {
		return api.BlobRef{}, err
	}
	control, err := s.controlScope()
	if err != nil {
		return api.BlobRef{}, err
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, control, state.Binding.ReservationID)
	if err != nil {
		return api.BlobRef{}, err
	}
	id, err := wire.NewID()
	if err != nil {
		return api.BlobRef{}, err
	}
	intentID, err := wire.NewID()
	if err != nil {
		return api.BlobRef{}, err
	}
	b := state.Binding
	retained := append([]byte(nil), data...)
	intent := api.InternalIntent{ID: intentID, Kind: api.InternalCaptureAppend, Config: scope.Config, Actor: scope.Actor, RequestedBy: b.RequestedBy, CauseOperationID: b.OperationID, CauseRequestID: b.RequestID, EffectID: b.EffectID, Target: b.Target, CancellationEpoch: plan.Reservation.CancellationEpoch}
	return s.deps.Store.RetainObject(ctx, scope, api.RetainObjectRequest{Intent: intent, Object: api.ObjectWrite{ObjectKey: id, Class: "capture", Bytes: retained, SHA256: digestBytes(retained), Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: b.Target.LifeID, Audience: "owner", Generation: 1}}})
}
