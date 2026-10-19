package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type requestFrameKey struct{}

func frameFromContext(ctx context.Context) api.FrameContext {
	frame, _ := ctx.Value(requestFrameKey{}).(api.FrameContext)
	return frame
}

type receiptView struct{ snapshot api.ReadSnapshot }

func (v receiptView) Snapshot() api.ReadSnapshot { return v.snapshot }
func (receiptView) Close() error                 { return nil }

type humanSessionFinalizer interface {
	FinalizeHumanSession(context.Context, api.Scope) (api.HumanSession, error)
}

func (s *Server) dispatchMutation(ctx context.Context, scope api.Scope, request api.Request) (json.RawMessage, api.Scope, error) {
	// Even a retry carrying its caller's context is a separate invocation.
	ctx = context.WithValue(ctx, mutationOwnerKey{}, (*mutationOwner)(nil))
	flight := scope.Actor.Kind + ":" + string(scope.Actor.ID) + ":" + string(scope.Actor.LifeID) + ":" + string(request.Method) + ":" + string(request.IdempotencyKey)
	for {
		s.mu.Lock()
		if s.flights == nil {
			s.flights = make(map[string]chan struct{})
		}
		if wait := s.flights[flight]; wait != nil {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, scope, contextError(ctx.Err())
			case <-wait:
			}
			continue
		}
		s.flights[flight] = make(chan struct{})
		s.mu.Unlock()
		break
	}
	defer func() { s.mu.Lock(); close(s.flights[flight]); delete(s.flights, flight); s.mu.Unlock() }()
	key := api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err == nil && receipt.Reply == nil {
		receipt, err = s.deps.Store.AwaitReceipt(ctx, scope, key)
	}
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
		switch request.Method {
		case "lane.start", "lane.adopt", "lane.resume", "lane.turn":
			s.mu.RLock()
			ready := s.launchConfigured && s.launchJobsActive && s.launchJobsHealthy
			s.mu.RUnlock()
			if !ready {
				return nil, scope, serviceError(api.CodePrerequisite, "launch admission requires LaunchPlanner and active healthy recovery/capture jobs")
			}
		}
		// A completed receipt remains readable during a deployment freeze.
		// Only new work acquires admission and contributes to drain activity.
		release, admissionErr := s.admitDispatch(ctx)
		if admissionErr != nil {
			return nil, scope, admissionErr
		}
		defer release()
		raw, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			return nil, scope, marshalErr
		}
		if scope.Frame != nil {
			raw = scope.Frame.Bytes()
		}
		control, ok := s.deps.Store.(mutationReservationStore)
		if !ok {
			return nil, scope, api.NotImplemented("lb-v2-service", "atomic mutation reservation ownership")
		}
		if tracker, ok := s.deps.Store.(interface {
			TrackMutation(context.Context) (context.Context, func())
		}); ok {
			var retire func()
			ctx, retire = tracker.TrackMutation(ctx)
			defer retire()
		}
		var won bool
		receipt, won, err = control.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: raw,
			Deadline: api.Timestamp(s.deps.Clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
		if err != nil {
			return nil, scope, err
		}
		if receipt.Config != scope.Config || receipt.Actor != scope.Actor || receipt.Key != key || !wire.ValidID(string(receipt.Operation.ID)) {
			return nil, scope, serviceError(api.CodeIntegrity, "atomic mutation reservation returned another request")
		}
		if !won {
			if receipt.Reply == nil {
				receipt, err = s.deps.Store.AwaitReceipt(ctx, scope, key)
			}
		} else {
			if receipt.Reply != nil || receipt.Operation.Status != "pending" || !wire.SameJSON(receipt.RawRequest, raw) {
				return nil, scope, serviceError(api.CodeIntegrity, "mutation winner lacks its original pending reservation")
			}
			s.mu.RLock()
			handler := s.handlers[request.Method]
			s.mu.RUnlock()
			var result json.RawMessage
			if handler == nil {
				err = api.NotImplemented(api.Methods[request.Method].Owner, string(request.Method))
			} else {
				result, err = s.invokeOwnedMutation(ctx, scope, receipt, handler)
			}
			if err == nil {
				err = wire.ValidateResult(request.Method, result)
			}
			if err != nil {
				if request.Method == "human.session" {
					// A session can commit before its connection finalization fails.
					// Preserve that failure for this invocation; never reload the
					// successful durable receipt over it or retry the bind here.
					committed, lookupErr := s.deps.Store.LookupReceipt(ctx, scope, key)
					if lookupErr != nil {
						return nil, scope, errors.Join(err, lookupErr)
					}
					if committed.Reply != nil && committed.Reply.Error == nil {
						return nil, scope, err
					}
				}
				if owner, ok := s.deps.Store.(interface {
					OwnsDeferredMutation(context.Context, api.Scope, api.RequestKey, api.ID) (bool, error)
				}); ok {
					// A disconnected waiter does not retire the original archive
					// job. It stays pending for the same outbox/recovery route.
					pending, ownerErr := owner.OwnsDeferredMutation(context.WithoutCancel(ctx), scope, key, receipt.Operation.ID)
					if ownerErr != nil {
						return nil, scope, ownerErr
					}
					if pending {
						failure := *typedError(err)
						failure.OperationID = receipt.Operation.ID
						return nil, scope, &failure
					}
				}
				_, commitErr := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, RawRequest: raw, Reply: &api.RPCReply{Error: typedError(err)}})
				if commitErr != nil {
					return nil, scope, commitErr
				}
			}
			receipt, err = s.deps.Store.LookupReceipt(ctx, scope, key)
			if err == nil && receipt.Reply == nil {
				err = serviceError(api.CodeIntegrity, "mutation handler did not commit its exact reply")
			}
		}
	}
	if err != nil {
		return nil, scope, err
	}
	if receipt.Reply == nil {
		return nil, scope, serviceError(api.CodeUnavailable, "mutation remains pending")
	}
	if scope.Connection != nil {
		current, err := s.authenticateConnection(ctx, scope.Connection)
		if err != nil {
			return nil, scope, err
		}
		if current.Actor != scope.Actor || current.Config != scope.Config || current.LaunchID != scope.LaunchID || current.EndpointGeneration != scope.EndpointGeneration || current.PolicyGeneration != scope.PolicyGeneration {
			return nil, scope, serviceError(api.CodeUnauthenticated, "mutation peer changed before reply")
		}
		current.Connection, current.Frame, current.Request, current.Source = scope.Connection, scope.Frame, request, scope.Source
		if err := s.deps.Authenticator.Authorize(ctx, current, request); err != nil {
			return nil, scope, err
		}
		if scope.Frame != nil {
			if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
				return nil, scope, err
			}
		}
	}
	if receipt.Reply.Error != nil {
		return nil, scope, receipt.Reply.Error
	}
	if request.Method == "human.session" {
		finalizer, ok := s.deps.Authenticator.(humanSessionFinalizer)
		if !ok {
			return nil, scope, api.NotImplemented("lb-v2-identity", "private human session finalization")
		}
		var retained api.HumanSession
		if err := wire.Decode(receipt.Reply.Result, &retained); err != nil {
			return nil, scope, err
		}
		actual, err := finalizer.FinalizeHumanSession(ctx, scope)
		if err != nil {
			return nil, scope, err
		}
		if actual != retained {
			return nil, scope, serviceError(api.CodeIntegrity, "finalized session differs from its completed receipt")
		}
	}
	scope.ReadView = receiptView{snapshot: api.ReadSnapshot{Config: scope.Config, LastSeq: receipt.LastSeq}}
	return append(json.RawMessage(nil), receipt.Reply.Result...), scope, nil
}
