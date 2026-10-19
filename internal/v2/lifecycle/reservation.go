package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) launchAvailability(ctx context.Context, scope api.Scope, request api.StartRequest) error {
	if _, err := s.readBlob(ctx, scope, request.Task); err != nil {
		return err
	}
	if absent(s.deps.Grants) {
		return api.NotImplemented("lb-v2-grants", "GrantResolver.Resolve")
	}
	if _, err := s.runner(request.Driver); err != nil {
		return err
	}
	return s.probe(ctx)
}

// A fresh dispatcher reservation has no reply yet. It belongs to this executor;
// awaiting that receipt here would await our own ReserveLaunch handoff.
func (s *Service) launchReplay(ctx context.Context, scope api.Scope) (api.Operation, bool, error) {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey,
		RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed != nil && typed.Code == api.CodeNotFound {
			return api.Operation{}, false, nil
		}
		return api.Operation{}, true, failure(err)
	}
	if !receiptMatches(scope, key, receipt) || !validID(receipt.Operation.ID) {
		return api.Operation{}, true, integrity("launch receipt differs from its authentic request")
	}
	if receipt.Reply == nil {
		owned, err := s.ownsMutation(ctx, scope, key, receipt)
		if err != nil {
			return api.Operation{}, true, err
		}
		if owned {
			return api.Operation{}, false, nil
		}
		receipt, err = s.deps.Store.AwaitReceipt(ctx, scope, key)
		if err != nil {
			return api.Operation{}, true, failure(err)
		}
		if !receiptMatches(scope, key, receipt) || !validID(receipt.Operation.ID) {
			return api.Operation{}, true, integrity("launch receipt differs from its authentic request")
		}
		if receipt.Reply == nil {
			return api.Operation{}, true, problem(api.CodeUnavailable, "launch receipt is still pending", "Await the original dispatcher operation.")
		}
	}
	if err := s.receiptPolicy(ctx, scope, receipt); err != nil {
		return api.Operation{}, true, err
	}
	if (receipt.Reply.Error == nil) == (len(receipt.Reply.Result) == 0) {
		return api.Operation{}, true, integrity("launch receipt has no exact result or error")
	}
	if receipt.Reply.Error != nil {
		return api.Operation{}, true, receipt.Reply.Error
	}
	var operation api.Operation
	if api.DecodeObject(receipt.Reply.Result, &operation) != nil || operation.ID != receipt.Operation.ID ||
		(receipt.Operation.LifeID != "" && operation.LifeID != receipt.Operation.LifeID) ||
		(receipt.Operation.Run != 0 && operation.Run != receipt.Operation.Run) ||
		!validTarget(api.LifeRef{LifeID: operation.LifeID, Run: operation.Run}) {
		return api.Operation{}, true, integrity("launch receipt has an invalid retained operation")
	}
	if !launchReplyTarget(scope.Request, receipt.Operation, operation) {
		return api.Operation{}, true, integrity("launch reply differs from its original requested target")
	}
	return operation, true, nil
}

func launchReplyTarget(request api.Request, retained, operation api.Operation) bool {
	switch request.Method {
	case "lane.start", "lane.adopt":
		// These requests have no life/run selector. The receipt retains the
		// original assigned target, regardless of later preflight state.
		target := api.LifeRef{LifeID: retained.LifeID, Run: retained.Run}
		if target == (api.LifeRef{}) {
			// A pre-reservation envelope has no assigned target; its sealed
			// reply still has to describe the original first launch.
			return operation.Run == 1
		}
		return validTarget(target) && operation.LifeID == target.LifeID && operation.Run == target.Run
	case "lane.resume":
		var value api.ResumeRequest
		return api.DecodeObject(request.Params, &value) == nil && operation.LifeID == value.Target.LifeID && operation.Run == value.Target.Run+1
	case "lane.turn":
		var value api.TurnRequest
		return api.DecodeObject(request.Params, &value) == nil && operation.LifeID == value.Target.LifeID && operation.Run == value.Target.Run+1
	}
	return false
}

func (s *Service) reservePublicLaunch(ctx context.Context, scope api.Scope, mode string, previous api.Lane) (api.Operation, error) {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey,
		RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if !receiptMatches(scope, key, receipt) || receipt.Reply != nil || !validID(receipt.Operation.ID) || receipt.Operation.Status != "pending" ||
		len(receipt.RawRequest) == 0 || len(receipt.RawRequest) > api.MaxFrameBytes {
		return api.Operation{}, integrity("launch has no exact pending dispatcher reservation")
	}
	owned, err := s.ownsMutation(ctx, scope, key, receipt)
	if err != nil {
		return api.Operation{}, err
	}
	if !owned {
		return api.Operation{}, integrity("mutation cannot complete another executor's reservation")
	}
	var original api.Request
	if api.DecodeObject(receipt.RawRequest, &original) != nil || !reflect.DeepEqual(original, scope.Request) {
		return api.Operation{}, integrity("launch reservation changed its original request bytes")
	}
	var parent api.Lane
	if scope.Actor.Kind == "lane" && previous.LifeID == "" {
		if !validGeneration(scope.EndpointGeneration) {
			return api.Operation{}, integrity("child reservation has no authenticated endpoint generation")
		}
		parent, err = s.currentStarter(ctx, scope, scope.LaunchID, scope.Actor, scope.EndpointGeneration)
		if err != nil {
			return api.Operation{}, err
		}
	}
	guards, authority, err := s.launchAuthority(ctx, scope, previous)
	if err != nil {
		return api.Operation{}, err
	}
	selector := api.LaunchReservationRequest{OperationID: receipt.Operation.ID, Guards: guards}
	if err := api.ValidateLaunchReservationRequest(scope, selector); err != nil {
		return api.Operation{}, failure(err)
	}
	reservation, err := s.deps.Store.ReserveLaunch(ctx, scope, selector)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if err := api.ValidateLaunchReservation(reservation); err != nil {
		// The public input was validated before this protected store call.
		// Invalid returned authority is an integrity fault, not file input.
		return api.Operation{}, integrity("store returned an invalid launch reservation")
	}
	if parent.LifeID != "" && !childReservation(parent, reservation) {
		return api.Operation{}, integrity("child reservation exceeds its current starter level or ancestry")
	}
	if reservation.Config != scope.Config || reservation.Mode != mode || reservation.OperationID != receipt.Operation.ID ||
		reservation.Authority != authority || !reservationPins(scope.Request, previous, reservation) ||
		reservation.RequestID != scope.Request.RequestID || reservation.RequestSHA256 != scope.Request.RequestSHA256 ||
		reservation.RequestedBy != scope.Actor || reservation.PolicyGeneration != scope.PolicyGeneration ||
		reservation.OriginalRequest.SHA256 != digestOfBytes(receipt.RawRequest) || reservation.OriginalRequest.Bytes != int64(len(receipt.RawRequest)) ||
		scope.Actor.Kind == "lane" && previous.LifeID == "" && reservation.ParentLifeID != scope.Actor.LifeID ||
		scope.Actor.Kind == "human" && previous.LifeID == "" && reservation.ParentLifeID != "" ||
		previous.LifeID != "" && (reservation.Target.LifeID != previous.LifeID || reservation.Target.Run != previous.Run+1 ||
			reservation.BaseGeneration != previous.Generation || reservation.CancellationEpoch != previous.CancellationEpoch ||
			reservation.PreviousLaunchID != previous.LaunchID ||
			reservation.ParentLifeID != previous.ParentLifeID || reservation.RootLifeID != previous.RootLifeID ||
			reservation.StarterEventSeq != previous.StarterEventSeq || !reflect.DeepEqual(reservation.StarterChain, previous.StarterChain)) {
		return api.Operation{}, integrity("store returned a foreign launch reservation")
	}
	retained, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if !receiptMatches(scope, key, retained) || retained.Operation.ID != reservation.OperationID ||
		!bytes.Equal(retained.RawRequest, receipt.RawRequest) || retained.Reply == nil {
		return api.Operation{}, integrity("reserved launch lost its exact pending operation reply")
	}
	if retained.Reply.Error != nil {
		return api.Operation{}, retained.Reply.Error
	}
	var operation api.Operation
	if api.DecodeObject(retained.Reply.Result, &operation) != nil ||
		operation.ID != reservation.OperationID || operation.Status != "pending" || operation.Error != nil ||
		operation.LifeID != reservation.Target.LifeID || operation.Run != reservation.Target.Run {
		return api.Operation{}, integrity("reserved launch has no correlated pending operation")
	}
	return operation, nil
}

func (s *Service) launchAuthority(ctx context.Context, scope api.Scope, previous api.Lane) ([]api.TransactionGuard, api.LaunchAuthority, error) {
	guards := []api.TransactionGuard{}
	if previous.LifeID != "" {
		guards = append(guards, api.TransactionGuard{Cancellation: &api.CancellationCheck{LifeID: previous.LifeID, Epoch: previous.CancellationEpoch}})
	}
	if scope.Actor.Kind == "lane" {
		if scope.Request.Proof != nil {
			return nil, api.LaunchAuthority{}, problem(api.CodeForbidden, "lane reservation cannot carry human proof", "Use its authentic current starter binding.")
		}
		return guards, api.LaunchAuthority{Kind: "starter", ID: scope.LaunchID}, nil
	}
	if scope.Actor.Kind != "human" {
		return nil, api.LaunchAuthority{}, problem(api.CodeForbidden, "public reservation requires an authenticated human or lane", "Use the original authorized endpoint.")
	}
	if previous.LifeID == "" {
		var id api.ID
		if scope.Request.Method == "lane.start" {
			var request api.StartRequest
			if err := api.DecodeObject(scope.Request.Params, &request); err != nil {
				return nil, api.LaunchAuthority{}, failure(err)
			}
			id = request.RootTicketID
		} else {
			var request api.AdoptRequest
			if err := api.DecodeObject(scope.Request.Params, &request); err != nil {
				return nil, api.LaunchAuthority{}, failure(err)
			}
			id = request.RootTicketID
		}
		ticket, err := s.deps.Store.Ticket(ctx, scope, id)
		if err != nil {
			return nil, api.LaunchAuthority{}, failure(err)
		}
		guards = append(guards, api.TransactionGuard{Ticket: &api.TicketUse{TicketID: ticket.ID, PrincipalID: ticket.PrincipalID, Config: ticket.Config,
			EndpointGeneration: ticket.EndpointGeneration, Level: ticket.Level, Role: ticket.Role, GrantSetID: ticket.GrantSetID}})
		return guards, api.LaunchAuthority{Kind: "ticket", ID: id}, nil
	}
	if scope.Request.Proof == nil {
		return nil, api.LaunchAuthority{}, problem(api.CodeForbidden, "retained human launch requires its operation proof", "Confirm the exact request and base generation.")
	}
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return nil, api.LaunchAuthority{}, failure(err)
	}
	if target.Method != scope.Request.Method || target.TargetID != previous.LifeID || target.BaseGeneration != previous.Generation || target.RequestSHA256 != scope.Request.RequestSHA256 {
		return nil, api.LaunchAuthority{}, integrity("retained launch proof target changed")
	}
	guards = append(guards, api.TransactionGuard{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}})
	return guards, api.LaunchAuthority{Kind: "proof", ID: scope.Request.Proof.ID}, nil
}

func reservationPins(request api.Request, previous api.Lane, reservation api.LaunchReservation) bool {
	if previous.LifeID != "" {
		return reservation.Level == previous.Level && reservation.Role == previous.Role && reservation.Driver == previous.Session.Driver
	}
	if request.Method == "lane.start" {
		var value api.StartRequest
		return api.DecodeObject(request.Params, &value) == nil && reservation.Level == value.Level && reservation.Role == value.Role && reservation.Driver == value.Driver
	}
	var value api.AdoptRequest
	return api.DecodeObject(request.Params, &value) == nil && reservation.Level == value.Level && reservation.Role == value.Role && reservation.Driver == value.Driver
}
