package lifecycle

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) LaneLoop(ctx context.Context, scope api.Scope,
	request api.LoopRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.loop", request); err != nil {
		return api.Operation{}, err
	}
	if request.BackoffMS < 1 || request.BackoffMS > int64(maxInteger) ||
		request.Enabled && request.IdleMessage == nil {
		return api.Operation{}, invalid("loop requires explicit backoff and idle input")
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.Operation{}, err
	}
	if result, found, err := s.staleReplay(ctx, scope, lane, request.ExpectedGeneration); found {
		return result, err
	}
	if lane.Cleaned || lane.State == "merged" || lane.State == "abandoned" || lane.Run != request.Target.Run {
		return api.Operation{}, problem(api.CodeConflict, "loop target is no longer eligible",
			"Read the current life and retain its exact generation.")
	}
	if request.IdleMessage != nil {
		if !validBlob(*request.IdleMessage) || request.IdleMessage.Class != "task" {
			return api.Operation{}, invalid("invalid loop idle input")
		}
		if _, err := s.readBlob(ctx, scope, *request.IdleMessage); err != nil {
			return api.Operation{}, err
		}
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if scope.PolicyGeneration != policy.Generation || !validGeneration(policy.Generation) {
		return api.Operation{}, problem(api.CodeConflict, "loop policy context is stale", "Reload current authority before changing a schedule.")
	}
	event, err := s.event(scope, lane, "lane.loop", request, scope.Actor)
	if err != nil {
		return api.Operation{}, err
	}
	return s.transact(ctx, scope, lane, []api.Event{event}, nil)
}

func (s *Service) LaneAttach(ctx context.Context, scope api.Scope,
	request api.AttachRequest) (api.StreamFrame, error) {
	stream, err := s.newAttach(ctx, scope, request)
	if err != nil {
		return api.StreamFrame{}, err
	}
	frame, nextErr := stream.Next(ctx)
	closeErr := stream.Close()
	if nextErr != nil {
		return api.StreamFrame{}, failure(nextErr)
	}
	if closeErr != nil {
		return api.StreamFrame{}, failure(closeErr)
	}
	return frame, nil
}

func (s *Service) OpenAttach(ctx context.Context, scope api.Scope,
	request api.AttachRequest) (api.EventStream, error) {
	stream, err := s.newAttach(ctx, scope, request)
	if err != nil {
		return nil, err
	}
	if scope.ReadView != nil {
		// The handler already returned the same pinned binding snapshot in
		// ResponseStream.Initial. Live frame indexing begins separately at 1.
		if _, err := stream.Next(ctx); err != nil {
			stream.Close()
			return nil, err
		}
		stream.index = 0
	}
	stream.scope.ReadView = nil
	return stream, nil
}

func (s *Service) LaneInput(ctx context.Context, scope api.Scope,
	request api.AttachInputRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.input", request); err != nil {
		return api.Operation{}, err
	}
	if !validID(request.ChannelID) || len(request.Input) > api.MaxChunkBytes ||
		len(request.Input) == 0 && (request.Columns == 0 || request.Rows == 0) ||
		(request.Columns == 0) != (request.Rows == 0) {
		return api.Operation{}, invalid("invalid bounded input or terminal dimensions")
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.Operation{}, err
	}
	if result, found, err := replayReply[api.Operation](s, ctx, scope); found || err != nil {
		return result, err
	}
	if lane.Cleaned || lane.Run != request.Target.Run || lane.State != "running" {
		return api.Operation{}, problem(api.CodeConflict, "input target is not running",
			"Attach to the current live run before submitting input.")
	}
	observation, facts, err := s.observe(ctx, scope, lane, request.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if observation.State != "running" || observation.Survivors == nil || *observation.Survivors == 0 {
		return api.Operation{}, problem(api.CodeConflict, "input process is no longer running", "Attach to the current observed run.")
	}
	control, err := s.inputControl()
	if err != nil {
		return api.Operation{}, err
	}
	pending, err := s.pendingMutation(ctx, scope)
	if err != nil {
		return api.Operation{}, err
	}
	intent := InputIntent{Request: request, OperationID: pending.Operation.ID, RequestID: scope.Request.RequestID,
		RequestSHA256: scope.Request.RequestSHA256, RequestedBy: scope.Actor, LaunchID: lane.LaunchID,
		ExpectedGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch}
	job, err := control.PlanInput(ctx, scope, intent)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if err := s.validateInputJob(ctx, scope, control, lane, facts.handle, intent, job); err != nil {
		return api.Operation{}, err
	}
	commit, err := s.commitLifecycle(ctx, scope, lane, nil,
		[]api.Effect{{ID: job.Lease.EffectID, Worker: &job.Plan}}, job.Lease)
	if err != nil {
		return api.Operation{}, err
	}
	var operation api.Operation
	if commit.Reply == nil || api.DecodeObject(commit.Reply.Result, &operation) != nil || operation.ID != intent.OperationID ||
		operation.LifeID != lane.LifeID || operation.Run != lane.Run || operation.Status != "pending" {
		return api.Operation{}, integrity("input mutation lost its original pending worker reply")
	}
	return operation, nil
}
