package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type runFacts struct {
	launchID       api.ID
	leaseID        api.ID
	handle         api.ProcessHandle
	observation    *api.ProcessObservation
	end            *api.RunEndEvent
	endSeq         api.Sequence
	endID          api.ID
	captureRefused *api.CaptureBinding
}

func (s *Service) walkEvents(ctx context.Context, scope api.Scope,
	lane api.Lane, target api.LifeRef, visit func(api.Event) error) error {
	query := api.EventTailRequest{LifeID: target.LifeID, Run: target.Run}
	for {
		if err := ctx.Err(); err != nil {
			return failure(err)
		}
		page, err := s.eventPage(ctx, scope, lane, query)
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if err := visit(event); err != nil {
				return err
			}
		}
		if page.Complete {
			return nil
		}
		if page.Cursor == "" || page.Cursor == query.Cursor {
			return integrity("event history cursor did not advance")
		}
		query.Cursor = page.Cursor
	}
}

func (s *Service) facts(ctx context.Context, scope api.Scope,
	lane api.Lane, target api.LifeRef) (runFacts, error) {
	var facts runFacts
	err := s.walkEvents(ctx, scope, lane, target, func(event api.Event) error {
		switch event.Kind {
		case "capture.refused":
			var capture api.CaptureBinding
			if decode(event.Payload, &capture) != nil || api.ValidateCaptureBinding(capture) != nil ||
				capture.Status != "refused" || capture.Config != scope.Config || capture.Target != target {
				return integrity("invalid recorded capture refusal")
			}
			facts.captureRefused = &capture
		case "lane.started", "lane.resumed", "launch.prepared":
			var launch api.LaunchEvent
			if err := decode(event.Payload, &launch); err != nil {
				return integrity("invalid recorded launch")
			}
			facts.launchID = launch.LaunchID
		case "identity.bound":
			var record api.LaunchRecord
			if err := decode(event.Payload, &record); err != nil {
				return integrity("invalid recorded launch binding")
			}
			// Only the agent's binding is the run's launch: a worker bound for the same life afterwards (lane
			// archive's worker, box 101: lane clean refused "process handle does not match its launch binding")
			// must not replace it.
			if record.Kind != "worker" {
				facts.launchID = record.ID
			}
		case "run.observed":
			var observation api.ProcessObservation
			if err := decode(event.Payload, &observation); err != nil {
				return integrity("invalid recorded process observation")
			}
			facts.handle = observation.Handle
			facts.observation = &observation
		case "lane.ended", "lane.lost":
			var end api.RunEndEvent
			if err := decode(event.Payload, &end); err != nil {
				return integrity("invalid recorded run end")
			}
			facts.launchID = end.LaunchID
			facts.handle = end.Observation.Handle
			facts.observation = &end.Observation
			if event.Kind == "lane.ended" {
				facts.end, facts.endSeq = &end, event.Seq
				facts.endID = event.ID
			} else {
				facts.end, facts.endSeq = nil, 0
			}
		}
		return nil
	})
	if err != nil {
		return runFacts{}, err
	}
	if !validID(facts.launchID) || !validID(facts.handle.ID) ||
		facts.handle.Target != target {
		return runFacts{}, problem(api.CodeContainmentUnknown,
			"run has no durable verified process handle",
			"Retain the leases and reconcile through the trusted supervisor.")
	}
	record, err := s.deps.Store.Launch(ctx, facts.launchID)
	if err != nil {
		return runFacts{}, failure(err)
	}
	if record.ID != facts.launchID || record.Config != scope.Config ||
		record.Target != target || record.ContainmentID != facts.handle.ContainmentID ||
		record.ProcessGeneration != facts.handle.Generation ||
		!validID(record.ContainmentID) || record.ProcessGeneration == "" ||
		record.ParentLifeID != lane.ParentLifeID || record.RootLifeID != lane.RootLifeID ||
		!reflect.DeepEqual(record.StarterChain, lane.StarterChain) ||
		record.StarterEventSeq != lane.StarterEventSeq {
		return runFacts{}, integrity("process handle does not match its launch binding")
	}
	if facts.captureRefused != nil && facts.captureRefused.LaunchID != record.ID {
		return runFacts{}, integrity("capture refusal belongs to another launch")
	}
	facts.leaseID = record.UIDLeaseID
	return facts, nil
}

func requireReviewCapture(facts runFacts) error {
	if facts.captureRefused != nil {
		return problem(api.CodeUnsupported, "run has explicitly refused capture",
			"Keep its incomplete evidence visible; review and acceptance require verified capture coverage.")
	}
	return nil
}

func validateObservation(handle api.ProcessHandle, observed api.ProcessObservation) error {
	if !validID(handle.ID) || !validTarget(handle.Target) || !validID(handle.ContainmentID) || handle.Generation == "" ||
		observed.Handle != handle || !validTime(observed.ObservedAt) {
		return integrity("process observation has a different identity or invalid time")
	}
	switch observed.PromptStatus {
	case "not_written", "written", "cut", "unknown", "completed":
	default:
		return integrity("unknown prompt observation status")
	}
	switch observed.State {
	case "unknown":
		if observed.Survivors != nil || observed.ExitCode != nil || observed.Signal != nil {
			return integrity("unknown containment claimed a terminal result")
		}
	case "prepared", "running":
		if observed.Survivors == nil || observed.ExitCode != nil || observed.Signal != nil {
			return integrity("incomplete live process observation")
		}
	case "exited":
		if observed.Survivors == nil || (observed.ExitCode == nil) == (observed.Signal == nil) {
			return integrity("incomplete terminal process observation")
		}
	default:
		return integrity("unknown process observation state")
	}
	if observed.ExitCode != nil && (*observed.ExitCode < -2147483648 ||
		*observed.ExitCode > 2147483647) || observed.Signal != nil &&
		(*observed.Signal < 0 || *observed.Signal > 2147483647) {
		return integrity("terminal process result outside signed range")
	}
	return nil
}

func (s *Service) observe(ctx context.Context, scope api.Scope, lane api.Lane,
	target api.LifeRef) (api.ProcessObservation, runFacts, error) {
	if absent(s.deps.Launcher) {
		return api.ProcessObservation{}, runFacts{},
			api.NotImplemented("lb-v2-linux", "Launcher.Observe")
	}
	facts, err := s.facts(ctx, scope, lane, target)
	if err != nil {
		return api.ProcessObservation{}, runFacts{}, err
	}
	observed, err := s.deps.Launcher.Observe(ctx, facts.handle)
	if err != nil {
		return api.ProcessObservation{}, runFacts{}, failure(err)
	}
	if err := validateObservation(facts.handle, observed); err != nil {
		return api.ProcessObservation{}, runFacts{}, err
	}
	// A fresh native census may have a later timestamp for identical process
	// facts. Use the retained measurement's exact bytes for the durable check
	// reply; the fresh census above must still agree on every process fact.
	if facts.observation != nil && sameProcessObservation(*facts.observation, observed) {
		observed = *facts.observation
	}
	return observed, facts, nil
}

func requireQuiescence(observed api.ProcessObservation) error {
	if observed.State == "unknown" || observed.Survivors == nil {
		return problem(api.CodeContainmentUnknown, "containment is unknown",
			"Retain every lease and reconcile the actual containment.")
	}
	if observed.State != "exited" || *observed.Survivors != 0 {
		return problem(api.CodeConflict, "run still has writers or survivors",
			"Stop the run and verify actual quiescence before continuing.")
	}
	return nil
}

func (s *Service) LaneCheck(ctx context.Context, scope api.Scope,
	request api.LifeRef) (api.ProcessObservation, error) {
	if err := s.authorize(ctx, scope, "lane.check", request); err != nil {
		return api.ProcessObservation{}, err
	}
	unlock, err := s.lockLife(ctx, request.LifeID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, request, false)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if reply, found, err := s.lookupReply(ctx, scope); found || err != nil {
		if err != nil {
			return api.ProcessObservation{}, err
		}
		var observed api.ProcessObservation
		if api.DecodeObject(reply.Result, &observed) != nil || observed.Handle.Target != request ||
			validateObservation(observed.Handle, observed) != nil {
			return api.ProcessObservation{}, integrity("stored observation reply is invalid")
		}
		return observed, nil
	}
	if lane.Cleaned || lane.Run != request.Run {
		return api.ProcessObservation{}, problem(api.CodeConflict, "life is cleaned or run is not current",
			"Read its retained history; do not reuse its old process lease.")
	}
	observed, facts, err := s.observe(ctx, scope, lane, request)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	event, err := s.event(scope, lane, "run.observed", observed,
		api.Actor{Kind: "service", ID: "lifecycle"})
	if err != nil {
		return api.ProcessObservation{}, err
	}
	event.ObservedAt = observed.ObservedAt
	events := []api.Event{event}
	effects := []api.Effect{}
	if observed.State == "exited" && facts.end == nil {
		if err := requireQuiescence(observed); err != nil {
			return api.ProcessObservation{}, err
		}
		if lane.Generation == api.Generation(maxInteger) {
			return api.ProcessObservation{}, integrity("life generation exhausted")
		}
		// A run that ends after the committed stop intent ended by stop (v2-contracts.md:465).
		reason := "exit"
		if lane.State == "stopping" {
			reason = "stop"
		}
		ended, err := s.event(scope, lane, "lane.ended", api.RunEndEvent{
			LaunchID: facts.launchID, Reason: reason, Observation: observed,
			BudgetRemaining: lane.BudgetRemaining}, api.Actor{Kind: "service", ID: "lifecycle"})
		if err != nil {
			return api.ProcessObservation{}, err
		}
		ended.ObservedAt = observed.ObservedAt
		state, err := s.event(scope, lane, "lane.state", api.StateEvent{
			From: lane.State, To: "verifying", Generation: lane.Generation + 1}, api.Actor{Kind: "service", ID: "lifecycle"})
		if err != nil {
			return api.ProcessObservation{}, err
		}
		state.ObservedAt = observed.ObservedAt
		events = append(events, ended, state)
		release, err := runRelease(facts, observed)
		if err != nil {
			return api.ProcessObservation{}, err
		}
		effects = append(effects, release)
	}
	commit, err := s.commitLifecycle(ctx, scope, lane, events, effects)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	var result api.ProcessObservation
	if api.DecodeObject(commit.Reply.Result, &result) != nil {
		return api.ProcessObservation{}, integrity("committed observation reply is invalid")
	}
	return result, nil
}

// The dispatcher checks replay before module preflight. Direct internal callers
// also retain the exact typed receipt, including errors, after authorization.
func (s *Service) lookupReply(ctx context.Context, scope api.Scope) (*api.RPCReply, bool, error) {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey,
		RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed != nil && typed.Code == api.CodeNotFound {
			return nil, false, nil
		}
		return nil, false, failure(err)
	}
	if !receiptMatches(scope, key, receipt) {
		return nil, true, integrity("stored receipt differs from its authenticated request")
	}
	if receipt.Reply == nil {
		owned, err := s.ownsMutation(ctx, scope, key, receipt)
		if err != nil {
			return nil, true, err
		}
		if owned {
			return nil, false, nil
		}
		receipt, err = s.deps.Store.AwaitReceipt(ctx, scope, key)
		if err != nil {
			return nil, true, failure(err)
		}
		if !receiptMatches(scope, key, receipt) {
			return nil, true, integrity("stored receipt differs from its authenticated request")
		}
	}
	if receipt.Reply == nil {
		return nil, true, problem(api.CodeUnavailable, "mutation receipt is still pending",
			"Await the original durable operation without submitting another effect.")
	}
	if (receipt.Reply.Error == nil) == (len(receipt.Reply.Result) == 0) {
		return nil, true, integrity("stored receipt differs from its authenticated request")
	}
	if err := s.receiptPolicy(ctx, scope, receipt); err != nil {
		return nil, true, err
	}
	if receipt.Reply.Error != nil {
		return nil, true, receipt.Reply.Error
	}
	return receipt.Reply, true, nil
}

func receiptMatches(scope api.Scope, key api.RequestKey, receipt api.MutationReceipt) bool {
	return receipt.Config == scope.Config && receipt.Key == key &&
		receipt.Actor == scope.Actor
}

func replayReply[T any](s *Service, ctx context.Context, scope api.Scope) (T, bool, error) {
	var result T
	reply, found, err := s.lookupReply(ctx, scope)
	if err != nil || !found {
		return result, found, err
	}
	if api.DecodeObject(reply.Result, &result) != nil {
		return result, true, integrity("stored lifecycle reply has the wrong result type")
	}
	switch value := any(result).(type) {
	case api.Operation:
		if !validID(value.ID) || !validTarget(api.LifeRef{LifeID: value.LifeID, Run: value.Run}) ||
			!replyTarget(scope.Request, api.LifeRef{LifeID: value.LifeID, Run: value.Run}) {
			return result, true, integrity("stored lifecycle operation is invalid")
		}
	case api.ReviewReceipt:
		if !validID(value.ID) || value.Reviewer != scope.Actor || !reviewCoverage(value.Coverage) {
			return result, true, integrity("stored review reply is invalid")
		}
	case api.ArchiveReceipt:
		if !validID(value.ID) || !validID(value.LifeID) || !validBlob(value.Manifest) ||
			!validID(value.StoreID) || value.Manifest.Class != "manifest" || !validTime(value.VerifiedAt) ||
			!validDigest(value.ArchiveSHA256) || value.ArchiveSHA256 != value.ReadBackSHA256 || !replyLife(scope.Request, value.LifeID) {
			return result, true, integrity("stored archive reply is invalid")
		}
	}
	return result, true, nil
}

func replyLife(request api.Request, life api.ID) bool {
	var selector struct {
		Target api.LifeRef `json:"target"`
	}
	return json.Unmarshal(request.Params, &selector) == nil && selector.Target.LifeID == life
}

func replyTarget(request api.Request, target api.LifeRef) bool {
	var selector struct {
		Target api.LifeRef `json:"target"`
	}
	return json.Unmarshal(request.Params, &selector) == nil && selector.Target == target
}

func (s *Service) staleReplay(ctx context.Context, scope api.Scope,
	lane api.Lane, expected api.Generation) (api.Operation, bool, error) {
	if uint64(expected) > maxInteger || expected == 0 {
		return api.Operation{}, true, invalid("invalid expected life generation")
	}
	reply, found, err := s.lookupReply(ctx, scope)
	if err != nil {
		return api.Operation{}, true, err
	}
	if !found {
		if expected == lane.Generation {
			return api.Operation{}, false, nil
		}
		return api.Operation{}, true, problem(api.CodeConflict, "life generation changed",
			"Read current state; retain the original key for an existing operation.")
	}
	var operation api.Operation
	if api.DecodeObject(reply.Result, &operation) != nil || !validID(operation.ID) ||
		operation.LifeID != lane.LifeID || operation.Run == 0 || operation.Run > lane.Run ||
		!replyTarget(scope.Request, api.LifeRef{LifeID: operation.LifeID, Run: operation.Run}) {
		return api.Operation{}, true, integrity("stored lifecycle reply is invalid")
	}
	return operation, true, nil
}

func (s *Service) LaneStop(ctx context.Context, scope api.Scope,
	request api.StopRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.stop", request); err != nil {
		return api.Operation{}, err
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
	if operation, done, err := s.staleReplay(ctx, scope, lane,
		request.ExpectedGeneration); done {
		return operation, err
	}
	terminal := lane.State == "verifying" || lane.State == "accepted"
	if lane.Cleaned || lane.Run != request.Target.Run || !terminal &&
		(lane.State != "running" && lane.State != "preparing" && lane.State != "lost" &&
			lane.State != "profile_wait") {
		return api.Operation{}, problem(api.CodeConflict, "life cannot enter stopping",
			"Read the current life and inspect its retained run outcome.")
	}
	if !validBlob(request.Reason) || request.Reason.Class != "task" {
		return api.Operation{}, invalid("stop requires a retained reason object")
	}
	if _, err := s.readBlob(ctx, scope, request.Reason); err != nil {
		return api.Operation{}, err
	}
	facts, err := s.facts(ctx, scope, lane, request.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if terminal {
		if facts.end == nil || facts.endSeq == 0 || !validID(facts.endID) || facts.end.Reason == "service_lost" ||
			facts.launchID != lane.LaunchID || lane.Containment != "quiescent" {
			return api.Operation{}, problem(api.CodeConflict, "stop requires the committed current run end",
				"Reconcile the original run before retrying its stop.")
		}
		if err := requireQuiescence(facts.end.Observation); err != nil {
			return api.Operation{}, err
		}
		if err := validateObservation(facts.handle, facts.end.Observation); err != nil {
			return api.Operation{}, err
		}
		return s.transact(ctx, scope, lane, nil, nil, api.StopResult{State: lane.State,
			EndEventID: facts.endID, EndSequence: facts.endSeq, End: *facts.end})
	}
	if lane.Generation == api.Generation(maxInteger) {
		return api.Operation{}, integrity("life generation exhausted")
	}
	event, err := s.event(scope, lane, "lane.stopping", api.StateEvent{
		From: lane.State, To: "stopping", Generation: lane.Generation + 1,
		Reason: &request.Reason}, scope.Actor)
	if err != nil {
		return api.Operation{}, err
	}
	effectID, err := newID()
	if err != nil {
		return api.Operation{}, err
	}
	// This is an intent, not a completed stop. The outbox must reconcile the
	// containment, capture drain and endpoint revocation before a lane end.
	return s.transact(ctx, scope, lane, []api.Event{event},
		[]api.Effect{{ID: effectID, Stop: &facts.handle}})
}
