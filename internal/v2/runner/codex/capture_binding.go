package codex

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type captureSource struct {
	state       api.CaptureState
	position    api.CapturePosition
	plan        api.LaunchPlan
	boundSeq    api.Sequence
	identitySeq api.Sequence
}

func (s *Service) captureSource(ctx context.Context, record api.CaptureRecord, lane api.Lane, events []api.Event) (captureSource, error) {
	var empty captureSource
	if !id(record.BindingID) {
		return empty, problem(api.CodeIntegrity, "Codex capture has no registered binding ID")
	}
	state, err := s.deps.Store.CaptureState(ctx, s.deps.ReadScope, record.BindingID)
	if err != nil {
		return empty, dependencyError(err)
	}
	binding := state.Binding
	policy, err := s.deps.Store.Policy(ctx, s.deps.ReadScope)
	if err != nil {
		return empty, dependencyError(err)
	}
	dispositionErr := captureDisposition(state, record, lane, s.deps.ReadScope.Config, policy)
	if dispositionErr != nil && dispositionErr != binding.Refusal {
		return empty, dispositionErr
	}
	retained, err := s.retainedLaunch(ctx, binding.LaunchID)
	if err != nil {
		return empty, err
	}
	plan := *retained.Plan
	if !reflect.DeepEqual(plan.Capture, binding) || plan.Reservation.ID != binding.ReservationID ||
		plan.Reservation.Target != record.Target || plan.Runner.Driver != api.DriverCodex ||
		plan.Runner.Executable != s.deps.Runtime.Executable || plan.Runner.Session.ID != lane.Session.ID {
		return empty, problem(api.CodeIntegrity, "Codex capture differs from the retained runner plan")
	}
	if _, err := api.PolicyGenerationFor(api.PolicyExactReplay, policy.Generation, plan.Reservation.PolicyGeneration); err != nil {
		return empty, dependencyError(err)
	}
	if err := s.retainedGrants(ctx, plan.Reservation, plan.Inputs.Grants); err != nil {
		return empty, err
	}
	// A qualified refusal still needs the exact retained plan and policy
	// snapshot. It never establishes a primary session, limit or continuation.
	if dispositionErr != nil {
		return empty, dispositionErr
	}
	storage, err := s.launchStorage(ctx, plan.Reservation, plan.Lease)
	if err != nil {
		return empty, err
	}
	if storage.Home != plan.Data.Home || storage.WorkspaceID != plan.Data.Workspace.ID {
		return empty, problem(api.CodeIntegrity, "Codex capture private storage changed after launch")
	}
	bound, err := s.deps.Store.LaunchBinding(ctx, binding.LaunchID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if err := api.ValidateLaunchBindingPlan(bound, plan); err != nil {
		return empty, dependencyError(err)
	}
	var boundSeq api.Sequence
	identity := false
	for _, event := range events {
		if event.Kind != "capture.bound" && event.Kind != "capture.refused" && event.Kind != "identity.bound" {
			continue
		}
		if event.OperationID != binding.OperationID || event.RequestID != binding.RequestID || event.RequestedBy != binding.RequestedBy {
			return empty, problem(api.CodeIntegrity, "Codex capture binding event changed its original cause")
		}
		if event.Kind == "identity.bound" {
			var value api.LaunchRecord
			if decode(event.Payload, &value) != nil || !reflect.DeepEqual(value, bound.Record) || event.ID != bound.Identity.EventID || event.Seq != bound.Identity.CommittedSeq {
				return empty, problem(api.CodeIntegrity, "Codex identity binding has no matching committed event")
			}
			identity = true
			continue
		}
		var value api.CaptureBinding
		if decode(event.Payload, &value) != nil || !reflect.DeepEqual(value, binding) || event.Kind != "capture.bound" || boundSeq != 0 {
			return empty, problem(api.CodeIntegrity, "Codex capture has no unique committed registration")
		}
		boundSeq = event.Seq
	}
	if boundSeq == 0 || !identity {
		return empty, problem(api.CodeIntegrity, "Codex capture or identity registration is uncommitted")
	}
	var streamID api.ID
	for _, stream := range binding.Streams {
		if stream.Stream == record.Stream {
			streamID = stream.ID
		}
	}
	if streamID == "" {
		return empty, problem(api.CodeIntegrity, "Codex output is not a registered capture stream")
	}
	var position api.CapturePosition
	found := false
	for _, candidate := range state.Positions {
		if candidate.StreamID == streamID {
			if found || candidate.NextOffset < 0 || candidate.NextOffset > 1<<53-1 {
				return empty, problem(api.CodeIntegrity, "Codex capture has ambiguous committed offsets")
			}
			position, found = candidate, true
		}
	}
	if !found {
		return empty, problem(api.CodeIntegrity, "Codex capture stream has no retained position")
	}
	return captureSource{state: state, position: position, plan: plan, boundSeq: boundSeq, identitySeq: bound.Identity.CommittedSeq}, nil
}

func captureDisposition(state api.CaptureState, record api.CaptureRecord, lane api.Lane, config string, policy api.EffectivePolicy) error {
	binding := state.Binding
	if err := api.ValidateCaptureBinding(binding); err != nil {
		return dependencyError(err)
	}
	if binding.ID != record.BindingID || binding.Config != config || binding.Target != record.Target ||
		binding.LaunchID != lane.LaunchID {
		return problem(api.CodeIntegrity, "Codex capture state differs from its launch binding")
	}
	if binding.Status == "refused" {
		if err := api.ValidateCapturePolicy(binding, policy); err != nil {
			return dependencyError(err)
		}
		return binding.Refusal
	}
	if state.Generation < binding.Generation || state.LastSeq == 0 {
		return problem(api.CodeIntegrity, "Codex capture has no committed state revision")
	}
	return nil
}

func captureCause(event api.Event, source captureSource) bool {
	b := source.state.Binding
	return event.OperationID == b.OperationID && event.RequestID == b.RequestID && event.RequestedBy == b.RequestedBy &&
		event.Seq > source.boundSeq && event.Seq > source.identitySeq && event.Seq <= source.state.LastSeq
}

func captureDrained(source captureSource, events []api.Event, size int64) bool {
	if !source.position.EOF || source.position.NextOffset != size {
		return false
	}
	for _, event := range events {
		if event.Kind != "capture.closed" || !captureCause(event, source) {
			continue
		}
		var receipt api.CaptureAppendReceipt
		if decode(event.Payload, &receipt) == nil && receipt.BindingID == source.state.Binding.ID &&
			receipt.StreamID == source.position.StreamID && receipt.EOF && receipt.Offset == size && receipt.NextOffset == size &&
			receipt.Generation <= source.state.Generation && receipt.LastSeq == event.Seq {
			return true
		}
	}
	return false
}
