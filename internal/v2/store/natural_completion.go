package store

import (
	"context"
	"database/sql"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) validateNaturalCompletion(ctx context.Context, db queryer, input api.Transaction) error {
	if input.Scope.Request.Method != "lane.check" {
		return nil
	}
	if len(input.Writes.Lanes) == 0 {
		if len(input.Effects) != 0 {
			return fault(api.CodeForbidden, "run release requires its atomic measured end")
		}
		if len(input.Events) == 0 {
			return nil // A retained error reply publishes no observation.
		}
		if len(input.Events) != 1 || input.Events[0].Kind != "run.observed" {
			return fault(api.CodeForbidden, "natural completion cannot emit state without the current lane write")
		}
		var target api.LifeRef
		var lane api.Lane
		var retained struct {
			Observation api.ProcessObservation
			Generation  api.Generation
		}
		var observation api.ProcessObservation
		if err := wire.Decode(input.Scope.Request.Params, &target); err != nil {
			return err
		}
		if err := storedProjection(ctx, db, "lane", target.LifeID, &lane); err != nil {
			return err
		}
		if err := storedProjection(ctx, db, "launch_observation", lane.LaunchID, &retained); err != nil {
			return err
		}
		if err := wire.Decode(input.Events[0].Payload, &observation); err != nil {
			return err
		}
		// The same conditions, named so a refusal says which one failed (item 1 diagnosis, box 98).
		for _, c := range []struct {
			name string
			bad  bool
		}{
			{"run", lane.Run != target.Run}, {"cleaned", lane.Cleaned},
			{"event_target", input.Events[0].LifeID != target.LifeID || input.Events[0].Run != target.Run},
			{"handle_target", observation.Handle.Target != target},
			{"observation", !sameValue(observation, retained.Observation) && !sameRunningProcess(observation, retained.Observation)},
			{"controller", input.Scope.Actor.Kind == "lane" && input.Scope.Actor.LifeID != lane.LifeID && !slices.Contains(lane.StarterChain, input.Scope.Actor.LifeID)},
		} {
			if c.bad {
				return fault(api.CodeForbidden, "check observation differs from its retained native run or controller ("+c.name+")")
			}
		}
		return nil
	}
	if len(input.Writes.Lanes) != 1 {
		return fault(api.CodeForbidden, "natural completion requires one current life")
	}
	next := input.Writes.Lanes[0]
	var before api.Lane
	var observed struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	if err := storedProjection(ctx, db, "lane", next.LifeID, &before); err != nil {
		return err
	}
	var target api.LifeRef
	if err := wire.Decode(input.Scope.Request.Params, &target); err != nil {
		return err
	}
	if target != (api.LifeRef{LifeID: before.LifeID, Run: before.Run}) {
		return fault(api.CodeForbidden, "lane.check changed its authenticated target")
	}
	if input.Scope.Actor.Kind == "lane" && input.Scope.Actor.LifeID != before.LifeID && !slices.Contains(before.StarterChain, input.Scope.Actor.LifeID) {
		return fault(api.CodeForbidden, "lane.check caller is not the retained life controller")
	}
	if err := storedProjection(ctx, db, "launch_observation", before.LaunchID, &observed); err != nil {
		return err
	}
	if observed.Observation.State != "exited" || observed.Observation.Survivors == nil || *observed.Observation.Survivors != 0 || observed.Observation.Handle.Target != (api.LifeRef{LifeID: before.LifeID, Run: before.Run}) {
		return fault(api.CodeContainmentUnknown, "natural completion lacks the actual zero-survivor observation")
	}
	want := before
	want.Generation++
	want.State = "verifying"
	want.Containment = "quiescent"
	want.LastSeq = next.LastSeq
	if !sameValue(want, next) {
		return fault(api.CodeForbidden, "natural completion changed unrelated life state")
	}
	cas, epoch, ended, state := false, false, false, false
	endReason := "exit"
	if before.State == "stopping" {
		endReason = "stop"
	}
	for _, compare := range input.Compare {
		cas = cas || compare.Kind == api.CompareLane && compare.ID == before.LifeID && compare.Generation == before.Generation
	}
	for _, guard := range input.Guards {
		epoch = epoch || guard.Cancellation != nil && guard.Cancellation.LifeID == before.LifeID && guard.Cancellation.Epoch == before.CancellationEpoch
	}
	for _, event := range input.Events {
		if event.LifeID != before.LifeID || event.Run != before.Run {
			return fault(api.CodeForbidden, "natural completion event belongs to another run")
		}
		switch event.Kind {
		case "lane.ended":
			var end api.RunEndEvent
			if err := wire.Decode(event.Payload, &end); err != nil {
				return err
			}
			ended = ended || end.LaunchID == before.LaunchID && end.Reason == endReason && sameValue(end.BudgetRemaining, next.BudgetRemaining) && sameValue(end.Observation, observed.Observation)
		case "lane.state":
			var change api.StateEvent
			if err := wire.Decode(event.Payload, &change); err != nil {
				return err
			}
			state = state || change.From == before.State && change.To == next.State && change.Generation == next.Generation
		}
	}
	if !cas || !epoch || !ended || !state {
		return fault(api.CodeForbidden, "natural completion lacks its life CAS epoch and measured end/state events")
	}
	if len(input.Effects) > 1 {
		return fault(api.CodeForbidden, "natural end has competing release stages")
	}
	for _, effect := range input.Effects {
		binding, err := s.launchBinding(ctx, db, before.LaunchID)
		if err != nil {
			return err
		}
		if effect.HelperRelease == nil || effect.Context == nil || effect.Context.Kind != api.InternalHelperRelease ||
			effect.Context.Target != target || effect.Context.RequestedBy != input.Scope.Actor ||
			effect.Context.CancellationEpoch != before.CancellationEpoch || effect.Context.CauseRequestID != input.Scope.Request.RequestID ||
			effect.HelperRelease.LeaseID != binding.Record.UIDLeaseID || !sameValue(effect.HelperRelease.Observation, observed.Observation) {
			return fault(api.CodeForbidden, "natural release differs from its measured run and retained lease")
		}
	}
	return nil
}

// A stop's end/release write is checked again under the actual writer lock.
// The context capability carries the exact live parent claim, never an RPC
// field or an inferred current claimant selected by life alone.
func (s *Service) validateStoppedRelease(ctx context.Context, db queryer, input api.Transaction) error {
	if input.Internal == nil || input.Internal.Kind != api.InternalLifecycleEffect {
		return nil
	}
	for _, effect := range input.Effects {
		if effect.HelperRelease == nil {
			continue
		}
		parent, err := s.launchClaim(ctx, db, input.Scope, *input.Internal)
		if err != nil {
			return err
		}
		attempt, ok := api.EffectLeaseFromContext(ctx)
		if !ok || !api.EffectLeaseClaimed(attempt) || !sameValue(attempt.Record, parent) ||
			attempt.ClaimID != parent.ClaimID || attempt.ExpiresAt != parent.ClaimExpiresAt || parent.Effect.Stop == nil {
			return fault(api.CodeConflict, "run release lost its exact live stop claim")
		}
		var saved struct {
			LaunchID api.ID
			Handle   api.ProcessHandle
		}
		if err := storedProjection(ctx, db, "launch_process", parent.Effect.Stop.ID, &saved); err != nil {
			return err
		}
		binding, err := s.launchBinding(ctx, db, saved.LaunchID)
		if err != nil {
			return err
		}
		if saved.Handle != *parent.Effect.Stop || effect.HelperRelease.Observation.Handle != saved.Handle ||
			effect.HelperRelease.LeaseID != binding.Record.UIDLeaseID || effect.Context == nil ||
			effect.Context.Target != input.Internal.Target || effect.Context.CancellationEpoch != input.Internal.CancellationEpoch ||
			effect.Context.CauseOperationID != parent.Effect.OperationID || effect.Context.CauseRequestID != parent.Effect.Context.CauseRequestID ||
			effect.Context.RequestedBy != parent.Effect.Context.RequestedBy {
			return fault(api.CodeForbidden, "run release changed its original stop process lease or cause")
		}
	}
	return nil
}

// A later terminal decision cancels execution authority, but must not strand
// physical release of the same ended run. This proves the exact retained end,
// native process and lease; a resumed/replaced/cleaned life cannot use it.
func (s *Service) endedReleaseFence(ctx context.Context, db queryer, effect api.Effect) error {
	c, request := effect.Context, effect.HelperRelease
	if c == nil || request == nil || c.Kind != api.InternalHelperRelease || c.Config != s.deps.Config {
		return fault(api.CodeForbidden, "ended release has no original helper cause")
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", c.Target.LifeID, &lane); err != nil {
		return err
	}
	if lane.Run != c.Target.Run || lane.Cleaned || lane.Containment != "quiescent" || lane.CancellationEpoch < c.CancellationEpoch ||
		lane.State != "verifying" && lane.State != "accepted" && lane.State != "merged" && lane.State != "abandoned" {
		return fault(api.CodeConflict, "release recovery has no unchanged ended current run")
	}
	binding, err := s.launchBinding(ctx, db, lane.LaunchID)
	if err != nil {
		return err
	}
	handle := request.Observation.Handle
	if binding.Record.Target != c.Target || binding.Record.UIDLeaseID != request.LeaseID ||
		binding.Record.ContainmentID != handle.ContainmentID || binding.Record.ProcessGeneration != handle.Generation ||
		request.Observation.State != "exited" || request.Observation.Survivors == nil || *request.Observation.Survivors != 0 {
		return fault(api.CodeContainmentUnknown, "release recovery changed the original helper lease or quiescence")
	}
	var saved struct {
		LaunchID api.ID
		Handle   api.ProcessHandle
	}
	if err := storedProjection(ctx, db, "launch_process", handle.ID, &saved); err != nil {
		return err
	}
	if saved.LaunchID != binding.Record.ID || saved.Handle != handle {
		return fault(api.CodeForbidden, "release recovery changed its retained native process")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind')='lane.ended' ORDER BY seq DESC LIMIT 1", string(c.Target.LifeID), uint64(c.Target.Run)).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return fault(api.CodeContainmentUnknown, "release recovery lacks its committed run end")
		}
		return err
	}
	var event api.Event
	var end api.RunEndEvent
	if err := decodeStored(raw, &event); err != nil {
		return err
	}
	if err := wire.Decode(event.Payload, &end); err != nil {
		return err
	}
	if end.LaunchID != binding.Record.ID || end.Reason == "service_lost" || !sameValue(end.Observation, request.Observation) {
		return fault(api.CodeContainmentUnknown, "release recovery disagrees with its exact measured end")
	}
	if event.Origin != "service" {
		allowAndLog("release_end_origin")
	}
	return nil
}

func (s *Service) releaseGuard(ctx context.Context, db queryer, input api.Transaction, check api.CancellationCheck) error {
	if input.Internal.Target.LifeID != check.LifeID || input.Internal.CancellationEpoch != check.Epoch {
		return fault(api.CodeForbidden, "release guard changed its original cancellation selector")
	}
	claim, err := s.launchClaim(ctx, db, input.Scope, *input.Internal)
	if err != nil {
		return err
	}
	attempt, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !api.EffectLeaseClaimed(attempt) || claim.Effect.HelperRelease == nil || !sameValue(attempt.Record, claim) ||
		attempt.ClaimID != claim.ClaimID || attempt.ExpiresAt != claim.ClaimExpiresAt {
		return fault(api.CodeConflict, "release guard requires its exact current helper attempt")
	}
	return s.checkEffectFence(ctx, db, claim.Effect)
}

// sameRunningProcess accepts a fresh census of the same still-running process: a real agent's survivor
// count and prompt state change while it works (box 98-99: the agent spawned past its launch census of
// 14 before the first lane check, so an exact match refused every check of a working agent). The
// process identity must still match exactly: same handle (launch, target, containment, generation),
// both running, no exit code or signal. Any other state still needs the exact retained bytes.
func sameRunningProcess(fresh, retained api.ProcessObservation) bool {
	return fresh.Handle == retained.Handle && fresh.State == "running" && retained.State == "running" &&
		fresh.ExitCode == nil && fresh.Signal == nil && retained.ExitCode == nil && retained.Signal == nil &&
		fresh.Survivors != nil
}
