package store

import (
	"context"
	"database/sql"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Derive the no-op stop receipt under the writer lock, independently of the
// module's proposed reply. A state label alone cannot manufacture a run end.
func (s *Service) terminalStop(ctx context.Context, db queryer, input api.Transaction) (api.StopResult, api.LifeRef, error) {
	var empty api.StopResult
	var request api.StopRequest
	if err := wire.Decode(input.Scope.Request.Params, &request); err != nil {
		return empty, api.LifeRef{}, err
	}
	target := request.Target
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", target.LifeID, &lane); err != nil {
		return empty, target, err
	}
	if lane.Cleaned || lane.Run != target.Run || lane.Generation != request.ExpectedGeneration || lane.Containment != "quiescent" ||
		lane.State != "verifying" && lane.State != "accepted" || len(input.Writes.Lanes) != 0 {
		return empty, target, fault(api.CodeConflict, "terminal stop requires the unchanged ended current life")
	}
	cas, epoch := false, false
	for _, compare := range input.Compare {
		cas = cas || compare.Kind == api.CompareLane && compare.ID == lane.LifeID && compare.Generation == lane.Generation
	}
	for _, guard := range input.Guards {
		epoch = epoch || guard.Cancellation != nil && guard.Cancellation.LifeID == lane.LifeID && guard.Cancellation.Epoch == lane.CancellationEpoch
	}
	if !cas || !epoch {
		return empty, target, fault(api.CodeForbidden, "terminal stop lost its life generation or cancellation fence")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind')='lane.ended' ORDER BY seq DESC LIMIT 1", string(target.LifeID), uint64(target.Run)).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return empty, target, fault(api.CodeConflict, "terminal stop has no committed run end")
		}
		return empty, target, err
	}
	var event api.Event
	var end api.RunEndEvent
	if err := decodeStored(raw, &event); err != nil {
		return empty, target, err
	}
	if err := wire.Decode(event.Payload, &end); err != nil {
		return empty, target, err
	}
	binding, err := s.launchBinding(ctx, db, lane.LaunchID)
	if err != nil {
		return empty, target, err
	}
	observation := end.Observation
	var current struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	if err := storedProjection(ctx, db, "launch_observation", lane.LaunchID, &current); err != nil {
		return empty, target, err
	}
	// A fresh observation of the same ended process may have a later sample
	// time. All process facts must still match the immutable committed end.
	actual, ended := current.Observation, observation
	actual.ObservedAt, ended.ObservedAt = "", ""
	if event.ID == "" || event.Seq == 0 || end.LaunchID != lane.LaunchID || end.Reason == "service_lost" ||
		observation.Handle.Target != target || binding.Record.Target != target || observation.Handle.ContainmentID != binding.Record.ContainmentID ||
		observation.Handle.Generation != binding.Record.ProcessGeneration || observation.State != "exited" ||
		observation.Survivors == nil || *observation.Survivors != 0 || (observation.ExitCode == nil) == (observation.Signal == nil) || !sameValue(actual, ended) {
		return empty, target, fault(api.CodeContainmentUnknown, "terminal stop lacks its exact committed quiescent process")
	}
	return api.StopResult{State: lane.State, EndEventID: event.ID, EndSequence: event.Seq, End: end}, target, nil
}

// The stopped end and release effect were committed atomically by the stop
// reconciler. Resolve that original writer cause rather than inventing an
// epoch from the archive caller or the presence of a credential projection.
func (s *Service) archiveStopEpoch(ctx context.Context, db queryer, event api.Event, end api.RunEndEvent, launchEpoch api.Generation) (*archivejob.StopEpoch, error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq<? AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind')='lane.stopping' ORDER BY seq DESC LIMIT 1", uint64(event.Seq), string(event.LifeID), uint64(event.Run)).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fault(api.CodeConflict, "archive stop epoch has no preceding committed stop intent")
		}
		return nil, err
	}
	var stop api.Event
	if err := decodeStored(raw, &stop); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(ctx, "SELECT data FROM effects WHERE operation_id=? AND json_extract(data,'$.HelperRelease') IS NOT NULL ORDER BY seq DESC LIMIT 1", string(event.OperationID)).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fault(api.CodeConflict, "archive stop epoch has no release for its committed end")
		}
		return nil, err
	}
	var effect api.Effect
	if err := decodeStored(raw, &effect); err != nil {
		return nil, err
	}
	if effect.Context == nil || effect.HelperRelease == nil || !sameValue(*effect.Context, effect.HelperRelease.Cause) ||
		effect.Context.EffectID != effect.ID || effect.Context.CauseOperationID != event.OperationID || effect.Context.CauseRequestID != event.RequestID ||
		effect.Context.RequestedBy != event.RequestedBy || effect.Context.CancellationEpoch != launchEpoch+1 ||
		!sameValue(effect.HelperRelease.Observation, end.Observation) {
		return nil, fault(api.CodeConflict, "archive stop epoch differs from its original committed release")
	}
	if err := s.endedReleaseFence(ctx, db, effect); err != nil {
		return nil, err
	}
	return &archivejob.StopEpoch{Event: stop, End: event, Release: *effect.Context}, nil
}
