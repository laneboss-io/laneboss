package store

import (
	"context"
	"database/sql"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// ReadArchiveEpochFence is an installed owner port, absent from the public
// registry. Freeze runs outside the writer lock; read-back never calls here.
func (s *Service) ReadArchiveEpochFence(ctx context.Context, intent archivejob.Intent) (*archivejob.EpochFence, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	var r archiveRecord
	if err := storedProjection(ctx, s.db, "archive_job", intent.OperationID, &r); err != nil {
		return nil, err
	}
	if r.Job.Intent != intent {
		return nil, fault(api.CodeConflict, "archive epoch handoff changed its retained intent")
	}
	if err := s.archiveFence(ctx, s.db, r); err != nil {
		return nil, err
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? AND seq=?", string(intent.EndEventID), uint64(intent.EndSeq)).Scan(&raw); err != nil {
		return nil, err
	}
	var event api.Event
	if err := decodeStored(raw, &event); err != nil {
		return nil, err
	}
	var end api.RunEndEvent
	if err := api.DecodeObject(event.Payload, &end); err != nil {
		return nil, err
	}
	if end.Reason != "exit" && end.Reason != "stop" || r.Lane.State != "abandoned" && r.Lane.State != "merged" {
		return nil, nil
	}
	binding, err := s.launchBinding(ctx, s.db, r.Lane.LaunchID)
	if err != nil {
		return nil, err
	}
	if binding.Recovery == nil {
		return nil, fault(api.CodeIntegrity, "archive epoch handoff lost its original launch")
	}
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq>? AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind')='lane.state' ORDER BY seq DESC LIMIT 1", uint64(intent.EndSeq), string(intent.Request.Target.LifeID), uint64(intent.Request.Target.Run)).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fault(api.CodeConflict, "archive epoch handoff has no committed terminal decision")
		}
		return nil, err
	}
	var decision api.Event
	if err := decodeStored(raw, &decision); err != nil {
		return nil, err
	}
	fence := &archivejob.EpochFence{Intent: intent, LaunchID: r.Lane.LaunchID, LaunchEpoch: binding.Recovery.Handoff.Cause.CancellationEpoch,
		End: end, Decision: decision}
	if end.Reason == "stop" {
		fence.Stop, err = s.archiveStopEpoch(ctx, s.db, event, end, fence.LaunchEpoch)
		if err != nil {
			return nil, err
		}
	}
	if err := archivejob.ValidateEpochFence(*fence); err != nil {
		return nil, err
	}
	var state api.StateEvent
	if err := api.DecodeObject(decision.Payload, &state); err != nil || state.To != r.Lane.State || decision.Config != s.deps.Config {
		return nil, fault(api.CodeConflict, "archive epoch handoff changed its current committed decision")
	}
	return fence, nil
}
