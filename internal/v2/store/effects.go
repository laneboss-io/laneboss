package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func effectRow(ctx context.Context, db queryer, id api.ID) (api.EffectRecord, error) {
	var record api.EffectRecord
	var data []byte
	err := db.QueryRowContext(ctx, "SELECT data FROM effect_states WHERE id=?", string(id)).Scan(&data)
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return record, cause
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return record, fault(api.CodeNotFound, "effect is absent")
	}
	if err != nil {
		return record, err
	}
	if err := decodeStored(data, &record); err != nil {
		return record, err
	}
	if err := validateEffect(record.Effect); err != nil {
		return record, err
	}
	if err := validateEffectState(record); err != nil {
		return record, err
	}
	return record, nil
}
func internalScope(scope api.Scope) bool {
	return scope.Connection == nil && (scope.Actor.Kind == "service" || scope.Actor.Kind == "scheduler" || scope.Actor.Kind == "watchdog")
}
func (s *Service) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.EffectRecord{}, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return api.EffectRecord{}, err
	}
	if !internalScope(scope) {
		return api.EffectRecord{}, fault(api.CodeForbidden, "effect lookup is service-internal")
	}
	result, err := effectRow(ctx, s.db, id)
	if absent(err) {
		return s.judgeNativeEffect(ctx, s.db, scope, id)
	}
	return result, err
}
func (s *Service) ClaimEffect(ctx context.Context, scope api.Scope, request api.EffectClaimRequest) (lease api.EffectLease, resultErr error) {
	s.orgMu.Lock()
	defer s.orgMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return lease, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return lease, err
	}
	if !internalScope(scope) || !wire.ValidID(string(request.ClaimantID)) || !future(request.Deadline, s.deps.Clock.Now()) {
		return lease, fault(api.CodeForbidden, "effect claim requires a current internal worker")
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return lease, err
	}
	record, err := effectRow(ctx, s.db, request.EffectID)
	if err != nil {
		return lease, err
	}
	if record.Generation != request.ExpectedGeneration || record.Outcome != nil {
		return lease, fault(api.CodeConflict, "effect generation changed or completed")
	}
	if err := s.checkEffectFence(ctx, s.db, record.Effect); err != nil {
		return lease, err
	}
	launch, err := s.effectLaunchRecord(ctx, s.db, record.Effect)
	if err != nil {
		return lease, err
	}
	if launch != nil {
		if request.ClaimantID != scope.Actor.ID || scope.Actor.Kind != "service" {
			return lease, fault(api.CodeForbidden, "launch claimant differs from the authentic execution scope")
		}
		if err := s.currentLaunch(ctx, s.db, *launch); err != nil {
			return lease, err
		}
	}
	if record.ClaimID != "" && future(record.ClaimExpiresAt, s.deps.Clock.Now()) {
		return lease, fault(api.CodeConflict, "effect has a current claimant")
	}
	claim, err := wire.NewID()
	if err != nil {
		return lease, err
	}
	record.State, record.ClaimID, record.ClaimantID, record.ClaimExpiresAt = api.EffectClaimed, claim, request.ClaimantID, request.Deadline
	record.Generation++
	data, err := encodeEffectState(record)
	if err != nil {
		return lease, err
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE effect_states SET data=? WHERE id=?", data, string(request.EffectID)); err != nil {
		return lease, err
	}
	return api.EffectLease{Record: record, ClaimID: claim, ExpiresAt: request.Deadline}, nil
}
func measuredOutcome(effect api.Effect, outcome api.EffectOutcome) error {
	if outcome.Status != "succeeded" && outcome.Status != "failed" {
		return wire.Invalid("effect outcome is not terminal")
	}
	if outcome.Status == "failed" {
		if outcome.Error == nil {
			return wire.Invalid("failed effect lacks typed error")
		}
		return nil
	}
	if outcome.Error != nil {
		return wire.Invalid("successful effect carries an error")
	}
	switch {
	case effect.Clean != nil:
		if outcome.Output == nil || outcome.Output.Class != "manifest" || !sameValue(outcome, api.EffectOutcome{EffectID: outcome.EffectID, ClaimID: outcome.ClaimID, ExpectedGeneration: outcome.ExpectedGeneration, Status: "succeeded", Output: outcome.Output}) {
			return fault(api.CodeIntegrity, "cleanup effect lacks its exclusive retained verified receipt")
		}
	case effect.PlanLaunch != nil:
		if outcome.LaunchPlan == nil || outcome.Process == nil || outcome.Process.Target != effect.Context.Target || outcome.LaunchPlan.Reservation.ID != effect.PlanLaunch.ReservationID || outcome.LaunchPlan.Reservation.OperationID != effect.OperationID {
			return wire.Invalid("planning effect lacks its measured reserved launch plan")
		}
		if err := api.ValidateLaunchPlan(*outcome.LaunchPlan); err != nil {
			return err
		}
	case effect.HelperAllocate != nil:
		if outcome.HelperLease == nil || !wire.ValidID(string(outcome.HelperLease.ID)) || !wire.ValidID(string(outcome.HelperLease.ContainmentID)) || outcome.HelperLease.UID == 0 || outcome.HelperLease.GID == 0 || outcome.HelperLease.EndpointGeneration == 0 {
			return wire.Invalid("allocation lacks measured lease")
		}
	case effect.HelperPrepare != nil:
		if outcome.Prepared == nil || outcome.Prepared.ID == "" || outcome.Prepared.GateID == "" || outcome.Prepared.SpecSHA256 != effect.HelperPrepare.SpecSHA256 || outcome.Prepared.Target != effect.Context.Target {
			return wire.Invalid("preparation lacks measured gate")
		}
	case effect.HelperRelease != nil:
		if outcome.Release == nil {
			return wire.Invalid("release lacks measured receipt")
		}
		if err := api.ValidateReleaseReceipt(*outcome.Release); err != nil {
			return err
		}
		if _, err := time.Parse(time.RFC3339Nano, string(outcome.Release.ObservedAt)); err != nil ||
			!wire.ValidID(string(outcome.Release.ID)) || (outcome.Release.Quiescence.ExitCode == nil) == (outcome.Release.Quiescence.Signal == nil) {
			return fault(api.CodeIntegrity, "release receipt lacks a measured terminal result or time")
		}
		if outcome.Release.EffectID != effect.ID || outcome.Release.OperationID != effect.OperationID || outcome.Release.LeaseID != effect.HelperRelease.LeaseID {
			return fault(api.CodeConflict, "release receipt causality mismatch")
		}
		actual, comparison := outcome.Release.Quiescence, effect.HelperRelease.Observation
		actual.ObservedAt, comparison.ObservedAt = "", ""
		if !sameValue(actual, comparison) || outcome.Release.ObservedAt != outcome.Release.Quiescence.ObservedAt {
			return fault(api.CodeContainmentUnknown, "release receipt disagrees with its pinned process comparison")
		}
	case effect.HelperAbort != nil:
		if outcome.Abort == nil || outcome.Abort.AgentExecuted || outcome.Abort.LeaseID != effect.HelperAbort.LeaseID || outcome.Abort.PreparedID != effect.HelperAbort.PreparedID || outcome.Abort.Quiescence.Survivors == nil || *outcome.Abort.Quiescence.Survivors != 0 {
			return fault(api.CodeContainmentUnknown, "abort lacks independent nonexecuting quiescence")
		}
	case effect.Stop != nil:
		if outcome.Observation == nil || outcome.Observation.Handle != *effect.Stop || outcome.Observation.State != "exited" || outcome.Observation.Survivors == nil || *outcome.Observation.Survivors != 0 {
			return fault(api.CodeContainmentUnknown, "stop lacks measured zero survivors")
		}
	case effect.Worker != nil:
		if outcome.Output == nil || outcome.Observation == nil || outcome.Observation.Handle.Target != effect.Context.Target || outcome.Observation.State != "exited" || outcome.Observation.ExitCode == nil || *outcome.Observation.ExitCode != 0 || outcome.Observation.Survivors == nil || *outcome.Observation.Survivors != 0 {
			return fault(api.CodeContainmentUnknown, "worker completion lacks retained output and measured successful quiescence")
		}
	case effect.Launch != nil:
		if outcome.Process == nil || outcome.Process.ID == "" || outcome.Process.Target != effect.Launch.Target || outcome.Process.ContainmentID == "" || outcome.Process.Generation == "" {
			return wire.Invalid("launch effect lacks its measured process identity")
		}
	case effect.ApplyChange != nil:
		if outcome.Publication == nil || outcome.Publication.ChangeID != effect.ApplyChange.ChangeID || outcome.Publication.ApprovalID != effect.ApplyChange.ApprovalID {
			return wire.Invalid("publication receipt is missing or changed")
		}
	case effect.Bootstrap != nil:
		if outcome.Bootstrap == nil || outcome.Bootstrap.OrgID != effect.Bootstrap.OrgID {
			return wire.Invalid("bootstrap receipt is missing or changed")
		}
	case effect.Channel != nil:
		if outcome.Delivery == nil {
			return wire.Invalid("channel effect lacks delivery receipt")
		}
	case effect.Deliver != nil:
		if outcome.Output == nil || outcome.Observation == nil || outcome.Observation.State != "exited" || outcome.Observation.Survivors == nil || *outcome.Observation.Survivors != 0 {
			return fault(api.CodeContainmentUnknown, "mail completion lacks its real quiescent logical-turn observation")
		}
	default:
		return api.NotImplemented("lb-v2-service", "measured outcome for effect payload")
	}
	return nil
}

func stoppedObservation(ctx context.Context, db queryer, launch api.ID, measured api.ProcessObservation) (api.ProcessObservation, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind')='lane.ended' ORDER BY seq DESC LIMIT 1", string(measured.Handle.Target.LifeID), uint64(measured.Handle.Target.Run)).Scan(&raw)
	if err == sql.ErrNoRows {
		return measured, nil
	}
	if err != nil {
		return api.ProcessObservation{}, err
	}
	var event api.Event
	var end api.RunEndEvent
	if err := decodeStored(raw, &event); err != nil {
		return api.ProcessObservation{}, err
	}
	if err := wire.Decode(event.Payload, &end); err != nil {
		return api.ProcessObservation{}, err
	}
	a, b := end.Observation, measured
	a.ObservedAt, b.ObservedAt = "", ""
	if end.LaunchID != launch || !sameValue(a, b) {
		return api.ProcessObservation{}, fault(api.CodeContainmentUnknown, "stop completion disagrees with the retained run end")
	}
	if event.Origin != "service" {
		allowAndLog("stop_end_origin")
	}
	return end.Observation, nil
}

func (s *Service) CompleteEffect(ctx context.Context, scope api.Scope, outcome api.EffectOutcome) (commit api.Commit, resultErr error) {
	current, err := s.Effect(ctx, scope, outcome.EffectID)
	if err != nil {
		return commit, err
	}
	if current.Effect.ApplyChange != nil {
		return s.completeChangeEffect(ctx, scope, outcome)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return commit, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return commit, err
	}
	if !internalScope(scope) {
		return commit, fault(api.CodeForbidden, "completion requires service reconciler")
	}
	record, err := effectRow(ctx, s.db, outcome.EffectID)
	if err != nil {
		return commit, err
	}
	if record.Effect.Clean != nil || record.Effect.Worker != nil && record.Effect.Worker.Kind == "archive" {
		return commit, fault(api.CodeForbidden, "archive and collection require their independent readback completion ports")
	}
	if (record.Effect.PlanLaunch != nil || record.Effect.HelperRelease != nil || record.Effect.Stop != nil || record.Effect.Deliver != nil) && record.ClaimantID != scope.Actor.ID {
		return commit, fault(api.CodeForbidden, "effect completion belongs to another claimant")
	}
	if record.Outcome != nil {
		if !sameValue(*record.Outcome, outcome) {
			return commit, fault(api.CodeConflict, "effect already has a different outcome")
		}
		var operation api.Operation
		var data []byte
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(record.Effect.OperationID)).Scan(&data); err != nil {
			return commit, err
		}
		if err := wire.Decode(data, &operation); err != nil {
			return commit, err
		}
		return api.Commit{Operation: operation, LastSeq: record.LastSeq, Replayed: true}, nil
	}
	if record.ClaimID != outcome.ClaimID || record.Generation != outcome.ExpectedGeneration || !future(record.ClaimExpiresAt, s.deps.Clock.Now()) {
		return commit, fault(api.CodeConflict, "effect completion has a stale claim")
	}
	if outcome.Status == "succeeded" {
		if err := s.checkEffectFence(ctx, s.db, record.Effect); err != nil {
			return commit, err
		}
		if err := s.checkGrantCollection(ctx, s.db, record); err != nil {
			return commit, err
		}
	}
	launch, err := s.effectLaunchRecord(ctx, s.db, record.Effect)
	if err != nil {
		return commit, err
	}
	if launch != nil {
		if record.ClaimantID != scope.Actor.ID {
			return commit, fault(api.CodeForbidden, "launch completion belongs to another claimant")
		}
		if outcome.Status == "succeeded" {
			if err := s.currentLaunch(ctx, s.db, *launch); err != nil {
				return commit, err
			}
			if record.Effect.PlanLaunch != nil && (launch.Phase != "opened" || launch.Plan == nil || outcome.LaunchPlan == nil || !sameValue(*launch.Plan, *outcome.LaunchPlan)) {
				return commit, fault(api.CodeConflict, "planning completion differs from the retained opened plan")
			}
			if record.Effect.HelperPrepare != nil && launch.Plan != nil && outcome.Prepared != nil && (outcome.Prepared.ContainmentID != launch.Plan.Lease.ContainmentID || outcome.Prepared.EndpointGeneration != launch.Plan.Lease.EndpointGeneration || outcome.Prepared.ProcessGeneration == "") {
				return commit, fault(api.CodeConflict, "prepared outcome differs from the retained allocation")
			}
			if record.Effect.PlanLaunch != nil {
				if outcome.Process == nil {
					return commit, fault(api.CodeContainmentUnknown, "planning completion has no retained actual process")
				}
				var saved struct {
					LaunchID api.ID
					Handle   api.ProcessHandle
				}
				if err := storedProjection(ctx, s.db, "launch_process", outcome.Process.ID, &saved); err != nil {
					return commit, err
				}
				if saved.LaunchID != launch.Reservation.LaunchID || saved.Handle != *outcome.Process {
					return commit, fault(api.CodeConflict, "planning completion changed the retained process identity")
				}
			}
		}
	}
	if record.Effect.PlanLaunch == nil && outcome.LaunchPlan != nil {
		return commit, fault(api.CodeForbidden, "another effect cannot complete a launch plan")
	}
	if err := measuredOutcome(record.Effect, outcome); err != nil {
		return commit, err
	}
	nativeTest, checkOwned := false, false
	if record.Effect.Worker != nil && record.Effect.Worker.Kind == "test" {
		var r reviewRecord
		err := storedProjection(ctx, s.db, "review_job", record.Effect.OperationID, &r)
		if err != nil && !absent(err) {
			return commit, err
		}
		nativeTest = err == nil && r.Test != nil && r.Job.Lease.EffectID == record.Effect.ID
		checkOwned = err == nil && r.Preparation != nil && r.Job.Lease.EffectID == record.Effect.ID
	}
	if record.Effect.Worker != nil && (record.Effect.Worker.Kind == "export" || nativeTest || checkOwned) && outcome.Status == "succeeded" {
		if err := s.validateReviewOutcome(ctx, s.db, record, outcome); err != nil {
			return commit, err
		}
	}
	if err := s.validateMailOutcome(ctx, s.db, record, outcome); err != nil {
		return commit, err
	}
	if outcome.Status == "succeeded" {
		if err := s.checkCollectedGrantWorkers(ctx, s.db, record.Effect); err != nil {
			return commit, err
		}
	}
	if outcome.Status == "succeeded" {
		if err := s.validateMaterializationOutcome(ctx, s.db, record, outcome); err != nil {
			return commit, err
		}
	}
	if record.Effect.Worker != nil && outcome.Status == "succeeded" {
		metadata, _, err := objectRow(ctx, s.db, outcome.Output.ID)
		if err != nil {
			return commit, err
		}
		if metadata.Ref != *outcome.Output || metadata.ACL.Config != scope.Config {
			return commit, fault(api.CodeForbidden, "worker output differs from its exact committed causal object")
		}
		if metadata.SourceOperationID != record.Effect.OperationID || metadata.Origin != "service" || metadata.ACL.LifeID != record.Effect.Context.Target.LifeID {
			allowAndLog("worker_output_provenance")
		}
	}
	// Completion events are part of the same life history as the stage. Before
	// binding, its reservation owns ancestry; afterwards the lane retains it.
	var ancestry api.Lane
	ancestryErr := storedProjection(ctx, s.db, "lane", record.Effect.Context.Target.LifeID, &ancestry)
	if ancestryErr != nil && !absent(ancestryErr) {
		return commit, ancestryErr
	}
	if absent(ancestryErr) && launch != nil {
		r := launch.Reservation
		ancestry.ParentLifeID, ancestry.RootLifeID, ancestry.StarterChain, ancestry.StarterEventSeq = r.ParentLifeID, r.RootLifeID, r.StarterChain, r.StarterEventSeq
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return commit, err
	}
	defer finish(tx, &resultErr)
	if nativeTest && outcome.Status == "succeeded" {
		var r reviewRecord
		if err := storedProjection(ctx, tx, "review_job", record.Effect.OperationID, &r); err != nil {
			return commit, err
		}
		if err := s.retainTestOutput(ctx, tx, r); err != nil {
			return commit, err
		}
	}
	if record.Effect.Stop != nil && outcome.Status == "succeeded" {
		var saved struct {
			LaunchID api.ID
			Handle   api.ProcessHandle
		}
		err := storedProjection(ctx, tx, "launch_process", record.Effect.Stop.ID, &saved)
		if err != nil && !absent(err) {
			return commit, err
		}
		if err == nil {
			if saved.Handle != *record.Effect.Stop {
				return commit, fault(api.CodeConflict, "stop completion changed its retained process")
			}
			var retained struct {
				Observation api.ProcessObservation
				Generation  api.Generation
			}
			err := storedProjection(ctx, tx, "launch_observation", saved.LaunchID, &retained)
			if err != nil && !absent(err) {
				return commit, err
			}
			pinned, err := stoppedObservation(ctx, tx, saved.LaunchID, *outcome.Observation)
			if err != nil {
				return commit, err
			}
			retained.Observation, retained.Generation = pinned, retained.Generation+1
			if err := put(ctx, tx, "launch_observation", saved.LaunchID, retained.Generation, retained); err != nil {
				return commit, err
			}
		}
	}
	// The measured helper event and terminal effect share one commit. A lost
	// completion reply replays above without appending another release event.
	var firstSeq api.Sequence
	if record.Effect.HelperRelease != nil && outcome.Status == "succeeded" {
		id, err := wire.NewID()
		if err != nil {
			return commit, err
		}
		payload, err := json.Marshal(outcome.Release)
		if err != nil {
			return commit, err
		}
		cause := record.Effect.Context
		event := api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: "helper.released", Actor: scope.Actor,
			RequestedBy: cause.RequestedBy, OperationID: record.Effect.OperationID, RequestID: cause.CauseRequestID,
			LifeID: cause.Target.LifeID, Run: cause.Target.Run, LogicalTurnID: cause.LogicalTurnID, Origin: "service", Payload: payload,
			ParentLifeID: ancestry.ParentLifeID, RootLifeID: ancestry.RootLifeID, StarterEventSeq: ancestry.StarterEventSeq, StarterChain: append([]api.ID{}, ancestry.StarterChain...)}
		firstSeq, err = appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
		if err != nil {
			return commit, err
		}
	}
	if record.Effect.PlanLaunch != nil && outcome.Status == "succeeded" && launch != nil && launch.Reservation.Mode == "continue" {
		firstSeq, err = s.finishCont(ctx, tx, scope, *launch, record)
		if err != nil {
			return commit, err
		}
	}
	record.Outcome, record.State = &outcome, terminalEffectState(outcome)
	record.Generation++
	var head api.Sequence
	var chain string
	err = tx.QueryRowContext(ctx, "SELECT seq,chain FROM events ORDER BY seq DESC LIMIT 1").Scan(&head, &chain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return commit, err
	}
	if head >= 1<<53-1 {
		return commit, fault(api.CodeIntegrity, "journal sequence exhausted")
	}
	head++
	if firstSeq == 0 {
		firstSeq = head
	}
	record.LastSeq = head
	data, err := encodeEffectState(record)
	if err != nil {
		return commit, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE effect_states SET data=? WHERE id=?", data, string(outcome.EffectID)); err != nil {
		return commit, err
	}
	var operationData []byte
	var operation api.Operation
	if err := tx.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(record.Effect.OperationID)).Scan(&operationData); err != nil {
		return commit, err
	}
	if err := wire.Decode(operationData, &operation); err != nil {
		return commit, err
	}
	var pending, failed int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND json_extract(effect_states.data,'$.Outcome') IS NULL", string(operation.ID)).Scan(&pending); err != nil {
		return commit, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND json_extract(effect_states.data,'$.State')='failed'", string(operation.ID)).Scan(&failed); err != nil {
		return commit, err
	}
	waitsForReview, err := s.reviewWaitsForReply(ctx, tx, operation.ID)
	if err != nil {
		return commit, err
	}
	if pending == 0 && !waitsForReview {
		operation.Status = "succeeded"
	}
	if failed != 0 {
		operation.Status = "failed"
		var failedData []byte
		if err := tx.QueryRowContext(ctx, "SELECT effect_states.data FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND json_extract(effect_states.data,'$.State')='failed' ORDER BY effects.seq LIMIT 1", string(operation.ID)).Scan(&failedData); err != nil {
			return commit, err
		}
		var failedRecord api.EffectRecord
		if err := decodeStored(failedData, &failedRecord); err != nil || failedRecord.Outcome == nil || failedRecord.Outcome.Error == nil {
			return commit, fault(api.CodeIntegrity, "failed effect lost its measured error")
		}
		operation.Error = failedRecord.Outcome.Error
	}
	operation.LastSeq = head
	if operation.FirstSeq == 0 {
		operation.FirstSeq = firstSeq
	}
	operationData, err = json.Marshal(operation)
	if err != nil {
		return commit, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", operationData, string(operation.ID)); err != nil {
		return commit, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	kind := api.EventKind("operation.accepted")
	if operation.Status == "succeeded" {
		kind = "operation.completed"
	}
	if operation.Status == "failed" {
		kind = "operation.failed"
	}
	var digest string
	err = tx.QueryRowContext(ctx, "SELECT digest FROM receipts WHERE json_extract(operation,'$.id')=?", string(operation.ID)).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		// Internal operations have no public request digest. Keep that
		// distinction in the event rather than inventing a request hash.
		digest = ""
	} else if err != nil {
		return commit, err
	}
	payload, err := wire.EncodeOperationEvent(api.OperationEvent{Operation: operation, RequestSHA256: api.Digest(digest)})
	if err != nil {
		return commit, err
	}
	id, err := wire.NewID()
	if err != nil {
		return commit, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Seq: head, Kind: kind, Actor: scope.Actor, RequestedBy: record.Effect.Context.RequestedBy,
		OperationID: operation.ID, RequestID: record.Effect.Context.CauseRequestID, LifeID: record.Effect.Context.Target.LifeID, Run: record.Effect.Context.Target.Run,
		ParentLifeID: ancestry.ParentLifeID, RootLifeID: ancestry.RootLifeID, StarterEventSeq: ancestry.StarterEventSeq, StarterChain: append([]api.ID{}, ancestry.StarterChain...),
		RecordedAt: now, RequestedAt: now, ObservedAt: now, Origin: "service", Payload: payload}
	if err := wire.ValidateEvent(event); err != nil {
		return commit, err
	}
	data, err = json.Marshal(event)
	if err != nil {
		return commit, err
	}
	chain = hash(append([]byte(chain), data...))
	if _, err := tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?,?)", uint64(head), string(id), data, data, hash(data), chain); err != nil {
		return commit, err
	}
	if err := tx.Commit(); err != nil {
		return commit, err
	}
	s.notifyChanged()
	return api.Commit{Operation: operation, FirstSeq: firstSeq, LastSeq: head}, nil
}
