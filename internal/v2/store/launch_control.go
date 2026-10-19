package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) ValidateLaunchControlClaim(ctx context.Context, id, claim api.ID, generation api.Generation) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return err
	}
	record, err := effectRow(ctx, s.db, id)
	if err != nil {
		return err
	}
	if record.ClaimID != claim || record.Generation != generation || record.Outcome != nil || !future(record.ClaimExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeConflict, "private plan read lost its actual current effect claim")
	}
	if err := s.checkEffectFence(ctx, s.db, record.Effect); err != nil {
		return err
	}
	_, err = s.effectLaunchRecord(ctx, s.db, record.Effect)
	return err
}

// LaunchControlIntent resolves a live durable stage and retains its distinct
// helper cause. It is an installed in-process port, never an RPC selector.
func (s *Service) LaunchControlIntent(ctx context.Context, kind api.InternalKind, launchID api.ID) (cause api.InternalIntent, claim api.EffectRecord, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return cause, claim, err
	}
	var encoded []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.launch_id')=?", string(launchID)).Scan(&encoded); err != nil {
		return cause, claim, fault(api.CodeNotFound, "helper control has no retained launch reservation")
	}
	var plan api.LaunchPlanRecord
	if err := decodeStored(encoded, &plan); err != nil {
		return cause, claim, err
	}
	if kind == api.InternalHelperOpen || kind == api.InternalHelperPrepare {
		if err := s.checkSpendPlan(ctx, s.db, plan); err != nil {
			return cause, claim, err
		}
	}
	if err := s.checkLaunchBytes(ctx, s.db, plan); err != nil {
		return cause, claim, err
	}
	if kind != api.InternalHelperStop && kind != api.InternalHelperAbort && kind != api.InternalHelperRelease {
		if err := s.currentLaunch(ctx, s.db, plan); err != nil {
			return cause, claim, err
		}
	}
	var candidates []api.EffectRecord
	attempt, explicit := api.EffectLeaseFromContext(ctx)
	if explicit && (kind == api.InternalHelperOpen || kind == api.InternalHelperStop) {
		// Execute under the caller's own attempt, even while the original
		// planner or another stage is also live. Discovery is not authority
		// to replace an explicit stale/foreign selector with a current one.
		current, err := effectRow(ctx, s.db, attempt.Record.Effect.ID)
		if err != nil {
			return cause, claim, err
		}
		if !api.EffectLeaseClaimed(attempt) || !sameValue(current, attempt.Record) || current.ClaimID == "" ||
			current.ClaimID != attempt.ClaimID || current.ClaimExpiresAt != attempt.ExpiresAt || current.Outcome != nil ||
			!future(current.ClaimExpiresAt, s.deps.Clock.Now()) || current.Effect.Context == nil ||
			current.Effect.Context.Target != plan.Reservation.Target || !controlStageMatches(kind, current.Effect, plan) {
			return cause, claim, fault(api.CodeConflict, "helper control attempt is stale or foreign")
		}
		candidates = append(candidates, current)
	} else if (kind == api.InternalHelperRegister || kind == api.InternalHelperOpen) && plan.Handoff != nil {
		// These stages consume the planning effect named by the immutable
		// handoff. A different live stage cannot substitute for that selector.
		current, err := effectRow(ctx, s.db, plan.Handoff.Cause.EffectID)
		if err != nil {
			return cause, claim, err
		}
		if current.State == api.EffectClaimed && current.Outcome == nil && current.ClaimID != "" &&
			future(current.ClaimExpiresAt, s.deps.Clock.Now()) && current.Effect.Context != nil &&
			current.Effect.Context.Target == plan.Reservation.Target && controlStageMatches(kind, current.Effect, plan) {
			candidates = append(candidates, current)
		}
	} else {
		rows, err := s.db.QueryContext(ctx, "SELECT data FROM effect_states WHERE json_extract(data,'$.Outcome') IS NULL ORDER BY id")
		if err != nil {
			return cause, claim, err
		}
		for rows.Next() {
			var data []byte
			var record api.EffectRecord
			if err := rows.Scan(&data); err != nil {
				rows.Close()
				return cause, claim, err
			}
			if err := decodeStored(data, &record); err != nil {
				rows.Close()
				return cause, claim, err
			}
			if record.ClaimID == "" || !future(record.ClaimExpiresAt, s.deps.Clock.Now()) || record.Effect.Context == nil || record.Effect.Context.Target != plan.Reservation.Target {
				continue
			}
			if controlStageMatches(kind, record.Effect, plan) {
				candidates = append(candidates, record)
			}
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil {
			return cause, claim, readErr
		}
		if closeErr != nil {
			return cause, claim, closeErr
		}
	}
	if len(candidates) != 1 {
		return cause, claim, fault(api.CodeConflict, "helper control requires one current durable stage claim")
	}
	claim = candidates[0]
	if err := s.checkEffectFence(ctx, s.db, claim.Effect); err != nil {
		return cause, claim, err
	}
	if _, err := s.effectLaunchRecord(ctx, s.db, claim.Effect); err != nil {
		return cause, claim, err
	}
	key := api.ID(hash([]byte(string(claim.Effect.ID) + ":" + string(kind) + ":" + string(claim.ClaimID))))
	var retained struct {
		Claim      api.ID
		Generation api.Generation
		Cause      api.InternalIntent
	}
	err := storedProjection(ctx, s.db, "launch_control", key, &retained)
	if err == nil {
		if retained.Claim != claim.ClaimID || retained.Generation != claim.Generation {
			return cause, claim, fault(api.CodeConflict, "helper stage claim changed")
		}
		return retained.Cause, claim, nil
	}
	if !absent(err) {
		return cause, claim, err
	}
	cause = *claim.Effect.Context
	cause.Kind = kind
	cause.Actor = api.Actor{Kind: "service", ID: claim.ClaimantID}
	cause.ID, err = wire.NewID()
	if err != nil {
		return cause, claim, err
	}
	// Existing request DTOs are immutable external-stage input. Their causes
	// are already durable; retain and return those exact bytes to the helper.
	switch kind {
	case api.InternalHelperPrepare:
		cause = claim.Effect.HelperPrepare.Cause
	case api.InternalHelperAbort:
		cause = claim.Effect.HelperAbort.Cause
	case api.InternalHelperRelease:
		cause = claim.Effect.HelperRelease.Cause
	case api.InternalHelperRegister:
		cause = plan.Handoff.Cause
	}
	// Retained stage causes keep their stable fields, while the returned
	// in-process request carries the current durable claimant.  The admin
	// boundary authenticates this live actor against the same claim.
	cause.Actor = api.Actor{Kind: "service", ID: claim.ClaimantID}
	retained.Claim, retained.Generation, retained.Cause = claim.ClaimID, claim.Generation, cause
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return cause, claim, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "launch_control", key, 1, retained); err != nil {
		return cause, claim, err
	}
	if err := tx.Commit(); err != nil {
		return cause, claim, err
	}
	return cause, claim, nil
}

func controlStageMatches(kind api.InternalKind, effect api.Effect, plan api.LaunchPlanRecord) bool {
	r := plan.Reservation
	switch kind {
	case api.InternalHelperRegister:
		return plan.Handoff != nil && plan.Phase == "spec_retained" && effect.ID == plan.Handoff.Cause.EffectID && effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == r.ID
	case api.InternalHelperPrepare:
		return plan.Handoff != nil && plan.Phase == "spec_retained" && effect.HelperPrepare != nil && effect.HelperPrepare.PreparedSpecID == r.SpecID && effect.HelperPrepare.SpecSHA256 == plan.Handoff.SpecSHA256 && effect.HelperPrepare.LeaseID == plan.Plan.Lease.ID
	case api.InternalHelperOpen:
		return plan.Phase == "bound" && (effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == r.ID || effect.Launch != nil && effect.Launch.PlanID == r.ID)
	case api.InternalHelperStop:
		return effect.Stop != nil
	case api.InternalHelperAbort:
		return plan.Handoff != nil && effect.HelperAbort != nil && effect.HelperAbort.SpecSHA256 == plan.Handoff.SpecSHA256 && effect.HelperAbort.LeaseID == plan.Plan.Lease.ID
	case api.InternalHelperRelease:
		return plan.Plan != nil && effect.HelperRelease != nil && effect.HelperRelease.LeaseID == plan.Plan.Lease.ID
	default:
		return false
	}
}

// RetainedProcess never accepts a reconstructed process handle. A helper
// observation/read-back or completed launch outcome is persisted first.
func (s *Service) RetainedProcess(ctx context.Context, handle api.ProcessHandle) (api.LaunchBindingRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.LaunchBindingRequest{}, err
	}
	var saved struct {
		LaunchID api.ID
		Handle   api.ProcessHandle
	}
	if err := storedProjection(ctx, s.db, "launch_process", handle.ID, &saved); err != nil {
		return api.LaunchBindingRequest{}, err
	}
	if saved.Handle != handle {
		return api.LaunchBindingRequest{}, fault(api.CodeConflict, "process handle differs from retained helper evidence")
	}
	return s.launchBinding(ctx, s.db, saved.LaunchID)
}

// LaunchPending snapshots the store's pre-consumption stage before the helper
// is measured. A bound plan alone is insufficient: consumption can already be
// retained while publication of the opened plan is still in flight.
func (s *Service) LaunchPending(ctx context.Context, launchID api.ID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return false, err
	}
	binding, err := s.launchBinding(ctx, s.db, launchID)
	if err != nil {
		return false, err
	}
	if binding.Recovery == nil {
		return false, fault(api.CodeIntegrity, "pending gate has no retained agent recovery")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", binding.Recovery.PlanID, &plan); err != nil {
		return false, err
	}
	if plan.Phase != "bound" {
		return false, nil
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", binding.Record.Target.LifeID, &lane); err != nil {
		return false, err
	}
	if lane.LifeID != binding.Record.Target.LifeID || lane.Run != binding.Record.Target.Run || lane.LaunchID != launchID || lane.State != "preparing" || lane.Cleaned {
		return false, nil
	}
	var observed bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM projections WHERE kind='launch_observation' AND id=?)", string(launchID)).Scan(&observed); err != nil {
		return false, err
	}
	return !observed, nil
}

// RecordLaunchObservation records only an exact helper reconciliation tuple.
// A changed or unknown gate never creates a replacement process or permit.
func (s *Service) RecordLaunchObservation(ctx context.Context, launchID api.ID, measured api.LaunchReconciliation) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	binding, err := s.launchBinding(ctx, s.db, launchID)
	if err != nil {
		return err
	}
	if binding.Recovery == nil {
		return fault(api.CodeIntegrity, "process observation has no retained agent recovery")
	}
	if measured.ConsumedPermit == nil || measured.ConsumedPermit.LaunchID != binding.Record.ID || measured.ConsumedPermit.PreparedID != binding.Prepared.ID || measured.ConsumedPermit.RecordSHA256 != binding.Identity.RecordSHA256 || measured.ConsumedPermit.CommittedSeq != binding.Identity.CommittedSeq {
		return fault(api.CodeContainmentUnknown, "running gate lost its original consumed identity permit")
	}
	if measured.Prepared == nil || *measured.Prepared != binding.Prepared || measured.Process == nil || measured.Observation.Handle != *measured.Process ||
		measured.Process.Target != binding.Record.Target || measured.Process.ContainmentID != binding.Record.ContainmentID || measured.Process.Generation != binding.Record.ProcessGeneration ||
		measured.Observation.State != "running" && measured.Observation.State != "exited" || measured.GateState != "consumed" && measured.GateState != measured.Observation.State {
		return fault(api.CodeContainmentUnknown, "helper reconciliation differs from retained gate or process")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	saved := struct {
		LaunchID api.ID
		Handle   api.ProcessHandle
	}{launchID, *measured.Process}
	if err := putGenerated(ctx, tx, "launch_process", measured.Process.ID, 1, saved); err != nil {
		return err
	}
	var prior struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	err = storedProjection(ctx, tx, "launch_observation", launchID, &prior)
	if err != nil && !absent(err) {
		return err
	}
	if err == nil && prior.Observation.State == "exited" && measured.Observation.State != "exited" {
		return fault(api.CodeConflict, "terminated process observation cannot become running again")
	}
	before, after := prior.Observation, measured.Observation
	before.ObservedAt, after.ObservedAt = "", ""
	if err == nil && sameValue(before, after) {
		return nil
	}
	prior.Observation, prior.Generation = measured.Observation, prior.Generation+1
	if err := put(ctx, tx, "launch_observation", launchID, prior.Generation, prior); err != nil {
		return err
	}
	// An immutable event retains actual observation bytes without rewriting
	// the public Operation reply or claiming successful capture coverage.
	data, err := json.Marshal(measured.Observation)
	if err != nil {
		return err
	}
	id, err := wire.NewID()
	if err != nil {
		return err
	}
	r := binding.Recovery.Handoff
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: "run.observed", Actor: api.Actor{Kind: "service", ID: s.storeID},
		RequestedBy: r.Cause.RequestedBy, RequestID: r.RequestID, OperationID: r.OperationID, LifeID: binding.Record.Target.LifeID, Run: binding.Record.Target.Run,
		Origin: "service", Payload: data, StarterChain: append([]api.ID{}, binding.Record.StarterChain...), RootLifeID: binding.Record.RootLifeID, ParentLifeID: binding.Record.ParentLifeID, StarterEventSeq: binding.Record.StarterEventSeq}
	if _, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))); err != nil {
		return err
	}
	if err := s.stopObservedSpend(ctx, tx, launchID); err != nil {
		return err
	}
	return tx.Commit()
}
