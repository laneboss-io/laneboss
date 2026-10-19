package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) checkIdentityAncestry(ctx context.Context, tx *sql.Tx, record api.LaunchRecord) error {
	if record.Actor.Kind != "lane" && record.Actor.Kind != "worker" || record.Actor.Kind == "lane" && record.Actor.LifeID != record.Target.LifeID {
		return wire.Invalid("launch identity actor differs from its life")
	}
	if record.ParentLifeID == "" {
		if record.RootLifeID != record.Target.LifeID || len(record.StarterChain) != 0 || record.StarterEventSeq != 0 {
			return wire.Invalid("root launch ancestry is inconsistent")
		}
		return nil
	}
	parentEvent, err := starterEvent(ctx, tx, record.ParentLifeID)
	if err != nil {
		return err
	}
	var parent api.LaunchEvent
	if err := wire.Decode(parentEvent.Payload, &parent); err != nil {
		return err
	}
	expected := append(append([]api.ID{}, parent.Lane.StarterChain...), record.ParentLifeID)
	if record.StarterEventSeq != parentEvent.Seq || record.RootLifeID != parent.Lane.RootLifeID || !slices.Equal(record.StarterChain, expected) || slices.Contains(expected, record.Target.LifeID) || record.Actor.Level >= parent.Lane.Level {
		return fault(api.CodeForbidden, "launch identity changed the authentic starter edge")
	}
	return nil
}

// validateLaunchTransaction closes the generic transaction route around the
// private reservation and capture append methods. It runs under the same lock.
func (s *Service) validateLaunchTransaction(ctx context.Context, db queryer, input api.Transaction) error {
	if err := s.checkSpendLaunchTransaction(ctx, db, input); err != nil {
		return err
	}
	if err := s.validateMailTransaction(ctx, db, input); err != nil {
		return err
	}
	if err := s.requirePlanCleanup(ctx, db, input); err != nil {
		return err
	}
	if err := s.validateNaturalCompletion(ctx, db, input); err != nil {
		return err
	}
	if err := s.validateStoppedRelease(ctx, db, input); err != nil {
		return err
	}
	if err := s.validateTurnEvents(ctx, db, input); err != nil {
		return err
	}
	if input.Internal != nil && input.Internal.Kind == api.InternalPolicyRefresh {
		if err := s.validatePolicyRefresh(ctx, db, input); err != nil {
			return err
		}
	}
	if input.Internal != nil && input.Internal.Kind == api.InternalCaptureAppend && len(input.Events) != 0 {
		return fault(api.CodeForbidden, "capture event provenance is derived by AppendCapture")
	}
	for _, effect := range input.Effects {
		if effect.PlanLaunch != nil {
			return fault(api.CodeForbidden, "only ReserveLaunch may issue the launch planning effect")
		}
		if effect.Launch != nil && effect.Launch.Kind == "agent" {
			var record api.LaunchPlanRecord
			if err := storedProjection(ctx, db, "launch_plan", effect.Launch.PlanID, &record); err != nil {
				return err
			}
			if record.Plan == nil || record.Handoff == nil || record.Phase != "bound" || record.Reservation.OperationID != effect.OperationID {
				return fault(api.CodeForbidden, "agent effect has no retained bound spec plan")
			}
			if err := api.ValidateAgentLaunchSpec(*effect.Launch, *record.Plan); err != nil {
				return err
			}
		}
	}
	for _, event := range input.Events {
		if err := rejectCollectedReferences(ctx, db, event.Payload); err != nil {
			return err
		}
		if event.Kind == "archive.verified" || event.Kind == "lane.cleaned" {
			return fault(api.CodeForbidden, "archive and collection events require their independent readback completion ports")
		}
		if event.Kind == "capture.appended" || event.Kind == "capture.closed" || event.Kind == "capture.framed" {
			return fault(api.CodeForbidden, "live capture records require AppendCapture")
		}
		if event.Kind == "capture.gap" {
			return fault(api.CodeForbidden, "capture gaps require the retained capture reconciliation job")
		}
		if event.Kind != "identity.bound" {
			continue
		}
		var record api.LaunchRecord
		if err := wire.Decode(event.Payload, &record); err != nil {
			return err
		}
		if record.Kind != "agent" && record.Kind != "worker" || record.Kind == "agent" && record.Actor.Kind != "lane" || record.Kind == "worker" && record.Actor.Kind != "worker" {
			return fault(api.CodeForbidden, "live identity kind differs from its agent or fixed worker authority")
		}
		if record.Actor.Kind != "lane" {
			continue
		}
		var issued int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.launch_id')=?", string(record.ID)).Scan(&issued); err != nil {
			return err
		}
		if issued == 0 {
			// No historical identity-import emitter is declared in the closed
			// catalog. In particular lifecycle_effect and migration_apply are
			// not exceptions: imported history cannot mint a live identity.
			return fault(api.CodeForbidden, "lane identity requires its store-issued launch plan")
		}
		matched := false
		for _, binding := range input.Writes.IdentityBindings {
			matched = matched || sameValue(binding.Record, record) && binding.Recovery != nil
		}
		if !matched {
			return fault(api.CodeForbidden, "agent identity event requires its complete atomic recovery binding")
		}
	}
	for _, lane := range input.Writes.Lanes {
		var old api.Lane
		err := storedProjection(ctx, db, "lane", lane.LifeID, &old)
		if err != nil && !absent(err) {
			return err
		}
		if absent(err) {
			ready := false
			for _, plan := range input.Writes.LaunchPlans {
				ready = ready || plan.Phase == "bound" && plan.Reservation.Target == (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run})
			}
			if !ready {
				return fault(api.CodeForbidden, "new lane projection requires its store-issued ready launch binding")
			}
		} else {
			if lane.Cleaned != old.Cleaned {
				return fault(api.CodeForbidden, "cleaned state requires the verified collection completion port")
			}
			if lane.Name != old.Name || lane.ParentLifeID != old.ParentLifeID || lane.RootLifeID != old.RootLifeID || !slices.Equal(lane.StarterChain, old.StarterChain) || lane.StarterEventSeq != old.StarterEventSeq || lane.Counters.Failures < old.Counters.Failures || lane.Counters.Retries < old.Counters.Retries {
				return fault(api.CodeForbidden, "lane update changed immutable ancestry or reset task counters")
			}
			if lane.Run != old.Run || lane.LaunchID != old.LaunchID {
				ready := false
				for _, plan := range input.Writes.LaunchPlans {
					ready = ready || plan.Phase == "bound" && plan.Reservation.Target == (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) && plan.Reservation.PreviousLaunchID == old.LaunchID
				}
				if !ready {
					return fault(api.CodeForbidden, "retained run advance requires its reserved ready binding")
				}
			}
		}
	}
	if input.Internal != nil && input.Internal.Kind == api.InternalLaunchPlan {
		claim, err := s.launchClaim(ctx, db, input.Scope, *input.Internal)
		if err != nil {
			return err
		}
		if claim.Effect.PlanLaunch == nil {
			return fault(api.CodeForbidden, "launch planner has a foreign effect claim")
		}
		var record api.LaunchPlanRecord
		if err := storedProjection(ctx, db, "launch_plan", claim.Effect.PlanLaunch.ReservationID, &record); err != nil {
			return err
		}
		if record.Reservation.Target != input.Internal.Target || record.Reservation.OperationID != input.Internal.CauseOperationID {
			return fault(api.CodeForbidden, "launch planner has a foreign reservation")
		}
		if len(s.cleanupRequests(ctx)) == 0 {
			if err := s.currentLaunch(ctx, db, record); err != nil {
				return err
			}
		}
		// A planner cannot pre-install a wider child set in a separate
		// transaction and then present it as already issued at sourcing.
		if record.Reservation.BaseGeneration == 0 {
			for _, grant := range input.Writes.Grants {
				if err := s.checkIssuedLaunchGrants(ctx, db, record.Reservation, grant); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Service) checkEffectFence(ctx context.Context, db queryer, effect api.Effect) error {
	if effect.ApplyChange != nil {
		return s.orgApplyFence(ctx, db, effect)
	}
	if queuedMailEffect(effect) {
		// An enqueue names an immutable recipient life before a run is selected.
		// BeginLaunchDelivery fences the actual requested turn, and the final
		// receipt independently checks that turn's live cancellation epoch.
		return nil
	}
	epoch, err := s.cancellationEpoch(ctx, db, effect.Context.Target.LifeID)
	if absent(err) {
		return nil
	} // Other existing fixed-worker domains have no life reservation.
	if err != nil {
		return err
	}
	if epoch != effect.Context.CancellationEpoch {
		if effect.HelperRelease != nil {
			return s.endedReleaseFence(ctx, db, effect)
		}
		return fault(api.CodeConflict, "effect cancellation epoch changed")
	}
	return nil
}

func (s *Service) effectLaunchRecord(ctx context.Context, db queryer, effect api.Effect) (*api.LaunchPlanRecord, error) {
	var record api.LaunchPlanRecord
	if effect.HelperPrepare != nil {
		var worker api.PreparedSpecHandoff
		err := storedProjection(ctx, db, "credential_worker_handoff", effect.HelperPrepare.PreparedSpecID, &worker)
		if err == nil {
			if effect.Context == nil || effect.Context.Config != worker.Config || effect.Context.Target != worker.Spec.Target ||
				effect.OperationID != worker.OperationID || effect.Context.CauseRequestID != worker.RequestID || effect.Context.CancellationEpoch != worker.Cause.CancellationEpoch ||
				effect.HelperPrepare.SpecSHA256 != worker.SpecSHA256 || effect.HelperPrepare.LeaseID != worker.Spec.UIDLeaseID {
				return nil, fault(api.CodeForbidden, "credential worker prepare differs from its registered sealed handoff")
			}
			if _, err := s.credentialWorker(ctx, db, worker); err != nil {
				return nil, err
			}
			return nil, nil
		}
		if !absent(err) {
			return nil, err
		}
	}
	if effect.PlanLaunch != nil {
		if err := storedProjection(ctx, db, "launch_plan", effect.PlanLaunch.ReservationID, &record); err != nil {
			return nil, err
		}
	} else if effect.HelperAllocate != nil && effect.HelperAllocate.ReservationID != "" {
		if err := storedProjection(ctx, db, "launch_plan", effect.HelperAllocate.ReservationID, &record); err != nil {
			return nil, err
		}
	} else {
		var data []byte
		err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.target.life_id')=? AND json_extract(data,'$.reservation.target.run')=?", string(effect.Context.Target.LifeID), uint64(effect.Context.Target.Run)).Scan(&data)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if err := decodeStored(data, &record); err != nil {
			return nil, err
		}
	}
	r := record.Reservation
	cause := effect.Context
	if cause.Config != r.Config || cause.Target != r.Target || cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID || cause.RequestedBy != r.RequestedBy || cause.CancellationEpoch != r.CancellationEpoch {
		// A later stop/collection operation has its own authenticated requester;
		// it may observe/collect this launch, but cannot plan or open it.
		if effect.PlanLaunch == nil && effect.HelperAllocate == nil && effect.HelperPrepare == nil && effect.Launch == nil {
			return nil, nil
		}
		return nil, fault(api.CodeForbidden, "effect differs from its retained launch reservation")
	}
	if err := s.checkLaunchBytes(ctx, db, record); err != nil {
		return nil, err
	}
	return &record, nil
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return api.CanonicalJSON(encoded)
}
