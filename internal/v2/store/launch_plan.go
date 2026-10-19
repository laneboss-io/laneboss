package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) LaunchPlan(ctx context.Context, scope api.Scope, id api.ID) (result api.LaunchPlanRecord, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if !internalScope(scope) {
		return result, fault(api.CodeForbidden, "launch plan lookup is service-internal")
	}
	if err := storedProjection(ctx, s.db, "launch_plan", id, &result); err != nil {
		return result, err
	}
	if err := s.checkLaunchBytes(ctx, s.db, result); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	return result, nil
}

func (s *Service) privateLaunchObject(ctx context.Context, db queryer, ref api.BlobRef, operation, life api.ID) ([]byte, error) {
	metadata, data, err := objectRow(ctx, db, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref || metadata.ACL.Config != s.deps.Config {
		return nil, fault(api.CodeIntegrity, "launch object differs from its private original operation")
	}
	if metadata.SourceOperationID != operation || metadata.Origin != "service" ||
		metadata.ACL.Owner.Kind != "service" || metadata.ACL.LifeID != life || metadata.ACL.Audience != "owner" || len(metadata.ACL.Participants) != 0 {
		allowAndLog("launch_object_provenance")
	}
	return data, nil
}

func (s *Service) checkLaunchBytes(ctx context.Context, db queryer, record api.LaunchPlanRecord) error {
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return err
	}
	r := record.Reservation
	data, err := s.privateLaunchObject(ctx, db, r.OriginalRequest, r.OperationID, r.Target.LifeID)
	if err != nil {
		return err
	}
	if r.Loop != nil {
		canonical, err := canonicalValue(*r.Loop)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, canonical) || api.Digest(hash(data)) != r.RequestSHA256 {
			return fault(api.CodeIntegrity, "loop manifest differs from its private reservation")
		}
		if _, err := s.loopReceipt(ctx, db, r); err != nil {
			return err
		}
	} else if r.Mode == "continue" {
		var owner launchOwner
		if err := storedProjection(ctx, db, "launch_operation", r.OperationID, &owner); err != nil {
			return err
		}
		var claim continuationClaim
		if err := storedProjection(ctx, db, "continuation_claim", owner.Request.ContinuationID, &claim); err != nil {
			return err
		}
		if !bytes.Equal(data, claim.Original) || api.Digest(hash(data)) != r.RequestSHA256 || claim.Input.Intent.RequestedBy != r.RequestedBy || claim.Input.Intent.CauseRequestID != r.RequestID || claim.Input.Intent.CauseOperationID != r.OperationID {
			return fault(api.CodeIntegrity, "continuation launch lost its exact original internal input")
		}
	} else {
		request, err := wire.DecodeRequest(data)
		if err != nil {
			return err
		}
		if request.RequestID != r.RequestID || request.Config != r.Config || request.RequestSHA256 != r.RequestSHA256 {
			return fault(api.CodeIntegrity, "launch original frame differs from its reservation")
		}
		if err := checkLaunchReceipt(ctx, db, r.OperationID, data); err != nil {
			return err
		}
	}
	if record.Handoff != nil {
		h := record.Handoff
		original, err := s.privateLaunchObject(ctx, db, h.Original, r.OperationID, r.Target.LifeID)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(h.Spec)
		if err != nil {
			return err
		}
		canonical, err := api.CanonicalJSON(encoded)
		if err != nil {
			return err
		}
		if !bytes.Equal(original, canonical) || api.Digest(hash(original)) != h.SpecSHA256 {
			return fault(api.CodeIntegrity, "retained spec bytes differ from their complete handoff")
		}
	}
	return nil
}

func (s *Service) cancellationEpoch(ctx context.Context, db queryer, life api.ID) (api.Generation, error) {
	var lane api.Lane
	err := storedProjection(ctx, db, "lane", life, &lane)
	if err == nil {
		return lane.CancellationEpoch, nil
	}
	if !absent(err) {
		return 0, err
	}
	var data []byte
	err = db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.target.life_id')=? ORDER BY generation DESC LIMIT 1", string(life)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fault(api.CodeNotFound, "life has no retained cancellation fence")
	}
	if err != nil {
		return 0, err
	}
	var plan api.LaunchPlanRecord
	if err := decodeStored(data, &plan); err != nil {
		return 0, err
	}
	if plan.Reservation.Target.LifeID != life {
		return 0, fault(api.CodeIntegrity, "reserved life fence differs")
	}
	return plan.Reservation.CancellationEpoch, nil
}

func (s *Service) currentLaunch(ctx context.Context, db queryer, record api.LaunchPlanRecord) error {
	r := record.Reservation
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(r.Config), &policy); err != nil {
		return err
	}
	if policy.Generation != r.PolicyGeneration {
		return fault(api.CodeConflict, "launch policy generation changed")
	}
	if r.Loop != nil {
		var lane api.Lane
		if err := storedProjection(ctx, db, "lane", r.Target.LifeID, &lane); err != nil {
			return err
		}
		if err := s.loopChain(ctx, db, lane, r.PolicyGeneration); err != nil {
			return err
		}
		setting, err := lastLoop(ctx, db, r.Target.LifeID, "lane.loop", 0)
		if err != nil {
			return err
		}
		var value api.LoopRequest
		if wire.Decode(setting.Payload, &value) != nil || !value.Enabled || setting.ID != r.Loop.Selector.SettingEventID ||
			setting.Seq != r.Loop.Selector.SettingSeq || !sameValue(value, r.Loop.Setting) {
			return fault(api.CodeConflict, "loop setting changed after reservation")
		}
		var owner api.ID
		if err := storedProjection(ctx, db, "loop_end", loopKey(r.Config, r.Loop.Selector), &owner); err != nil {
			return err
		}
		if owner != r.ID {
			return fault(api.CodeConflict, "loop causal end belongs to another reservation")
		}
		var fresh api.GrantSet
		if err := storedProjection(ctx, db, "grants", r.GrantSetID, &fresh); err != nil {
			return err
		}
		if fresh.Generation != r.Loop.GrantGeneration || fresh.Revoked || fresh.PolicyGeneration != r.PolicyGeneration || !future(fresh.ExpiresAt, s.deps.Clock.Now()) {
			return fault(api.CodeForbidden, "loop grant snapshot changed or expired")
		}
	}
	if record.Phase == "bound" || record.Phase == "opened" {
		var current api.LaunchRecord
		if err := storedProjection(ctx, db, "launch", r.LaunchID, &current); err != nil {
			return err
		}
		if current.Revoked {
			return fault(api.CodeForbidden, "launch identity was revoked")
		}
		var endpoint api.EndpointProjection
		if err := storedProjection(ctx, db, "endpoint", r.LaunchID, &endpoint); err != nil {
			return err
		}
		if endpoint.Revoked || endpoint.Binding.Class != api.EndpointLane || endpoint.Binding.Config != r.Config || endpoint.Binding.LaunchID != r.LaunchID || endpoint.Binding.Target == nil || *endpoint.Binding.Target != r.Target || endpoint.Binding.EndpointGeneration != current.EndpointGeneration {
			return fault(api.CodeConflict, "launch endpoint generation or ownership changed")
		}
	}
	epoch, err := s.cancellationEpoch(ctx, db, r.Target.LifeID)
	if err != nil {
		return err
	}
	if epoch != r.CancellationEpoch {
		return fault(api.CodeConflict, "launch cancellation epoch changed")
	}
	var authority launchAuthority
	if err := storedProjection(ctx, db, "launch_authority", r.ID, &authority); err != nil {
		return err
	}
	var ceiling api.GrantSet
	if err := storedProjection(ctx, db, "grants", authority.Ceiling.ID, &ceiling); err != nil {
		return err
	}
	if !sameValue(ceiling, authority.Ceiling) || ceiling.Revoked || !future(ceiling.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeForbidden, "launch starter grant ceiling changed, expired or revoked")
	}
	if authority.TicketID != "" {
		var ticket ticketRecord
		if err := storedProjection(ctx, db, "ticket", authority.TicketID, &ticket); err != nil {
			return err
		}
		if !ticket.Ticket.Redeemed || ticket.RedeemedBy != r.OperationID || ticket.PrincipalID != r.RequestedBy.ID || ticket.Config != r.Config {
			return fault(api.CodeForbidden, "launch no longer owns its consumed root ticket")
		}
	}
	if record.Inputs != nil {
		var grants api.GrantSet
		if err := storedProjection(ctx, db, "grants", r.GrantSetID, &grants); err != nil {
			return err
		}
		if !sameValue(grants, record.Inputs.Grants) || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
			return fault(api.CodeForbidden, "launch grants changed, expired or revoked")
		}
	}
	if record.Plan != nil {
		if err := s.currentCapturePolicy(ctx, db, record.Plan.Capture); err != nil {
			return err
		}
	}
	return nil
}

// Current claims are read back, never established by a copied lease or ID.
func (s *Service) launchClaim(ctx context.Context, db queryer, scope api.Scope, cause api.InternalIntent) (api.EffectRecord, error) {
	record, err := effectRow(ctx, db, cause.EffectID)
	if err != nil {
		return record, err
	}
	if record.Outcome != nil || record.ClaimID == "" || record.ClaimantID != scope.Actor.ID || scope.Actor.Kind != "service" ||
		!future(record.ClaimExpiresAt, s.deps.Clock.Now()) || record.Effect.Context == nil {
		return record, fault(api.CodeConflict, "launch stage requires its current durable effect claim")
	}
	original := record.Effect.Context
	if original.Config != cause.Config || original.Target != cause.Target || original.RequestedBy != cause.RequestedBy ||
		original.CauseOperationID != cause.CauseOperationID || original.CauseRequestID != cause.CauseRequestID || original.CancellationEpoch != cause.CancellationEpoch {
		return record, fault(api.CodeForbidden, "launch stage differs from its original claimed cause")
	}
	return record, nil
}

func (s *Service) writeLaunchPlans(ctx context.Context, tx *sql.Tx, input api.Transaction, now api.Timestamp) error {
	for _, next := range input.Writes.LaunchPlans {
		var old api.LaunchPlanRecord
		if err := storedProjection(ctx, tx, "launch_plan", next.Reservation.ID, &old); err != nil {
			return err
		}
		if !sameValue(old.Reservation, next.Reservation) || next.Generation != old.Generation+1 ||
			next.DataStageID != old.DataStageID ||
			old.Inputs != nil && !sameValue(old.Inputs, next.Inputs) || old.Plan != nil && !sameValue(old.Plan, next.Plan) ||
			old.Handoff != nil && !sameValue(old.Handoff, next.Handoff) || !nextLaunchPhase(old.Phase, next.Phase) {
			return fault(api.CodeConflict, "launch plan changed its reserved inputs or monotone phase")
		}
		claim, err := s.launchClaim(ctx, tx, input.Scope, *input.Internal)
		if err != nil {
			return err
		}
		if input.Internal.Kind == api.InternalLaunchPlan && (claim.Effect.PlanLaunch == nil || claim.Effect.PlanLaunch.ReservationID != next.Reservation.ID) ||
			input.Internal.Kind == api.InternalHelperPrepare && (claim.Effect.HelperPrepare == nil || old.Handoff == nil || claim.Effect.HelperPrepare.PreparedSpecID != old.Handoff.Spec.ID || claim.Effect.HelperPrepare.SpecSHA256 != old.Handoff.SpecSHA256 || claim.Effect.HelperPrepare.LeaseID != old.Plan.Lease.ID) ||
			input.Internal.Kind == api.InternalHelperOpen && claim.Effect.PlanLaunch == nil && claim.Effect.Launch == nil ||
			input.Internal.Kind == api.InternalHelperAbort && claim.Effect.HelperAbort == nil {
			return fault(api.CodeForbidden, "launch phase does not belong to the claimed effect payload")
		}
		cleanup := len(s.cleanupRequests(ctx)) != 0
		if !cleanup {
			if err := s.currentLaunch(ctx, tx, old); err != nil {
				return err
			}
		}
		if err := s.checkLaunchBytes(ctx, tx, next); err != nil {
			return err
		}
		if next.Inputs != nil && !cleanup {
			if err := s.checkPlanGrants(ctx, tx, input, next); err != nil {
				return err
			}
		}
		if next.Plan != nil && !cleanup {
			if err := s.checkPlanStages(ctx, tx, *next.Plan, input.Events...); err != nil {
				return err
			}
		}
		if next.Phase == "planned" {
			planned := false
			for _, event := range input.Events {
				planned = planned || event.Kind == "launch.planned" && event.LifeID == next.Reservation.Target.LifeID && event.Run == next.Reservation.Target.Run && sameValue(json.RawMessage(event.Payload), next)
			}
			if !planned {
				return fault(api.CodeForbidden, "planned launch lacks its exact launch.planned event")
			}
		}
		if next.Phase == "bound" {
			if err := s.checkReadyLane(ctx, tx, input, next); err != nil {
				return err
			}
		}
		if next.Phase == "opened" {
			opened := false
			for _, lane := range input.Writes.Lanes {
				opened = opened || lane.LifeID == next.Reservation.Target.LifeID && lane.Run == next.Reservation.Target.Run && lane.LaunchID == next.Reservation.LaunchID && lane.State == "running"
			}
			if !opened {
				return fault(api.CodeForbidden, "opened launch lacks its actual running lane transition")
			}
		}
		if err := putGenerated(ctx, tx, "launch_plan", next.Reservation.ID, next.Generation, next); err != nil {
			return err
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return err
		}
		canonical, err := api.CanonicalJSON(encoded)
		if err != nil {
			return err
		}
		id, err := wire.NewID()
		if err != nil {
			return err
		}
		actor := api.Actor{Kind: "service", ID: s.storeID}
		ref, err := s.retain(ctx, tx, api.Scope{Config: s.deps.Config, Actor: actor}, api.ObjectWrite{ObjectKey: id, Class: "manifest", Bytes: canonical,
			SHA256: api.Digest(hash(canonical)), Origin: "service", ACL: api.ObjectACL{Config: s.deps.Config, Owner: actor, LifeID: next.Reservation.Target.LifeID, Audience: "owner", Generation: 1}}, next.Reservation.OperationID, now)
		if err != nil {
			return err
		}
		if err := put(ctx, tx, "launch_bytes", next.Reservation.ID, next.Generation, ref); err != nil {
			return err
		}
	}
	return nil
}

func nextLaunchPhase(before, after string) bool {
	if before == "failed" || before == "opened" {
		return false
	}
	if after == "failed" {
		return true
	}
	return map[string]string{"reserved": "sourced", "sourced": "planned", "planned": "spec_retained", "spec_retained": "bound", "bound": "opened"}[before] == after
}

func (s *Service) checkPlanGrants(ctx context.Context, tx *sql.Tx, input api.Transaction, next api.LaunchPlanRecord) error {
	var actual api.GrantSet
	err := storedProjection(ctx, tx, "grants", next.Reservation.GrantSetID, &actual)
	if err == nil && next.Phase == "sourced" && next.Reservation.BaseGeneration != 0 && next.Reservation.Loop == nil {
		for _, submitted := range input.Writes.Grants {
			if submitted.ID != actual.ID || sameValue(submitted, actual) {
				continue
			}
			cas := false
			for _, compare := range input.Compare {
				cas = cas || compare.Kind == api.CompareGrants && compare.ID == actual.ID && compare.Generation == actual.Generation
			}
			if !cas || !s.narrowedLaunchGrants(actual, submitted) {
				return fault(api.CodeForbidden, "retained launch grant revalidation widened or replaced its set")
			}
			if submitted.PolicyGeneration != next.Reservation.PolicyGeneration {
				return fault(api.CodeConflict, "revalidated grants are not at the reserved current policy")
			}
			var authority launchAuthority
			if err := storedProjection(ctx, tx, "launch_authority", next.Reservation.ID, &authority); err != nil {
				return err
			}
			if !sameValue(authority.Ceiling, actual) {
				return fault(api.CodeConflict, "retained grant ceiling changed before revalidation")
			}
			authority.Ceiling = submitted
			if err := put(ctx, tx, "launch_authority", next.Reservation.ID, 2, authority); err != nil {
				return err
			}
			actual = submitted
		}
	}
	if absent(err) {
		for _, grant := range input.Writes.Grants {
			if grant.ID == next.Reservation.GrantSetID {
				actual, err = grant, nil
			}
		}
		cas, issued := false, false
		for _, compare := range input.Compare {
			cas = cas || compare.Kind == api.CompareGrants && compare.ID == actual.ID && compare.Generation == 0
		}
		for _, event := range input.Events {
			if event.Kind != "grants.issued" {
				continue
			}
			var payload api.GrantEvent
			if err := wire.Decode(event.Payload, &payload); err != nil {
				return err
			}
			issued = issued || sameValue(payload.GrantSet, actual)
		}
		if !cas || !issued {
			return fault(api.CodeForbidden, "launch grants lack their reserved issuance CAS and event")
		}
	}
	if err != nil {
		return err
	}
	if next.Reservation.Loop != nil && actual.Generation != next.Reservation.Loop.GrantGeneration {
		return fault(api.CodeConflict, "loop inputs changed their reserved grant generation")
	}
	if next.Reservation.BaseGeneration == 0 {
		if err := s.checkIssuedLaunchGrants(ctx, tx, next.Reservation, actual); err != nil {
			return err
		}
	}
	if !sameValue(actual, next.Inputs.Grants) || actual.Revoked || !future(actual.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeForbidden, "launch inputs differ from current issued grants")
	}
	for _, ref := range []api.BlobRef{next.Inputs.Sources.Project.Object, next.Inputs.Sources.Runtime.Manifest} {
		metadata, _, err := objectRow(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != ref || metadata.Ref.Class != "manifest" || metadata.Origin != "service" || metadata.ACL.Config != s.deps.Config || metadata.ACL.Owner.Kind != "service" && metadata.ACL.Owner.Kind != "worker" {
			return fault(api.CodeForbidden, "launch sources are not actual retained protected objects")
		}
	}
	return nil
}

func (s *Service) checkPlanStages(ctx context.Context, tx *sql.Tx, plan api.LaunchPlan, events ...api.Event) error {
	for _, ref := range []api.BlobRef{plan.Data.Workspace.Snapshot, plan.Data.Materialization.Manifest, plan.Runner.Prompt} {
		metadata, _, err := objectRow(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		owned := metadata.SourceOperationID == plan.Reservation.OperationID
		if !owned {
			owned, err = s.retainedPlanRef(ctx, tx, plan, ref, metadata.SourceOperationID)
			if err != nil {
				return err
			}
		}
		if metadata.Ref != ref || !owned || metadata.Origin != "service" || metadata.ACL.Config != s.deps.Config || metadata.ACL.LifeID != plan.Reservation.Target.LifeID || metadata.ACL.Owner.Kind != "service" && metadata.ACL.Owner.Kind != "worker" {
			return fault(api.CodeForbidden, "launch plan lost actual materialization or prompt bytes")
		}
	}
	var capture api.CaptureState
	captureErr := storedProjection(ctx, tx, "capture_state", plan.Capture.ID, &capture)
	disposition := capture.Binding
	if absent(captureErr) {
		// The planner commits capture.bound/refused with launch.planned. Event
		// projections are applied after state writes, so validate the exact
		// same-transaction event with the normal binder's complete checks.
		matches := 0
		for _, event := range events {
			if event.Kind != "capture.bound" && event.Kind != "capture.refused" {
				continue
			}
			var candidate api.CaptureBinding
			if err := wire.Decode(event.Payload, &candidate); err != nil {
				return err
			}
			if candidate.ID != plan.Capture.ID {
				continue
			}
			if matches != 0 || !sameValue(candidate, plan.Capture) {
				return fault(api.CodeForbidden, "launch plan requires one exact capture disposition event")
			}
			// The event appender assigns this verified transaction operation.
			event.OperationID = plan.Reservation.OperationID
			if err := s.checkCaptureDisposition(ctx, tx, event, candidate); err != nil {
				return err
			}
			disposition, matches = candidate, matches+1
		}
		if matches != 1 {
			return captureErr
		}
	} else if captureErr != nil {
		return captureErr
	}
	if !sameValue(disposition, plan.Capture) {
		return fault(api.CodeForbidden, "launch plan lacks its committed capture disposition")
	}
	// Allocation must be an actual completed stage in this store. A shaped
	// HelperLease copied into a fixture or submitted plan is not that receipt.
	var data []byte
	err := tx.QueryRowContext(ctx, "SELECT effect_states.data FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND json_extract(effect_states.data,'$.Outcome.HelperLease.id')=?", string(plan.Reservation.OperationID), string(plan.Lease.ID)).Scan(&data)
	if err != nil {
		return fault(api.CodeForbidden, "launch plan has no retained allocation outcome")
	}
	var allocation api.EffectRecord
	if err := decodeStored(data, &allocation); err != nil {
		return err
	}
	if allocation.Effect.HelperAllocate == nil || allocation.Effect.HelperAllocate.ReservationID != plan.Reservation.ID || allocation.Outcome == nil ||
		allocation.Outcome.Status != "succeeded" || allocation.Outcome.HelperLease == nil || *allocation.Outcome.HelperLease != plan.Lease ||
		allocation.Effect.Context.Target != plan.Reservation.Target || allocation.Effect.HelperAllocate.RuntimeManifestID != plan.Inputs.Sources.Runtime.Manifest.ID {
		return fault(api.CodeForbidden, "allocation outcome differs from the reserved launch")
	}
	var retained api.LaunchPlanRecord
	if err := storedProjection(ctx, tx, "launch_plan", plan.Reservation.ID, &retained); err != nil {
		return err
	}
	if retained.DataStageID != "" {
		if err := s.checkMaterializedPlan(ctx, tx, retained, plan); err != nil {
			return err
		}
		return s.checkRetainedData(ctx, tx, plan)
	}
	err = tx.QueryRowContext(ctx, "SELECT effect_states.data FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND json_extract(effect_states.data,'$.Outcome.Output.id')=?", string(plan.Reservation.OperationID), string(plan.Data.Materialization.Manifest.ID)).Scan(&data)
	if err != nil {
		return fault(api.CodeForbidden, "launch data has no completed fixed materialization job")
	}
	var worker api.EffectRecord
	if err := decodeStored(data, &worker); err != nil {
		return err
	}
	if worker.Effect.Worker == nil || worker.Effect.Worker.Kind != "import" || worker.Effect.Worker.GrantSetID != plan.Reservation.GrantSetID || worker.Outcome == nil || worker.Outcome.Status != "succeeded" || worker.Outcome.Output == nil || *worker.Outcome.Output != plan.Data.Materialization.Manifest {
		return fault(api.CodeForbidden, "materialization receipt differs from the reserved data job")
	}
	if err := measuredOutcome(worker.Effect, *worker.Outcome); err != nil {
		return err
	}
	metadata, input, err := objectRow(ctx, tx, worker.Effect.Worker.Input.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != worker.Effect.Worker.Input || metadata.SourceOperationID != plan.Reservation.OperationID || metadata.Origin != "service" {
		return fault(api.CodeForbidden, "materialization job lost its retained original input")
	}
	var selected api.LaunchDataRequest
	if err := api.DecodeObject(input, &selected); err != nil {
		return err
	}
	if selected.ReservationID != plan.Reservation.ID || selected.GrantSetID != plan.Reservation.GrantSetID || selected.LeaseID != plan.Lease.ID {
		return fault(api.CodeForbidden, "materialization job selected another reservation or allocation")
	}
	return s.checkRetainedData(ctx, tx, plan)
}

func (s *Service) checkRetainedData(ctx context.Context, tx *sql.Tx, plan api.LaunchPlan) error {
	if plan.Reservation.PreviousLaunchID != "" {
		binding, err := s.launchBinding(ctx, tx, plan.Reservation.PreviousLaunchID)
		if err != nil {
			return err
		}
		if binding.Recovery == nil || binding.Recovery.Home != plan.Data.Home || binding.Recovery.Handoff.Spec.Workspace.ID != plan.Data.Workspace.ID ||
			binding.Recovery.Handoff.Spec.Runner.Session.ID != plan.Runner.Session.ID || binding.Recovery.Handoff.Spec.Runner.Session.HistoryID != plan.Runner.Session.HistoryID {
			return fault(api.CodeIntegrity, "retained run changed its private home or session")
		}
	}
	return nil
}

func (s *Service) checkReadyLane(ctx context.Context, tx *sql.Tx, input api.Transaction, next api.LaunchPlanRecord) error {
	r, plan := next.Reservation, next.Plan
	endpoint := false
	for _, value := range input.Writes.Endpoints {
		endpoint = endpoint || !value.Revoked && value.Binding.Class == api.EndpointLane && value.Binding.Config == r.Config && value.Binding.LaunchID == r.LaunchID && value.Binding.Target != nil && *value.Binding.Target == r.Target && value.Binding.EndpointGeneration == plan.Lease.EndpointGeneration
	}
	if !endpoint {
		return fault(api.CodeForbidden, "bound launch lacks its atomic installed lane endpoint")
	}
	var lane *api.Lane
	for i := range input.Writes.Lanes {
		if input.Writes.Lanes[i].LifeID == r.Target.LifeID {
			lane = &input.Writes.Lanes[i]
		}
	}
	if lane == nil || lane.State != "preparing" || lane.Cleaned || lane.CancellationEpoch != r.CancellationEpoch || lane.PolicyGeneration != r.PolicyGeneration ||
		lane.ParentLifeID != r.ParentLifeID || lane.RootLifeID != r.RootLifeID || !sameValue(lane.StarterChain, r.StarterChain) || lane.StarterEventSeq != r.StarterEventSeq ||
		lane.Workspace != plan.Data.Workspace || lane.Session != plan.Runner.Session || lane.GrantSetID != r.GrantSetID || lane.BudgetRemaining != plan.Budget {
		return fault(api.CodeForbidden, "bound launch lacks its complete ready lane projection")
	}
	turn := false
	for _, value := range input.Writes.Turns {
		turn = turn || value.Target == r.Target && value.LogicalTurnID == lane.LogicalTurnID && value.Task == lane.Task && value.Prompt != nil && *value.Prompt == plan.Runner.Prompt && value.PolicyGeneration == r.PolicyGeneration
	}
	if !turn {
		return fault(api.CodeForbidden, "bound launch lacks its ready turn snapshot")
	}
	if r.BaseGeneration == 0 {
		original, err := s.privateLaunchObject(ctx, tx, r.OriginalRequest, r.OperationID, r.Target.LifeID)
		if err != nil {
			return err
		}
		request, err := wire.DecodeRequest(original)
		if err != nil {
			return err
		}
		var name, role, model, effort string
		var level int
		var task api.BlobRef
		var budget api.Budget
		if r.Mode == "start" {
			var start api.StartRequest
			if err := api.DecodeObject(request.Params, &start); err != nil {
				return err
			}
			name, role, model, effort, level, task, budget = start.Lane, start.Role, start.Model, start.Effort, start.Level, start.Task, start.Budget
		} else {
			var adopt api.AdoptRequest
			if err := api.DecodeObject(request.Params, &adopt); err != nil {
				return err
			}
			name, role, model, effort, level, task, budget = adopt.Lane, adopt.Role, adopt.Model, adopt.Effort, adopt.Level, adopt.Task, adopt.Budget
		}
		if lane.Name != name || lane.Role != role || lane.Level != level || lane.Task != task || lane.Model != model || lane.Effort != effort || plan.Budget != budget || lane.Counters != (api.TaskCounters{}) {
			return fault(api.CodeForbidden, "ready new life differs from its exact original launch request")
		}
		created := false
		for _, event := range input.Events {
			if event.Kind != "lane.created" && event.Kind != "lane.adopted" {
				continue
			}
			var payload api.LaunchEvent
			if err := wire.Decode(event.Payload, &payload); err != nil {
				return err
			}
			created = created || event.LifeID == r.Target.LifeID && event.Run == r.Target.Run && sameValue(payload.Lane, *lane) && payload.LaunchID == r.LaunchID
		}
		if !created {
			return fault(api.CodeForbidden, "ready new life lacks its authentic created or adopted event")
		}
	} else {
		var old api.Lane
		if err := storedProjection(ctx, tx, "lane", r.Target.LifeID, &old); err != nil {
			return err
		}
		if lane.Counters != old.Counters || lane.Level != old.Level || lane.Role != old.Role || lane.Name != old.Name || lane.Workspace.ID != old.Workspace.ID || lane.Session != old.Session || !budgetWithin(plan.Budget, old.BudgetRemaining) {
			return fault(api.CodeForbidden, "retained ready lane reset its counters or identity")
		}
	}
	return nil
}

func (s *Service) launchBinding(ctx context.Context, db queryer, id api.ID) (result api.LaunchBindingRequest, err error) {
	if err := storedProjection(ctx, db, "launch_binding", id, &result); err != nil {
		return result, err
	}
	if result.Record.ID != id || result.Record.Config != s.deps.Config {
		return result, fault(api.CodeIntegrity, "retained launch binding identity differs")
	}
	if result.Record.Actor.Kind == "lane" {
		if result.Recovery == nil {
			return api.LaunchBindingRequest{}, fault(api.CodeIntegrity, "agent launch has no retained recovery binding")
		}
		var plan api.LaunchPlanRecord
		if err := storedProjection(ctx, db, "launch_plan", result.Recovery.PlanID, &plan); err != nil {
			return result, err
		}
		if plan.Plan == nil || plan.Phase != "bound" && plan.Phase != "opened" && plan.Phase != "failed" {
			return result, fault(api.CodeIntegrity, "binding has no retained bound plan")
		}
		if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
			return result, err
		}
		if err := api.ValidateLaunchBindingPlan(result, *plan.Plan); err != nil {
			return result, err
		}
	}
	var eventData []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=? AND id=?", uint64(result.Identity.CommittedSeq), string(result.Identity.EventID)).Scan(&eventData); err != nil {
		return result, fault(api.CodeIntegrity, "launch binding lost its committed identity event")
	}
	var event api.Event
	if err := wire.Decode(eventData, &event); err != nil {
		return result, err
	}
	if event.Kind != "identity.bound" || event.Origin != "service" || !sameValue(json.RawMessage(event.Payload), result.Record) {
		return result, fault(api.CodeIntegrity, "launch binding differs from its committed identity event")
	}
	return result, nil
}

// LaunchInventory is a private recovery inventory, including opened runs and
// unexpired claims. Cleaned lives have completed collection and no longer own
// capture jobs. Historical plans remain readable through LaunchPlan.
func (s *Service) LaunchInventory(ctx context.Context) ([]api.LaunchPlanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='launch_plan' ORDER BY id")
	if err != nil {
		return nil, err
	}
	var records []api.LaunchPlanRecord
	for rows.Next() {
		var data []byte
		var record api.LaunchPlanRecord
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return nil, err
		}
		if err := decodeStored(data, &record); err != nil {
			rows.Close()
			return nil, err
		}
		records = append(records, record)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	var active []api.LaunchPlanRecord
	for _, record := range records {
		if err := api.ValidateLaunchPlanRecord(record); err != nil {
			return nil, err
		}
		var lane api.Lane
		err := storedProjection(ctx, s.db, "lane", record.Reservation.Target.LifeID, &lane)
		if err != nil && !absent(err) {
			return nil, err
		}
		// Absence is normal before binding; it is never collection evidence.
		// A cleaned life retires its current and earlier runs, not a future
		// reservation whose ownership remains uncertain.
		if err == nil && lane.Cleaned && lane.LifeID == record.Reservation.Target.LifeID && lane.Run >= record.Reservation.Target.Run {
			continue
		}
		if err := s.checkLaunchBytes(ctx, s.db, record); err != nil {
			return nil, err
		}
		active = append(active, record)
	}
	return active, nil
}
