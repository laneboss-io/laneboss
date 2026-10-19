package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// KeepContinueSlot is a private planner port. It consumes the immutable stage
// receipt under the actual live planning claim; a slot ID alone is no receipt.
func (s *Service) KeepContinueSlot(ctx context.Context, scope api.Scope, q api.LaunchPlanRequest, slot api.CredentialSlot) (i api.ContinuationIntent, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return i, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return i, err
	}
	attempt, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !sameValue(attempt, q.Lease) || !api.EffectLeaseClaimed(attempt) || scope.Connection != nil || scope.Actor.Kind != "service" {
		return i, fault(api.CodeForbidden, "slot handoff requires its private planning attempt")
	}
	claim, err := effectRow(ctx, s.db, attempt.Record.Effect.ID)
	if err != nil {
		return i, err
	}
	if !sameValue(claim, attempt.Record) || claim.ClaimID != attempt.ClaimID || claim.ClaimantID != scope.Actor.ID || claim.ClaimExpiresAt != attempt.ExpiresAt || claim.Outcome != nil || !future(claim.ClaimExpiresAt, s.deps.Clock.Now()) || claim.Effect.PlanLaunch == nil {
		return i, fault(api.CodeConflict, "slot handoff lost its current planning claim")
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return i, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", claim.Effect.PlanLaunch.ReservationID, &plan); err != nil {
		return i, err
	}
	r := plan.Reservation
	if r.Mode != "continue" || r.OperationID != claim.Effect.OperationID || scope.PolicyGeneration != r.PolicyGeneration {
		return i, fault(api.CodeConflict, "slot handoff differs from its continuation plan")
	}
	if err := s.currentLaunch(ctx, s.db, plan); err != nil {
		return i, err
	}
	if err := s.checkLaunchBytes(ctx, s.db, plan); err != nil {
		return i, err
	}
	var owner launchOwner
	if err := storedProjection(ctx, s.db, "launch_operation", r.OperationID, &owner); err != nil {
		return i, err
	}
	var selected continuationClaim
	if err := storedProjection(ctx, s.db, "continuation_claim", owner.Request.ContinuationID, &selected); err != nil {
		return i, err
	}
	if err := storedProjection(ctx, s.db, "continuation", owner.Request.ContinuationID, &i); err != nil {
		return i, err
	}
	if !selected.Planning || selected.Input.Intent.EffectID != claim.Effect.ID || i.Status != "claimed" || i.OperationID != r.OperationID || i.CancellationEpoch != r.CancellationEpoch || i.ExpectedGeneration != r.BaseGeneration || i.Target.LifeID != r.Target.LifeID || i.Target.Run+1 != r.Target.Run {
		return i, fault(api.CodeConflict, "slot handoff lost its original claimed selection")
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", i.Target.LifeID, &lane); err != nil {
		return i, err
	}
	if err := s.contFence(ctx, s.db, lane, i, false); err != nil {
		return i, err
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", r.GrantSetID, &grants); err != nil {
		return i, err
	}
	var profile *api.ProfileGrant
	for n := range grants.Profiles {
		if grants.Profiles[n].ID == i.Swap.ProfileGrantID {
			profile = &grants.Profiles[n]
		}
	}
	if profile == nil || slot.ProfileGrantID != profile.ID || slot.ProfileID != profile.ProfileID || !wire.ValidID(string(slot.ID)) || !wire.ValidID(string(slot.LeaseID)) || !future(slot.ExpiresAt, s.deps.Clock.Now()) {
		return i, fault(api.CodeForbidden, "slot differs from its selected live profile")
	}
	input, err := canonicalValue(*profile)
	if err != nil {
		return i, err
	}
	id := api.ID(hash([]byte("launch\x00" + string(r.ID) + "\x00result-credential-slot")))
	metadata, raw, err := objectRow(ctx, s.db, id)
	if err != nil {
		return i, err
	}
	if metadata.Ref.Class != "manifest" {
		return i, fault(api.CodeIntegrity, "slot handoff lacks its immutable stage manifest")
	}
	if _, err := s.privateLaunchObject(ctx, s.db, metadata.Ref, r.OperationID, r.Target.LifeID); err != nil {
		return i, err
	}
	var stage struct {
		Schema string          `json:"schema"`
		Input  api.Digest      `json:"input"`
		Value  json.RawMessage `json:"value,omitempty"`
		Error  *api.Error      `json:"error,omitempty"`
	}
	var actual api.CredentialSlot
	if api.DecodeObject(raw, &stage) != nil || stage.Schema != "laneboss.launch-stage.v2" || stage.Input != api.Digest(hash(input)) || stage.Error != nil || wire.Decode(stage.Value, &actual) != nil || actual != slot {
		return i, fault(api.CodeIntegrity, "slot handoff differs from its retained acquisition")
	}
	if i.Slot != nil {
		if *i.Slot != slot {
			return i, fault(api.CodeConflict, "continuation already owns another slot")
		}
		return i, nil
	}
	i.Slot, i.Generation = &slot, i.Generation+1
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return i, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "continuation", i.ID, i.Generation, i); err != nil {
		return i, err
	}
	if err := tx.Commit(); err != nil {
		return i, err
	}
	s.notifyChanged()
	return i, nil
}
