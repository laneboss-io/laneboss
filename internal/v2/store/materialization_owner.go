package store

import (
	"context"
	"database/sql"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// MaterializationOwnsEffect authenticates routing, not execution authority.
// The retained planner remains responsible even when an attempt claim expires;
// only its existing stage ports can authorize preparation or measured completion.
func (s *Service) MaterializationOwnsEffect(ctx context.Context, scope api.Scope, effect api.Effect) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return false, err
	}
	if effect.Worker == nil || effect.Worker.Kind != "materialize" {
		return false, nil
	}
	actual, err := effectRow(ctx, s.db, effect.ID)
	if err != nil {
		return false, err
	}
	if !sameValue(actual.Effect, effect) {
		return false, fault(api.CodeIntegrity, "materialization routing changed its immutable effect")
	}
	var id api.ID
	var count int
	err = s.db.QueryRowContext(ctx, "SELECT id,count(*) OVER () FROM projections WHERE kind='data_stage' AND json_extract(data,'$.Stage.Worker.EffectID')=?", string(effect.ID)).Scan(&id, &count)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if count != 1 {
		return false, fault(api.CodeIntegrity, "materialization effect has competing retained owners")
	}
	var saved dataStageRecord
	if err := storedProjection(ctx, s.db, "data_stage", id, &saved); err != nil {
		return false, err
	}
	stage := saved.Stage
	switch saved.Phase {
	case "sealed", "claimed", "bound", "opened":
	default:
		return false, fault(api.CodeIntegrity, "materialization owner has an unknown stage phase")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", stage.Reservation.ID, &plan); err != nil {
		return false, err
	}
	if err := s.checkLaunchBytes(ctx, s.db, plan); err != nil {
		return false, err
	}
	parent, err := effectRow(ctx, s.db, stage.ParentEffectID)
	if err != nil {
		return false, err
	}
	if saved.Generation == 0 || id != stage.ID || plan.DataStageID != stage.ID ||
		!sameValue(plan.Reservation, stage.Reservation) || plan.Inputs == nil || !sameValue(*plan.Inputs, stage.Inputs) ||
		parent.Effect.PlanLaunch == nil || parent.Effect.PlanLaunch.ReservationID != stage.Reservation.ID ||
		!sameValue(parent.Effect, saved.Parent.Record.Effect) || stage.Worker.EffectID != effect.ID ||
		stage.Worker.Kind != "materialize" || stage.Worker.Input != stage.Plan.Input || !sameValue(*effect.Worker, stage.Plan) ||
		stage.Worker.Target != stage.Reservation.Target || stage.Worker.OperationID != effect.OperationID || stage.Worker.GrantSetID != stage.Grants.ID ||
		effect.OperationID != stage.Reservation.OperationID {
		return false, fault(api.CodeIntegrity, "materialization effect lost its retained planning owner")
	}
	// SealDataStage derives this cause from the immutable parent. A kind or
	// effect-ID match alone cannot route foreign work away from reconciliation.
	want := *parent.Effect.Context
	want.ID, want.Kind, want.EffectID = effect.Context.ID, api.InternalLifecycleEffect, stage.Worker.EffectID
	if !sameValue(want, *effect.Context) {
		return false, fault(api.CodeIntegrity, "materialization child changed its original planning cause")
	}
	return true, nil
}
