package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Caller has already checked the actual opened plan and retained native
// process. Completion, the selected slot and swapped event share that commit.
func (s *Service) finishCont(ctx context.Context, tx *sql.Tx, scope api.Scope, plan api.LaunchPlanRecord, effect api.EffectRecord) (api.Sequence, error) {
	r := plan.Reservation
	var owner launchOwner
	if err := storedProjection(ctx, tx, "launch_operation", r.OperationID, &owner); err != nil {
		return 0, err
	}
	var selected continuationClaim
	if err := storedProjection(ctx, tx, "continuation_claim", owner.Request.ContinuationID, &selected); err != nil {
		return 0, err
	}
	if !selected.Planning {
		return 0, nil
	}
	var i api.ContinuationIntent
	if err := storedProjection(ctx, tx, "continuation", owner.Request.ContinuationID, &i); err != nil {
		return 0, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, tx, "lane", r.Target.LifeID, &lane); err != nil {
		return 0, err
	}
	if plan.Phase != "opened" || plan.Plan == nil || selected.Input.Intent.EffectID != effect.Effect.ID || i.Status != "claimed" || i.OperationID != r.OperationID || i.Swap.OperationID != r.OperationID || i.Target.LifeID != r.Target.LifeID || i.Target.Run+1 != r.Target.Run || i.CancellationEpoch != r.CancellationEpoch || !sameValue(i.Swap, selected.Input.Request.Swap) || i.Slot == nil || *i.Slot != plan.Plan.Runner.Slot || lane.Run != r.Target.Run || lane.LaunchID != r.LaunchID || lane.CancellationEpoch != r.CancellationEpoch || lane.LogicalTurnID != i.LogicalTurnID || lane.State != "running" {
		return 0, fault(api.CodeConflict, "opened continuation lost its claimed slot, turn or cancellation fence")
	}
	var unfinished int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND effects.id<>? AND (json_extract(effect_states.data,'$.Outcome') IS NULL OR json_extract(effect_states.data,'$.State')='failed')", string(r.OperationID), string(effect.Effect.ID)).Scan(&unfinished); err != nil {
		return 0, err
	}
	if unfinished != 0 {
		return 0, fault(api.CodeConflict, "continuation has unfinished or failed durable stages")
	}
	i.Status, i.Generation = "completed", i.Generation+1
	if err := put(ctx, tx, "continuation", i.ID, i.Generation, i); err != nil {
		return 0, err
	}
	id, err := wire.NewID()
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(api.WatchdogEvent{Signal: &i.Swap.Limit, Swap: &i.Swap, Reason: "profile continuation opened", BudgetRemaining: lane.BudgetRemaining})
	if err != nil {
		return 0, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: r.Config, Kind: "watchdog.swapped", Actor: scope.Actor, RequestedBy: r.RequestedBy, RequestID: r.RequestID,
		OperationID: r.OperationID, LifeID: r.Target.LifeID, Run: r.Target.Run, LogicalTurnID: i.LogicalTurnID, Origin: "service", Payload: payload,
		RootLifeID: r.RootLifeID, ParentLifeID: r.ParentLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq}
	return appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
}
