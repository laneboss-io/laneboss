package lifecycle

import (
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only the store-issued private manifest replaces a public request frame.
// The original service PlanLaunch claim remains the executor's authority.
func (execution *planExecution) loopInput(raw []byte) error {
	r := execution.record.Reservation
	var cause api.LoopTurnCause
	if r.Loop == nil || api.ValidateLaunchReservation(r) != nil || api.DecodeObject(raw, &cause) != nil ||
		!reflect.DeepEqual(cause, *r.Loop) || digestOfBytes(raw) != r.RequestSHA256 ||
		execution.input.turn != cause.LogicalTurnID || execution.lease.Record.Effect.ID != cause.PlanEffectID {
		return integrity("loop manifest differs from its reserved causal input")
	}
	execution.input.task, execution.input.budget = *cause.Setting.IdleMessage, cause.BudgetRemaining
	execution.input.role, execution.input.driver = api.RoleContext{Level: r.Level, Role: r.Role}, r.Driver
	return nil
}
