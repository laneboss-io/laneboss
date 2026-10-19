package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestItem3PublicStrictLevels(t *testing.T) {
	for _, cell := range []string{"lower", "equal", "higher", "l3-spawn"} {
		t.Run(cell, func(t *testing.T) {
			f := newLaunchFixture(t)
			actor := f.parent
			switch cell {
			case "equal":
				f.request.Level = actor.Level
			case "higher":
				f.request.Level = actor.Level + 1
			case "l3-spawn":
				actor.Level, f.request.Level = 3, 3
				actor.Role = "executor"
				parent := f.store.lanes[actor.LifeID]
				parent.Level, parent.Role = actor.Level, actor.Role
				f.store.lanes[parent.LifeID] = parent
				launch := f.store.launches[f.scope.LaunchID]
				launch.Actor = actor
				f.store.launches[launch.ID] = launch
				f.store.policy.Context = api.RoleContext{Level: actor.Level, Role: actor.Role}
			}
			scope := f.fixture.scope("lane.start", f.request, actor)
			before := len(f.store.plans)
			tickets, reads := launchClone(t, f.store.tickets), f.store.ticketReads
			launches, prepared := f.launcher.launched.Load(), f.launcher.prepared.Load()
			operation, err := f.service.LaneStart(context.Background(), scope, f.request)
			if cell == "lower" {
				if err != nil || operation.Status != "pending" || f.store.reservationCalls != 1 || len(f.store.plans) != before+1 {
					t.Fatal("strictly lower public start failed to reserve its genuine child", err)
				}
				return
			}
			requireCode(t, err, api.CodeForbidden)
			if f.store.reservationCalls != 0 || len(f.store.plans) != before || len(f.store.effects) != 0 || f.launcher.launched.Load() != launches || f.launcher.prepared.Load() != prepared || !reflect.DeepEqual(operation, api.Operation{}) || f.store.ticketReads != reads || !reflect.DeepEqual(tickets, f.store.tickets) {
				t.Fatal("equal/higher/L3 public start changed reservation, ticket or launch counts")
			}
		})
	}
}
