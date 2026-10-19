//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestTurnEnvelopeStore(t *testing.T) {
	for _, mode := range []string{"retained", "written", "run", "life", "missing", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			turn := api.TurnSnapshot{Target: api.LifeRef{LifeID: testID(t), Run: 1}, LogicalTurnID: testID(t), Generation: 1}
			fixtureProjection(t, s, "turn", turn.LogicalTurnID, 1, turn)
			event := api.Event{Kind: "lane.turn", LifeID: turn.Target.LifeID, Run: turn.Target.Run, LogicalTurnID: turn.LogicalTurnID}
			input := api.Transaction{Events: []api.Event{event}}
			if err := s.validateLaunchTransaction(ctx, s.db, input); err != nil {
				t.Fatal("retained turn envelope control failed", err)
			}
			if mode == "retained" {
				return
			}
			if mode == "written" {
				turn.LogicalTurnID = testID(t)
				input.Events[0].LogicalTurnID = turn.LogicalTurnID
				input.Writes.Turns = []api.TurnSnapshot{turn}
				if err := s.validateLaunchTransaction(ctx, s.db, input); err != nil {
					t.Fatal("same-transaction turn envelope control failed", err)
				}
				return
			}
			switch mode {
			case "run":
				input.Events[0].Run++
			case "life":
				input.Events[0].LifeID = testID(t)
			case "missing":
				input.Events[0].LogicalTurnID = ""
			case "foreign":
				input.Events[0].LogicalTurnID = testID(t)
			}
			if err := s.validateLaunchTransaction(ctx, s.db, input); err == nil {
				t.Fatal("turn envelope escaped its real snapshot")
			}
		})
	}
}
