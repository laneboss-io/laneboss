package policy

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestStableSkipApproval(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func(*fixture)
	}{
		{"launch", func(f *fixture) {
			f.scope.Actor.ID, f.scope.LaunchID = "actor-b", "launch-b"
			f.store.lane.LaunchID = f.scope.LaunchID
			f.store.launch.ID, f.store.launch.Actor = f.scope.LaunchID, f.scope.Actor
		}},
		{"turn", func(f *fixture) {
			f.request.LogicalTurnID, f.store.lane.LogicalTurnID, f.store.turn.LogicalTurnID = "turn-b", "turn-b", "turn-b"
			f.store.turn.Generation++
		}},
		{"grants", func(f *fixture) { f.store.grants.Generation++; f.store.lane.Generation++ }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			installSkip(t, f)
			f.evaluate(t)
			if f.evaluate(t).SkipID == "" {
				t.Fatal("stable skip approval was not reusable")
			}
			approved := f.store.policy.Skip[0].ContextSHA256
			row.edit(f)
			current, err := SkipContextDigest(f.scope.Config, f.request.Command, f.store.policy)
			if err != nil || current != approved {
				t.Fatal("approved work digest bound ephemeral launch/turn facts")
			}
			warm := f.evaluate(t)
			if warm.SkipID != "" || warm.CacheOf != "" || len(f.judge.requests) != 2 || warm.Rules[0].Probability == nil {
				t.Fatal("new authority context reused another positive proof")
			}
			skipped := f.evaluate(t)
			if skipped.SkipID == "" || skipped.CacheOf != warm.ID || len(f.judge.requests) != 2 {
				t.Fatal("stable skip approval was not reusable")
			}
		})
	}
}

func TestHumanCannotSeedLaneSkip(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	installSkip(t, f)
	lane := f.scope
	f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
	f.evaluate(t)
	f.scope = lane
	warm := f.evaluate(t)
	if warm.SkipID != "" || warm.CacheOf != "" || len(f.judge.requests) != 2 {
		t.Fatal("human preview seeded a lane positive proof")
	}
	if skipped := f.evaluate(t); skipped.SkipID == "" || skipped.CacheOf != warm.ID {
		t.Fatal("lane's own scored proof was not reusable")
	}
}
