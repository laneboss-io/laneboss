//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestPolicyHistoryIntegrity(t *testing.T) {
	for _, problem := range []string{"future", "hash", "ambiguous"} {
		t.Run(problem, func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "worker"}
			first := api.EffectivePolicy{Generation: 1, SHA256: testDigest([]byte("first policy"))}
			fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 1, first)
			current := first
			current.Generation = 2
			current.SHA256 = testDigest([]byte("current policy"))
			fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 2, current)
			if actual, err := s.PolicyAt(ctx, scope, 1); err != nil || !sameValue(actual, first) {
				t.Fatal("retained policy history control failed", err)
			}
			generation := api.Generation(1)
			if problem == "hash" {
				// Install malformed historical evidence once in a separate
				// corruption fixture. Never update immutable history or disable
				// the real trigger just to reach the reader's digest guard.
				s, _ = testStore(t)
				fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 2, current)
				if _, err := s.db.ExecContext(ctx, "INSERT INTO projection_history(kind,id,data,sha256) VALUES('policy',?,?,?)", s.deps.Config, enrollmentJSON(t, first), string(testDigest([]byte("changed bytes")))); err != nil {
					t.Fatal(err)
				}
			} else if problem == "ambiguous" {
				// Conflicting historical generations go through the actual
				// publisher/CAS path and must return a typed conflict, without
				// inserting a duplicate immutable history row.
				other := first
				other.SHA256 = testDigest([]byte("conflicting policy"))
				cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: s.deps.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
				if _, err := s.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{Policy: &other}}); err == nil {
					t.Fatal("policy history accepted ambiguous")
				} else {
					expectCode(t, err, api.CodeConflict)
				}
				actual, err := s.PolicyAt(ctx, scope, first.Generation)
				if err != nil || !sameValue(actual, first) {
					t.Fatal("conflicting policy replaced immutable history", err)
				}
				return
			} else {
				other := first
				other.SHA256 = testDigest([]byte("unapproved policy history"))
				if problem == "future" {
					other.Generation = 3
					generation = 3
				}
				data := enrollmentJSON(t, other)
				if _, err := s.db.ExecContext(ctx, "INSERT INTO projection_history(kind,id,data,sha256) VALUES('policy',?,?,?)", s.deps.Config, data, string(testDigest(data))); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.PolicyAt(ctx, scope, generation); err == nil {
				t.Fatal("policy history accepted " + problem)
			}
		})
	}
}

func TestPolicyRefreshJournal(t *testing.T) {
	t.Run("journal_head", func(t *testing.T) {
		s, _ := testStore(t)
		ctx := context.Background()
		before := api.Lane{LifeID: testID(t), Run: 1, Generation: 1, PolicyGeneration: 1, GrantSetID: testID(t), State: "running"}
		current := api.EffectivePolicy{Generation: 2, SHA256: testDigest([]byte("approved policy"))}
		fixtureProjection(t, s, "lane", before.LifeID, 1, before)
		fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 2, current)
		next := before
		next.Generation++
		next.PolicyGeneration = 2
		next.LastSeq = 1
		payload := api.PolicyAdvanceEvent{FromGeneration: 1, ToGeneration: 2, LaneGeneration: 2, PolicySHA256: current.SHA256, GrantSetID: before.GrantSetID}
		event := api.Event{ID: testID(t), Kind: "lane.policy", LifeID: before.LifeID, Run: 1, Origin: "service", Payload: enrollmentJSON(t, payload)}
		input := api.Transaction{Internal: &api.InternalIntent{Target: api.LifeRef{LifeID: before.LifeID, Run: 1}}, Writes: api.StateWrites{Lanes: []api.Lane{next}}, Events: []api.Event{event}}
		if err := s.validatePolicyRefresh(ctx, s.db, input); err != nil {
			t.Fatal("actual policy journal head control failed", err)
		}
		input.Writes.Lanes[0].LastSeq = 999
		if err := s.validatePolicyRefresh(ctx, s.db, input); err == nil {
			t.Fatal("policy refresh accepted a caller supplied journal sequence")
		}
	})
}

func TestNaturalObservationFence(t *testing.T) {
	t.Run("still_running", func(t *testing.T) {
		s, _ := testStore(t)
		ctx := context.Background()
		before := api.Lane{LifeID: testID(t), Run: 1, LaunchID: testID(t), Generation: 1, State: "running", Containment: "running"}
		fixtureProjection(t, s, "lane", before.LifeID, 1, before)
		target := api.LifeRef{LifeID: before.LifeID, Run: 1}
		survivors, exitCode := uint64(0), 0
		observation := api.ProcessObservation{
			State: "exited", Survivors: &survivors, ExitCode: &exitCode,
			Handle:       api.ProcessHandle{ID: testID(t), Target: target, ContainmentID: testID(t), Generation: "fixture-process"},
			PromptStatus: "completed", ObservedAt: "2026-01-01T00:00:00Z",
		}
		observed := struct {
			Observation api.ProcessObservation
			Generation  api.Generation
		}{observation, 1}
		fixtureProjection(t, s, "launch_observation", before.LaunchID, observed.Generation, observed)
		next := before
		next.Generation++
		next.State, next.Containment = "verifying", "quiescent"
		end := api.RunEndEvent{LaunchID: before.LaunchID, Reason: "exit", Observation: observation, BudgetRemaining: next.BudgetRemaining}
		input := api.Transaction{
			Scope:   api.Scope{Actor: api.Actor{Kind: "lane", LifeID: before.LifeID}, Request: testRequest(t, "lane.check", target)},
			Writes:  api.StateWrites{Lanes: []api.Lane{next}},
			Compare: []api.Compare{{Kind: api.CompareLane, ID: before.LifeID, Generation: before.Generation}},
			Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: before.LifeID, Epoch: before.CancellationEpoch}}},
			Events: []api.Event{
				{Kind: "lane.ended", LifeID: before.LifeID, Run: 1, Payload: enrollmentJSON(t, end)},
				{Kind: "lane.state", LifeID: before.LifeID, Run: 1, Payload: enrollmentJSON(t, api.StateEvent{From: before.State, To: next.State, Generation: next.Generation})},
			},
		}
		if err := s.validateNaturalCompletion(ctx, s.db, input); err != nil {
			t.Fatal("zero-survivor natural completion control failed", err)
		}

		// Keep the events schema-valid when changing only the retained process
		// observation, so a later decoder refusal cannot mask this fence.
		observation.State, observation.ExitCode, survivors = "running", nil, 1
		observed.Observation = observation
		observed.Generation++
		fixtureProjection(t, s, "launch_observation", before.LaunchID, observed.Generation, observed)
		end.Observation = observation
		input.Events[0].Payload = enrollmentJSON(t, end)
		var decoded api.RunEndEvent
		if err := wire.Decode(input.Events[0].Payload, &decoded); err != nil {
			t.Fatal("running observation fixture is not schema-valid", err)
		}
		err := s.validateNaturalCompletion(ctx, s.db, input)
		if err == nil {
			t.Fatal("natural completion accepted a still running observation")
		}
		expectCode(t, err, api.CodeContainmentUnknown)
	})
}
