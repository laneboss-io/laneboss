//go:build linux

package store

import (
	"context"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestCheckRunningCensus(t *testing.T) {
	for _, mode := range []string{"fresh", "handle", "containment", "generation", "fresh_exit", "retained_exit", "fresh_code", "retained_code", "fresh_signal", "retained_signal", "no_survivors"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			lane := api.Lane{LifeID: testID(t), Run: 1, LaunchID: testID(t), Generation: 1, State: "running"}
			target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
			fixtureProjection(t, s, "lane", lane.LifeID, lane.Generation, lane)
			one, two, code, signal := uint64(1), uint64(2), 0, 15
			retained := api.ProcessObservation{Handle: api.ProcessHandle{ID: testID(t), Target: target, ContainmentID: testID(t), Generation: "census-process"},
				State: "running", Survivors: &one, PromptStatus: "unknown", ObservedAt: "2026-01-01T00:00:00Z"}
			fresh := retained
			fresh.Survivors, fresh.PromptStatus, fresh.ObservedAt = &two, "written", "2026-01-01T00:00:01Z"
			switch mode {
			case "handle":
				fresh.Handle.ID = testID(t)
			case "containment":
				fresh.Handle.ContainmentID = testID(t)
			case "generation":
				fresh.Handle.Generation = "different-process"
			case "fresh_exit":
				fresh.State = "exited"
			case "retained_exit":
				retained.State = "exited"
			case "fresh_code":
				fresh.ExitCode = &code
			case "retained_code":
				retained.ExitCode = &code
			case "fresh_signal":
				fresh.Signal = &signal
			case "retained_signal":
				retained.Signal = &signal
			case "no_survivors":
				fresh.Survivors = nil
			}
			// Pin each helper clause directly as well as the no-write path.
			// Otherwise schema checks could conceal a weakened process fence.
			if sameRunningProcess(fresh, retained) != (mode == "fresh") {
				t.Fatal("running process fence accepted a changed census")
			}
			census := fresh
			switch mode {
			case "fresh_exit":
				census.ExitCode = &code
			case "fresh_code", "fresh_signal":
				census.State = "exited"
			case "no_survivors":
				// An unmeasured census is unknown on the wire. A known
				// state with missing survivors is already schema-invalid.
				census.State = "unknown"
			}
			observed := struct {
				Observation api.ProcessObservation
				Generation  api.Generation
			}{retained, 1}
			fixtureProjection(t, s, "launch_observation", lane.LaunchID, 1, observed)
			input := api.Transaction{Scope: api.Scope{Actor: api.Actor{Kind: "lane", LifeID: lane.LifeID}, Request: testRequest(t, "lane.check", target)},
				Events: []api.Event{{Kind: "run.observed", LifeID: lane.LifeID, Run: lane.Run, Payload: enrollmentJSON(t, census)}}}
			// Use the same schema check as TestNaturalObservationFence before
			// attributing any refusal to the no-write observation fence.
			var decoded api.ProcessObservation
			if err := wire.Decode(input.Events[0].Payload, &decoded); err != nil {
				t.Fatal("census fixture is not schema-valid", err)
			}
			if len(input.Writes.Lanes) != 0 || sameValue(census, retained) {
				t.Fatal("census fixture missed the no-write exception path")
			}
			err := s.validateNaturalCompletion(ctx, s.db, input)
			if mode == "fresh" {
				if err != nil {
					t.Fatal("same running process rejected its fresh census", err)
				}
				return
			}
			expectCode(t, err, api.CodeForbidden)
			if !strings.Contains(err.Error(), "(observation)") {
				t.Fatal("census was refused outside its process fence", err)
			}
		})
	}
}
