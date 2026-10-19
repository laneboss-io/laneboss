package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestStopEndedRun(t *testing.T) {
	for _, outcome := range []string{"exit", "failure", "signal"} {
		t.Run(outcome, func(t *testing.T) {
			f := newFixture(t)
			fixtureActiveRun(f)
			if outcome == "failure" {
				exit := 1
				f.launcher.observation.ExitCode = &exit
			} else if outcome == "signal" {
				signal := 15
				f.launcher.observation.ExitCode, f.launcher.observation.Signal = nil, &signal
			}
			if _, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target); err != nil {
				t.Fatal("cannot commit the naturally ended run", err)
			}
			before := f.store.lanes[f.target.LifeID]
			end := f.store.events[len(f.store.events)-2]
			if before.State != "verifying" || end.Kind != "lane.ended" {
				t.Fatal("service did not retain the actual pre-stop terminal state")
			}
			reason := f.blob("terminal-stop-reason", "task", []byte("stop this already ended run\n"))
			request := api.StopRequest{Target: f.target, ExpectedGeneration: before.Generation, Reason: reason}
			scope := f.scope("lane.stop", request, f.parent)
			transactions, sequence, observations := len(f.store.transactions), f.store.seq, f.launcher.observed.Load()
			operation, err := f.service.LaneStop(context.Background(), scope, request)
			if err != nil {
				t.Fatal("stop refused a committed naturally ended run", err)
			}
			var result struct {
				Stop *struct {
					State       string          `json:"state"`
					EndEventID  api.ID          `json:"end_event_id"`
					EndSequence api.Sequence    `json:"end_sequence"`
					End         api.RunEndEvent `json:"end"`
				} `json:"stop"`
			}
			raw, err := json.Marshal(operation)
			if err != nil || json.Unmarshal(raw, &result) != nil || operation.Status != "succeeded" || result.Stop == nil ||
				result.Stop.State != before.State || result.Stop.EndEventID != end.ID || result.Stop.EndSequence != end.Seq ||
				!sameJSON(end.Payload, mustJSON(t, result.Stop.End)) || operation.LifeID != f.target.LifeID || operation.Run != f.target.Run {
				t.Fatal("terminal stop lost its typed actual state and committed end")
			}
			if !reflect.DeepEqual(f.store.lanes[f.target.LifeID], before) || f.store.seq != sequence ||
				len(f.store.transactions) != transactions+1 || f.launcher.observed.Load() != observations {
				t.Fatal("terminal stop changed the lane or repeated physical observation")
			}
			tx := f.store.transactions[len(f.store.transactions)-1]
			if len(tx.Events) != 0 || len(tx.Effects) != 0 || len(tx.Writes.Lanes) != 0 || len(tx.Compare) != 1 || len(tx.Guards) != 1 {
				t.Fatal("terminal stop emitted another stop/end or lost its writer fences")
			}
			replay, err := f.service.LaneStop(context.Background(), scope, request)
			if err != nil || !reflect.DeepEqual(operation, replay) || len(f.store.transactions) != transactions+1 {
				t.Fatal("terminal stop did not replay its exact receipt", err)
			}
			t.Logf("service records before stop: state=%s end_reason=%s observation=%s; terminal stop replay retained", before.State, result.Stop.End.Reason, result.Stop.End.Observation.State)
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStopTerminalGuards(t *testing.T) {
	for _, mode := range []string{"never-started", "abandoned", "merged", "cleaned", "no-end", "survivors", "unknown", "foreign-launch", "stale-generation", "missing-reason"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			lane := f.store.lanes[f.target.LifeID]
			lane.State, lane.Containment = "verifying", "quiescent"
			want := api.CodeConflict
			switch mode {
			case "never-started":
				lane.State = "failed"
				f.store.events = nil
			case "abandoned", "merged":
				lane.State = mode
			case "cleaned":
				lane.Cleaned = true
			case "no-end":
				fixtureActiveRun(f)
				f.store.events = f.store.events[1:]
			case "survivors", "unknown", "foreign-launch":
				var end api.RunEndEvent
				if err := api.DecodeObject(f.store.events[0].Payload, &end); err != nil {
					t.Fatal(err)
				}
				if mode == "survivors" {
					one := uint64(1)
					end.Observation.Survivors = &one
					want = api.CodeIntegrity
				} else if mode == "unknown" {
					end.Reason = "service_lost"
				} else {
					end.LaunchID = "foreign-launch"
					want = api.CodeNotFound
				}
				f.store.events[0].Payload = mustJSON(t, end)
			}
			f.store.lanes[lane.LifeID] = lane
			reason := f.blob("terminal-stop-reason", "task", []byte("retained reason\n"))
			request := api.StopRequest{Target: f.target, ExpectedGeneration: lane.Generation, Reason: reason}
			if mode == "stale-generation" {
				request.ExpectedGeneration++
			} else if mode == "missing-reason" {
				delete(f.store.blobs, reason.ID)
				want = api.CodeNotFound
			}
			_, err := f.service.LaneStop(context.Background(), f.scope("lane.stop", request, f.parent), request)
			requireCode(t, err, want)
			if len(f.store.transactions) != 0 {
				t.Fatal("illegal terminal stop committed effects or a success receipt")
			}
		})
	}
}
