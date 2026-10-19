package eventstore

import (
	"time"
)

// DisplayHistory replays the CLI projection reducer, rather than inventing a
// second definition of running. It exposes counts only, never projection text.
func DisplayHistory(events []Object, now time.Time, idle time.Duration) []Object {
	if len(events) == 0 {
		return []Object{}
	}
	type timedEvent struct {
		event Object
		at    time.Time
	}
	timed := make([]timedEvent, 0, len(events))
	at := func(e Object) time.Time {
		stamp := text(e["recorded_at"])
		value, _ := time.Parse(time.RFC3339Nano, stamp)
		return value
	}
	for _, e := range events {
		timed = append(timed, timedEvent{event: e, at: at(e)})
	}
	projections, latest := map[string]Object{}, map[string]time.Time{}
	result := []Object{}
	index := 0
	end := now.Add(-24 * time.Hour)
	for {
		for index < len(timed) && !timed[index].at.After(end) {
			e := timed[index].event
			lane := text(e["lane"])
			if lane != "" {
				latest[lane] = timed[index].at
				if occurred, err := time.Parse(time.RFC3339Nano, text(e["occurred_at"])); err == nil {
					latest[lane] = occurred
				}
				if projections[lane] == nil {
					projections[lane] = empty(lane)
				}
				apply(projections[lane], e)
			}
			index++
		}
		running, stuck := 0, 0
		for lane, p := range projections {
			if p["running"] == true {
				if p["state"] != "verifying" {
					running++
				}
				if end.Sub(latest[lane]) > idle {
					stuck++
				}
			}
		}
		var runningValue, stuckValue any
		if len(projections) > 0 {
			runningValue, stuckValue = running, stuck
		}
		result = append(result, Object{"time": end.UTC().Format(time.RFC3339Nano), "running": runningValue, "stuck": stuckValue})
		if end.Equal(now) {
			break
		}
		end = end.UTC().Truncate(time.Hour).Add(time.Hour)
		if end.After(now) {
			end = now
		}
	}
	return result
}
