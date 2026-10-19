package dashboard

import (
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

// Lifecycle labels are derived only from the recorded kind and payload. The
// actor remains the envelope's principal ID; readers never supply a caller.
func lifecycleStep(event object) any {
	p := obj(event["payload"])
	switch event["kind"] {
	case "lane.started":
		if _, turn := p["mail"]; turn && p["how"] == "resume" {
			return "turn"
		}
		if p["how"] == "resume" {
			return "resume"
		}
		return "start"
	case "lane.adopted":
		return "adopt"
	case "lane.resumed":
		return "resume"
	case "lane.ended":
		if p["reason"] == "stopped" {
			return "stop"
		}
		return "ended"
	case "lane.state":
		switch p["state"] {
		case "accepted", "abandoned", "merged":
			return p["state"]
		}
		return "state"
	case "lane.merged":
		return "merged"
	case "lane.cleaned":
		return "clean"
	case "lane.lost":
		return "lost"
	}
	return nil
}

func eventBoard(c *config.Configuration, events []eventstore.Object, selection eventOptions, now time.Time) (any, error) {
	overview, err := orgView(c, events)
	if err != nil {
		return nil, err
	}
	levels := map[string]int{}
	for _, group := range []string{"instances", "supervisors"} {
		for _, entry := range overview[group].([]any) {
			row := obj(entry)
			levels[str(row["name"])] = int(number(row["level"]))
		}
	}
	counts := object{}
	matched := []eventstore.Object{}
	matchedLevels := []int{}
	since := now.Add(-time.Hour)
	metadata := map[string]object{}
	for _, event := range events {
		if !eventstore.ExternallyAppended(event) && (event["kind"] == "lane.started" || event["kind"] == "lane.adopted") {
			metadata[str(event["lane"])] = obj(event["payload"])
		}
		meta := metadata[str(event["lane"])]
		if selection.runner != "" && meta["runner"] != selection.runner || selection.model != "" && meta["model"] != selection.model {
			continue
		}
		if selection.account != "" && meta["account"] != selection.account || selection.rule != "" && obj(event["payload"])["guard"] != selection.rule {
			continue
		}
		if selection.outcome != "" && (event["kind"] != "lane.ended" || outcome(event) != selection.outcome) {
			continue
		}
		at := metricTime(event)
		if !selection.since.IsZero() && at.Before(selection.since) || !selection.until.IsZero() && at.After(selection.until) {
			continue
		}
		level := eventLevel(event, levels, metadata)
		if selection.lane != "" && event["lane"] != selection.lane || selection.kind != "" && event["kind"] != selection.kind || selection.level != 0 && level != selection.level {
			continue
		}
		matched = append(matched, event)
		matchedLevels = append(matchedLevels, level)
		at, err = time.Parse(time.RFC3339Nano, str(when(event)))
		if err == nil && !at.Before(since) && !at.After(now) {
			kind := str(event["kind"])
			counts[kind] = int(number(counts[kind])) + 1
		}
	}
	rows := eventView(matched, selection.limit)
	for i, row := range rows {
		level := matchedLevels[len(matchedLevels)-1-i]
		row["level"] = nil
		if level != 0 {
			row["level"] = level
		}
	}
	if !selection.board {
		return rows, nil
	}
	return object{"events": rows, "counts_last_hour": counts, "since": since.UTC().Format(time.RFC3339Nano)}, nil
}

func eventLevel(event object, levels map[string]int, metadata map[string]object) int {
	p := obj(event["payload"])
	if level, ok := eventstore.RecordedLevel(p["level"]).(int); ok {
		return level
	}
	if lane := str(event["lane"]); lane != "" {
		if level, ok := eventstore.RecordedLevel(metadata[lane]["level"]).(int); ok {
			return level
		}
		return 0
	}
	for _, name := range []string{str(p["instance"]), str(p["supervisor"])} {
		if level := levels[name]; level != 0 {
			return level
		}
	}
	return 0
}
