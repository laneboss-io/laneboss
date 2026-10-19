package dashboard

import (
	"context"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

func nowView(ctx context.Context, c *config.Configuration, binding *eventstore.Configuration, lanes, events []object, now time.Time, cache *eventstore.UsageCache) (object, error) {
	a, err := analytics(ctx, binding, lanes, events, "24h", 15, now, cache)
	if err != nil {
		return nil, err
	}
	d, err := decisionView(binding, "", lanes)
	if err != nil {
		return nil, err
	}
	health, err := healthView(c, events)
	if err != nil {
		return nil, err
	}
	since := now.Add(-24 * time.Hour)
	series := map[string][]object{}
	for _, row := range eventstore.DisplayHistory(events, now, 15*time.Minute) {
		for _, key := range []string{"running", "stuck"} {
			series[key] = append(series[key], object{"time": row["time"], "value": row[key], "source": eventSource(since, now, "", "")})
		}
	}
	turns, refusals, changed := 0, 0, 0
	targets := map[string]map[string]bool{}
	for _, key := range []string{"running", "turns", "refusals", "stuck", "decisions", "disk"} {
		targets[key] = map[string]bool{}
	}
	turnHours, refusalHours, decisionHours := map[string]int{}, map[string]int{}, map[string]int{}
	for _, row := range obj(a["usage"])["rows"].([]object) {
		for _, record := range row["records"].([]any) {
			r := obj(record)
			at, _ := time.Parse(time.RFC3339Nano, str(r["time"]))
			turnHours[hour(at)]++
			if inWindow(at, now.Add(-5*time.Minute), now) {
				turns++
				targets["turns"][str(row["lane"])] = true
			}
		}
	}
	for _, row := range a["refusals"].([]object) {
		refusalHours[str(row["hour"])] += int(number(row["count"]))
	}
	for _, e := range events {
		at := metricTime(e)
		if e["kind"] == "lane.refusal" && inWindow(at, now.Add(-time.Hour), now) {
			refusals++
			targets["refusals"][str(e["lane"])] = true
		}
		if strings.HasPrefix(str(e["kind"]), "disk.") && obj(e["payload"])["free_bytes"] != nil && inWindow(at, since, now) {
			series["disk"] = append(series["disk"], object{"time": at.UTC().Format(time.RFC3339Nano), "value": obj(e["payload"])["free_bytes"], "source": eventSource(since, now, "", str(e["kind"]))})
		}
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	for _, change := range d["changes"].([]object) {
		at, parseErr := time.Parse(time.RFC3339Nano, str(change["time"]))
		if parseErr == nil && inWindow(at, since, now) {
			decisionHours[hour(at)]++
			if !at.Before(today) {
				changed++
				targets["decisions"][str(change["id"])] = true
			}
		}
	}
	for key, counts := range map[string]map[string]int{"turns": turnHours, "refusals": refusalHours, "decisions": decisionHours} {
		if len(counts) == 0 {
			continue
		}
		for at := since.UTC().Truncate(time.Hour); !at.After(now); at = at.Add(time.Hour) {
			series[key] = append(series[key], object{"time": at.Format(time.RFC3339), "value": counts[hour(at)], "source": "/api/analytics?window=24h"})
		}
	}
	running := 0
	for _, lane := range laneView(lanes, events, now) {
		if lane["state"] == "running" {
			running++
			targets["running"][str(lane["lane"])] = true
		}
	}
	for _, lane := range a["stuck"].([]object) {
		targets["stuck"][str(lane["lane"])] = true
	}
	var runningValue, stuckValue, turnValue, refusalValue, changedValue any
	if len(lanes) > 0 {
		runningValue, stuckValue = running, len(a["stuck"].([]object))
	}
	if len(turnHours) > 0 {
		turnValue = turns
	}
	if len(events) > 0 {
		refusalValue = refusals
	}
	if flag(d["available"]) && flag(obj(d["integrity"])["ok"]) {
		changedValue = changed
	}
	metrics := []object{}
	for _, entry := range []object{
		{"key": "running", "label": "Running lanes", "value": runningValue, "source": "/api/lanes"},
		{"key": "turns", "label": "Turns · last 5 min", "value": turnValue, "partial": obj(a["usage"])["partial"], "source": "/api/analytics?window=24h"},
		{"key": "refusals", "label": "Refusals · last hour", "value": refusalValue, "source": eventSource(now.Add(-time.Hour), now, "", "lane.refusal")},
		{"key": "stuck", "label": "Stuck · 15 min idle", "value": stuckValue, "source": "/api/analytics?window=24h"},
		{"key": "decisions", "label": "Decisions changed · UTC today", "value": changedValue, "source": "/api/decisions"},
		{"key": "disk", "label": "Disk free", "value": obj(health["disk"])["free_bytes"], "unit": "bytes", "source": "/api/health"},
	} {
		key := str(entry["key"])
		names := []string{}
		for name := range targets[key] {
			if name != "" {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		entry["targets"] = names
		entry["series"] = series[key]
		if series[key] == nil {
			entry["series"] = []object{}
		}
		if key == "decisions" {
			for _, point := range series[key] {
				point["source"] = "/api/decisions"
			}
		}
		metrics = append(metrics, entry)
	}
	return object{"time": now.UTC().Format(time.RFC3339Nano), "metrics": metrics}, nil
}
