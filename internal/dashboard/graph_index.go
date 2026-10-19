package dashboard

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

// Graph inputs are built from one verified snapshot. Requests do not parse
// event timestamps or reconstruct lane/supervisor bindings again.
type graphInputs struct {
	name                      any
	nodes                     []object
	groups                    []object
	activity                  map[string][]time.Time
	problem                   error
	verifyMillis, buildMillis float64
}

const unrecordedSupervisor = "group:unrecorded-supervisor"

func buildGraphInputs(ctx context.Context, c *config.Configuration, lanes, events []object, now time.Time) (*graphInputs, error) {
	org, err := orgView(c, events)
	if err != nil {
		return nil, err
	}
	index := &graphInputs{name: org["name"], nodes: []object{}, groups: []object{}, activity: map[string][]time.Time{}}
	states, ended := map[string]object{}, map[string]object{}
	heartbeats := map[string]object{}
	for _, heartbeat := range heartbeatView(events) {
		heartbeats[str(heartbeat["supervisor"])] = heartbeat
	}
	for _, lane := range laneView(lanes, events, now) {
		states[str(lane["lane"])] = lane
	}
	since := now.Add(-time.Hour)
	for _, e := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e["kind"] == "lane.ended" {
			ended[str(e["lane"])] = e
		}
		at := metricTime(e)
		if at.IsZero() || at.Before(since) {
			continue
		}
		name := str(e["lane"])
		if name == "" {
			name = str(obj(e["payload"])["instance"])
		}
		if name == "" {
			name = str(obj(e["payload"])["supervisor"])
		}
		index.activity[name] = append(index.activity[name], at)
	}
	for name, times := range index.activity {
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		index.activity[name] = times
	}
	add := func(name, kind string, level int, runner, model any) {
		state, source := "unknown", name
		for _, candidate := range []string{name, strings.ToLower(name), strings.TrimPrefix(name, fmt.Sprintf("L%d-", level))} {
			if states[candidate] != nil {
				source = candidate
				break
			}
		}
		if lane := states[source]; lane != nil {
			state = str(lane["state"])
			if !flag(lane["running"]) && ended[source] != nil && (outcome(ended[source]) == "failed" || outcome(ended[source]) == "hook_config_failure") {
				state = "failed"
			}
			if model == nil {
				model = lane["model"]
			}
			if runner == nil {
				runner = lane["runner"]
			}
		}
		var recordedLevel any
		if level >= 3 && level <= 6 {
			recordedLevel = level
		}
		var starter any
		if kind != "lane" {
			if heartbeat := heartbeats[name]; heartbeat != nil {
				switch str(heartbeat["state"]) {
				case "running", "verifying", "idle", "ended", "failed":
					state = str(heartbeat["state"])
				}
				starter = heartbeat["starter"]
			}
		}
		index.nodes = append(index.nodes, object{"id": kind + ":" + name, "name": name, "kind": kind, "level": recordedLevel, "level_source": nil, "runner": runner, "model": model, "state": state, "target": name, "lane": source, "starter": starter, "parent": "human", "parent_recorded": false})
	}
	for _, entry := range org["instances"].([]any) {
		row := obj(entry)
		name, level := str(row["name"]), int(number(row["level"]))
		add(name, "instance", level, row["runner"], row["model"])
	}
	for _, entry := range org["supervisors"].([]any) {
		row := obj(entry)
		// Keep the recorded principal ID even when an instance shares its
		// runner binding. A supervisor:N parent is never renamed to an instance.
		add(str(row["name"]), "supervisor", int(number(row["level"])), row["runner"], row["model"])
	}
	metadata := eventstore.RecordedLaneInfo(events)
	for _, lane := range lanes {
		name := str(lane["lane"])
		info := metadata[name]
		level := info["level"]
		starter := info["starter"]
		add(name, "lane", int(number(level)), lane["runner"], lane["model"])
		index.nodes[len(index.nodes)-1]["starter"] = starter
		index.nodes[len(index.nodes)-1]["level_source"] = info["level_source"]
	}
	known := map[string]bool{"human": true}
	for _, node := range index.nodes {
		known[str(node["id"])] = true
	}
	missing := false
	for _, node := range index.nodes {
		if node["kind"] != "lane" {
			starter := str(node["starter"])
			if starter != "" && starter != node["id"] && known[starter] {
				node["parent"], node["parent_recorded"] = starter, true
			}
			continue
		}
		starter := str(node["starter"])
		if starter != "" && starter != node["id"] && known[starter] {
			node["parent"], node["parent_recorded"] = starter, true
		} else {
			node["parent"] = unrecordedSupervisor
			missing = true
		}
	}
	if missing {
		index.groups = append(index.groups, object{"id": unrecordedSupervisor, "kind": "group", "label": "Unrecorded supervisor", "level": nil, "parent": "human"})
	}
	sort.Slice(index.nodes, func(i, j int) bool {
		if index.nodes[i]["level"] != index.nodes[j]["level"] {
			return number(index.nodes[i]["level"]) > number(index.nodes[j]["level"])
		}
		return str(index.nodes[i]["id"]) < str(index.nodes[j]["id"])
	})
	return index, nil
}

func graphRange(times []time.Time, from, to time.Time) (int, int) {
	first := sort.Search(len(times), func(i int) bool { return !times[i].Before(from) })
	last := sort.Search(len(times), func(i int) bool { return times[i].After(to) })
	return first, last
}

func (index *graphInputs) view(ctx context.Context, now time.Time) (object, error) {
	if index.problem != nil {
		return nil, index.problem
	}
	since := now.Add(-time.Hour)
	nodes := make([]object, 0, len(index.nodes))
	labels := make([]string, 12)
	for i := range labels {
		labels[i] = since.Add(time.Duration(i) * 5 * time.Minute).UTC().Format(time.RFC3339Nano)
	}
	for _, base := range index.nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := object{}
		for key, value := range base {
			row[key] = value
		}
		times := index.activity[str(row["lane"])]
		first, last := graphRange(times, since, now)
		if first == last {
			times = index.activity[str(row["name"])]
			first, last = graphRange(times, since, now)
		}
		series := []any{}
		if first < last {
			for i := range labels {
				start := since.Add(time.Duration(i) * 5 * time.Minute)
				end := start.Add(5 * time.Minute)
				low := sort.Search(len(times), func(j int) bool { return !times[j].Before(start) })
				high := sort.Search(len(times), func(j int) bool {
					if i == 11 {
						return times[j].After(now)
					}
					return !times[j].Before(end)
				})
				series = append(series, object{"time": labels[i], "value": high - low})
			}
		}
		row["series"], row["source"] = series, eventSource(since, now, str(row["lane"]), "")
		nodes = append(nodes, row)
	}
	return object{"name": index.name, "root": object{"id": "human", "kind": "human", "parent": nil, "level": nil}, "groups": index.groups, "nodes": nodes, "since": since.UTC().Format(time.RFC3339Nano)}, nil
}
