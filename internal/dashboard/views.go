package dashboard

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/disk"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/orgtree"
)

type object = map[string]any

func urlQuery(raw string) (url.Values, error) { return url.ParseQuery(raw) }
func obj(value any) object                    { result, _ := value.(object); return result }
func str(value any) string                    { result, _ := value.(string); return result }
func flag(value any) bool                     { result, _ := value.(bool); return result }
func number(value any) float64 {
	switch n := value.(type) {
	case int64:
		return float64(n)
	case float64:
		return n
	case int:
		return float64(n)
	case json.Number:
		value, _ := n.Float64()
		return value
	}
	return 0
}
func when(event object) any {
	if str(event["occurred_at"]) != "" {
		return event["occurred_at"]
	}
	return event["recorded_at"]
}
func capText(text string) string {
	runes := []rune(text)
	if len(runes) > 200 {
		return string(runes[:199]) + "…"
	}
	return text
}
func hasWithheld(value any) bool {
	switch v := value.(type) {
	case string:
		return v == "[withheld]"
	case object:
		for key, item := range v {
			if key == "[withheld]" || hasWithheld(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if hasWithheld(item) {
				return true
			}
		}
	}
	return false
}

// Summaries expose operational metadata, never prompts, messages, environment
// tables, commands or file contents. Screen the whole payload BEFORE capping so
// a credential crossing the cap cannot leave a fragment on the page.
func summary(event object) string {
	payload := obj(screen(event["payload"]))
	parts := []string{}
	if eventstore.ExternallyAppended(event) {
		parts = append(parts, "Externally appended lifecycle event")
	}
	if hasWithheld(payload) {
		parts = append(parts, "[withheld]")
	}
	for _, key := range strings.Fields("state status reason run runner model exit_code budget_minutes duration_seconds survivors count free_bytes used_percent guard rule rule_id legacy_relationship") {
		value, exists := payload[key]
		if !exists || value == nil {
			continue
		}
		switch value.(type) {
		case string, bool, float64, int64, int, json.Number:
			parts = append(parts, key+"="+fmt.Sprint(value))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d payload fields recorded", len(payload)))
	}
	return capText(strings.Join(parts, "; "))
}

func eventView(events []eventstore.Object, limit int) []object {
	result := []object{}
	for i := len(events) - 1; i >= 0 && len(result) < limit; i-- {
		e := events[i]
		result = append(result, object{"id": e["id"], "seq": e["seq"], "time": when(e), "lane": e["lane"], "kind": e["kind"], "actor": e["actor"], "externally_appended": eventstore.ExternallyAppended(e), "step": lifecycleStep(e), "summary": summary(e)})
	}
	return result
}

func laneView(lanes, events []eventstore.Object, now time.Time) []object {
	metadata := eventstore.RecordedLaneInfo(events)
	last, started, ended := map[string]object{}, map[string]object{}, map[string]object{}
	for _, e := range events {
		name := str(e["lane"])
		if name == "" {
			continue
		}
		last[name] = e
		if eventstore.ExternallyAppended(e) {
			continue
		}
		if e["kind"] == "lane.started" || e["kind"] == "lane.adopted" {
			started[name] = e
		}
		if e["kind"] == "lane.ended" {
			ended[name] = e
		}
	}
	result := []object{}
	for _, lane := range lanes {
		name := str(lane["lane"])
		state := "idle"
		if lane["state"] == "verifying" {
			state = "verifying"
		} else if flag(lane["running"]) {
			state = "running"
		} else if lane["state"] != nil && lane["state"] != "waiting" && lane["state"] != "planned" && (started[name] != nil || ended[name] != nil) {
			state = "ended"
		}
		var at, budget, lastEvent, lastExit any
		if e := started[name]; e != nil {
			at = when(e)
			began, err := time.Parse(time.RFC3339Nano, str(at))
			if err == nil && flag(lane["running"]) {
				elapsed := max(0, now.Sub(began).Seconds())
				budget = math.Round(max(0, number(screen(obj(e["payload"])["budget_minutes"]))*60-elapsed))
			}
		}
		if e := last[name]; e != nil {
			lastEvent = object{"time": when(e), "kind": e["kind"], "summary": summary(e)}
		}
		if e := ended[name]; e != nil {
			lastExit = obj(e["payload"])["exit_code"]
		}
		info := metadata[name]
		result = append(result, object{"lane": lane["lane"], "state": state, "recorded_state": lane["state"], "running": lane["running"], "runner": lane["runner"], "model": lane["model"], "started": at, "budget_left_seconds": budget, "last_event": lastEvent, "last_exit": lastExit, "level": info["level"], "level_source": info["level_source"], "starter": info["starter"]})
	}
	return result
}

func refusalView(events []eventstore.Object) []object {
	result := []object{}
	for i := len(events) - 1; i >= 0 && len(result) < 100; i-- {
		e := events[i]
		if e["kind"] != "lane.refusal" {
			continue
		}
		p := obj(screen(e["payload"]))
		message := obj(p["message"])
		text := str(message["text"])
		if flag(message["withheld"]) || hasWithheld(message) {
			text = "[withheld]"
		}
		at := p["at"]
		if at == nil || at == "" {
			at = when(e)
		}
		result = append(result, object{"rule_id": p["guard"], "refusal": p["refusal"], "lane": e["lane"], "time": at, "text": capText(text), "kind": p["kind"]})
	}
	return result
}

func heartbeatView(events []eventstore.Object) []object {
	latest := map[string]object{}
	for _, e := range events {
		if !strings.HasSuffix(str(e["kind"]), ".heartbeat") {
			continue
		}
		p := obj(e["payload"])
		name := str(p["supervisor"])
		if name == "" {
			name = str(p["instance"])
		}
		if name == "" {
			name = str(e["lane"])
		}
		if name == "" {
			continue
		}
		candidate := object{"supervisor": name, "time": when(e), "runner": p["runner"], "model": p["model"], "state": p["state"], "starter": p["starter"]}
		previous := latest[name]
		oldTime, oldErr := time.Parse(time.RFC3339Nano, str(previous["time"]))
		newTime, newErr := time.Parse(time.RFC3339Nano, str(candidate["time"]))
		if previous == nil || oldErr != nil || newErr == nil && !newTime.Before(oldTime) {
			latest[name] = candidate
		}
	}
	keys := make([]string, 0, len(latest))
	for name := range latest {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	result := []object{}
	for _, name := range keys {
		result = append(result, latest[name])
	}
	return result
}

func orgView(c *config.Configuration, events []eventstore.Object) (object, error) {
	result := object{"name": c.Name, "levels": []any{}, "instances": []any{}, "supervisors": []any{}}
	root := orgRoot(c)
	if root != "" {
		var err error
		result, err = orgtree.ReadOverview(root)
		if err != nil {
			return nil, err
		}
		result["supervisors"] = []any{}
	}
	supervisors := obj(c.Data["supervisors"])
	names := make([]string, 0, len(supervisors))
	for name := range supervisors {
		names = append(names, name)
	}
	sort.Strings(names)
	models, runners := map[string]any{}, map[string]any{}
	for _, e := range events {
		if e["kind"] == "lane.started" || e["kind"] == "lane.adopted" {
			models[str(e["lane"])], runners[str(e["lane"])] = obj(e["payload"])["model"], obj(e["payload"])["runner"]
		}
	}
	for _, heartbeat := range heartbeatView(events) {
		name := str(heartbeat["supervisor"])
		if heartbeat["model"] != nil {
			models[name] = heartbeat["model"]
		}
		if heartbeat["runner"] != nil {
			runners[name] = heartbeat["runner"]
		}
	}
	levels := map[int]bool{}
	for _, name := range names {
		p := obj(supervisors[name])
		recordedLevel := eventstore.RecordedLevel(p["level"])
		level := int(number(recordedLevel))
		if level != 0 {
			levels[level] = true
		}
		result["supervisors"] = append(result["supervisors"].([]any), object{"name": name, "level": recordedLevel, "runner": p["runner"], "model": models[name]})
	}
	if root == "" {
		ordered := []int{}
		for level := range levels {
			ordered = append(ordered, level)
		}
		sort.Ints(ordered)
		for _, level := range ordered {
			result["levels"] = append(result["levels"].([]any), level)
		}
	}
	for _, value := range result["instances"].([]any) {
		instance := obj(value)
		name := str(instance["name"])
		binding := name
		if supervisors[binding] == nil {
			binding = strings.TrimPrefix(name, fmt.Sprintf("L%d-", int(number(instance["level"]))))
		}
		instance["runner"] = obj(supervisors[binding])["runner"]
		instance["model"] = models[name]
		if instance["runner"] == nil {
			instance["runner"] = runners[name]
		}
		if instance["model"] == nil {
			instance["model"] = models[binding]
		}
	}
	return result, nil
}

func orgRoot(c *config.Configuration) string {
	if root := str(obj(c.Data["dashboard"])["org"]); root != "" {
		return root
	}
	if c.Organisation != "" {
		candidate := filepath.Join(c.Home, "orgs", c.Organisation)
		if _, err := os.Stat(filepath.Join(candidate, ".laneboss", "org.toml")); err == nil {
			return candidate
		}
	}
	return ""
}

func healthView(c *config.Configuration, events []eventstore.Object) (object, error) {
	settings := obj(c.Data["disk"])
	path := str(settings["path"])
	if path == "" {
		var err error
		path, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	reading, err := disk.Read(path)
	if err != nil {
		return nil, err
	}
	warn, stop := 85.0, 90.0
	if value := settings["warn_percent"]; value != nil {
		warn = number(value)
	}
	if value := settings["stop_percent"]; value != nil {
		stop = number(value)
	}
	state := disk.OK
	if reading.UsedPercent >= stop {
		state = disk.STOP
	} else if reading.UsedPercent >= warn {
		state = disk.WARN
	}
	return object{"disk": object{"free_bytes": reading.FreeBytes, "used_percent": math.Round(reading.UsedPercent*10) / 10, "state": state, "warn_percent": warn, "stop_percent": stop}, "heartbeats": heartbeatView(events)}, nil
}
