// Package refusal provides descriptive effect grouping and append-only human
// review proposals. It contains no permission checks or policy-write path.
package refusal

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/protocol"
)

type object = map[string]any

func obj(v any) object  { x, _ := v.(object); return x }
func text(v any) string { x, _ := v.(string); return x }
func at(e object) string {
	if s := text(e["occurred_at"]); s != "" {
		return s
	}
	return text(e["recorded_at"])
}
func capText(v any) string {
	s := text(eventstore.ScreenValue(v))
	r := []rune(s)
	if len(r) > 200 {
		return string(r[:199]) + "…"
	}
	return s
}

// Effect classifies only a recorded refusal's stated effect. Ambiguous calls
// stay opaque. This function is never consulted to allow a tool or command.
func Effect(p object) string {
	message := strings.ToLower(text(obj(p["message"])["text"]))
	if strings.Contains(message, "guard") && (strings.Contains(message, "self-change") || strings.Contains(message, "self change") || strings.Contains(message, "change guard") || strings.Contains(message, "edit guard")) {
		return "guard_self_change"
	}
	if strings.Contains(message, "secret") && strings.Contains(message, "read") || strings.Contains(message, "credential") && strings.Contains(message, "read") {
		return "secret_read"
	}
	if strings.Contains(message, "protected path") || strings.Contains(message, "protected file") {
		return "protected_path"
	}
	if strings.Contains(message, "outside scope") && strings.Contains(message, "write") || strings.Contains(message, "outside the scope") && strings.Contains(message, "write") {
		return "write_outside_scope"
	}
	if strings.Contains(message, "outbound") || strings.Contains(message, "push") || strings.Contains(message, "network") {
		return "outbound_network"
	}
	return "unknown_opaque"
}
func Rows(events []object) []object {
	metadata := eventstore.RecordedLaneInfo(events)
	rows := []object{}
	for _, e := range events {
		if e["kind"] != "lane.refusal" {
			continue
		}
		p := obj(e["payload"])
		example := capText(obj(p["message"])["text"])
		if obj(p["message"])["withheld"] == true {
			example = "[withheld]"
		}
		level := eventstore.RecordedLevel(p["level"])
		if info := metadata[text(e["lane"])]; info != nil && level == nil {
			level = info["level"]
		}
		rows = append(rows, object{"id": p["refusal"], "event": e["seq"], "time": at(e), "lane": e["lane"], "employee": e["lane"], "level": level, "rule_id": p["guard"], "effect": Effect(p), "example": example, "source": "/api/events?" + url.Values{"lane": {text(e["lane"])}, "kind": {"lane.refusal"}, "rule": {text(p["guard"])}, "limit": {"1000"}}.Encode()})
	}
	return rows
}
func View(events []object, levels map[string]int) object {
	rows := Rows(events)
	groups := map[string]object{}
	hours := map[string]object{}
	for _, row := range rows {
		key := fmt.Sprint(row["effect"], "/", row["rule_id"], "/", row["level"], "/", row["employee"])
		if groups[key] == nil {
			groups[key] = object{"effect": row["effect"], "rule_id": row["rule_id"], "level": row["level"], "employee": row["employee"], "count": 0, "first_seen": row["time"], "last_seen": row["time"], "examples": []object{}, "refusals": []any{}, "source": row["source"]}
		}
		g := groups[key]
		g["count"] = g["count"].(int) + 1
		stamp, _ := time.Parse(time.RFC3339Nano, text(row["time"]))
		first, _ := time.Parse(time.RFC3339Nano, text(g["first_seen"]))
		last, _ := time.Parse(time.RFC3339Nano, text(g["last_seen"]))
		if stamp.Before(first) {
			g["first_seen"] = row["time"]
		}
		if stamp.After(last) {
			g["last_seen"] = row["time"]
		}
		if len(g["examples"].([]object)) < 3 {
			g["examples"] = append(g["examples"].([]object), row)
		}
		g["refusals"] = append(g["refusals"].([]any), row["id"])
		hour := stamp.UTC().Truncate(time.Hour).Format(time.RFC3339)
		hourKey := key + "/" + hour
		if hours[hourKey] == nil {
			hours[hourKey] = object{"hour": hour, "effect": row["effect"], "rule_id": row["rule_id"], "employee": row["employee"], "level": row["level"], "count": 0, "source": row["source"]}
		}
		hours[hourKey]["count"] = hours[hourKey]["count"].(int) + 1
	}
	ordered := func(m map[string]object) []object {
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		result := []object{}
		for _, k := range keys {
			result = append(result, m[k])
		}
		return result
	}
	return object{"rows": rows, "groups": ordered(groups), "hours": ordered(hours), "count": len(rows), "effect_basis": "recorded refusal text; opaque if unresolved"}
}
func Proposals(events []object) []object {
	rows := []object{}
	for _, e := range events {
		if e["kind"] == "rule.proposal" {
			p := obj(eventstore.ScreenValue(e["payload"]))
			p["id"], p["event"], p["time"], p["source"] = e["id"], e["seq"], at(e), "/api/events?kind=rule.proposal&limit=1000"
			rows = append(rows, p)
		}
	}
	return rows
}

type Request struct{ Refusal, Rule, Effect, Note string }

func Report(name string, request Request, actor string) (object, error) {
	if (request.Refusal == "") == (request.Rule == "") || strings.TrimSpace(request.Note) == "" || utf8.RuneCountInString(request.Note) > 4000 {
		return nil, errors.New("select a refusal or rule and supply a note of at most 4000 characters")
	}
	if eventstore.ScreenValue(request.Note) != request.Note || eventstore.ScreenValue(request.Rule) != request.Rule || eventstore.ScreenValue(request.Refusal) != request.Refusal {
		return nil, errors.New("the report contains a credential-shaped value")
	}
	binding, err := eventstore.Bind(name)
	if err != nil {
		return nil, err
	}
	_, events, err := eventstore.ReadDisplay(binding)
	if err != nil {
		return nil, err
	}
	matched := []object{}
	for _, row := range Rows(events) {
		if request.Refusal != "" && row["id"] != request.Refusal || request.Rule != "" && row["rule_id"] != request.Rule || request.Effect != "" && row["effect"] != request.Effect {
			continue
		}
		matched = append(matched, row)
	}
	if len(matched) == 0 {
		return nil, errors.New("no recorded refusal matches the report")
	}
	rule := matched[0]["rule_id"]
	ids, lanes := []any{}, []any{}
	seen := map[string]bool{}
	examples := []object{}
	for _, row := range matched {
		ids = append(ids, row["id"])
		lane := text(row["lane"])
		if !seen[lane] {
			seen[lane] = true
			lanes = append(lanes, lane)
		}
		if len(examples) < 10 {
			examples = append(examples, row)
		}
	}
	_, version, err := protocol.Load()
	if err != nil {
		return nil, err
	}
	d, err := binding.OpenDirectory(true)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	store, err := eventstore.Open(d, true)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	proposal, err := store.Append(object{"kind": "rule.proposal", "actor": actor, "protocol_version": version, "payload": object{"rule_id": rule, "refusals": ids, "lanes": lanes, "examples": examples, "note": request.Note, "count": len(matched), "policy_changed": false}})
	if err != nil {
		return nil, err
	}
	if err = proposalPolicyFault(binding.Directory); err != nil {
		return nil, err
	}
	return proposal, nil
}
