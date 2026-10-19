// Package ledger builds employee ledgers from the launcher's existing records.
// Both the CLI and dashboard call Read; no ledger state is persisted.
package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/instancename"
	"laneboss.io/laneboss/internal/judge"
)

type object = map[string]any
type Selection struct{ Instance, Lane, Since string }

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (s Selection) Validate() (time.Time, error) {
	if s.Instance != "" && s.Lane != "" || s.Instance != "" && !instancename.Valid(s.Instance) || s.Lane != "" && !namePattern.MatchString(s.Lane) {
		return time.Time{}, errors.New("select one valid instance or lane")
	}
	if s.Since == "" {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339Nano, s.Since)
	if err != nil {
		at, err = time.Parse("2006-01-02", s.Since)
	}
	if err != nil {
		return time.Time{}, errors.New("since must be an RFC3339 time or UTC date")
	}
	return at, nil
}
func obj(v any) object  { x, _ := v.(object); return x }
func text(v any) string { x, _ := v.(string); return x }
func list(v any) []any  { x, _ := v.([]any); return x }
func numeric(v any) (float64, bool) {
	switch x := eventstore.ScreenValue(v).(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case json.Number:
		n, err := x.Float64()
		return n, err == nil
	}
	return 0, false
}
func at(e object) string {
	if value := text(e["occurred_at"]); value != "" {
		return value
	}
	return text(e["recorded_at"])
}
func after(stamp string, since time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	return err == nil && (since.IsZero() || !t.Before(since))
}
func add(row object, key string, value any) bool {
	n, ok := numeric(value)
	if !ok || n < 0 {
		return false
	}
	old, _ := numeric(row[key])
	row[key] = old + n
	return true
}
func outcome(e object) string {
	if e["kind"] == "lane.lost" {
		return "lost"
	}
	if e["kind"] == "lane.gone" {
		return "gone"
	}
	p := obj(e["payload"])
	switch p["reason"] {
	case "timeout":
		return "stopped_at_budget"
	case "stopped":
		return "stopped"
	case "hook-config":
		return "hook_config_failure"
	}
	exit, known := numeric(p["exit_code"])
	if p["reason"] == "exit" && known && exit == 0 {
		return "success"
	}
	return "failed"
}
func source(lane, kind string) string {
	q := url.Values{"limit": {"1000"}}
	if lane != "" {
		q.Set("lane", lane)
	}
	if kind != "" {
		q.Set("kind", kind)
	}
	return "/api/events?" + q.Encode()
}
func capText(s string) string {
	r := []rune(s)
	if len(r) > 200 {
		return string(r[:199]) + "…"
	}
	return s
}

// Read returns a deterministic, screened view of a verified record snapshot.
// No request time or live elapsed duration is introduced, so the two callers
// compute identical rows when the underlying recorded bytes are identical.
func Read(name string, selection Selection) (object, error) {
	return ReadContext(context.Background(), name, selection, nil)
}

func ReadContext(ctx context.Context, name string, selection Selection, cache *eventstore.UsageCache) (object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	since, err := selection.Validate()
	if err != nil {
		return nil, err
	}
	c, err := config.Load(name)
	if err != nil {
		return nil, err
	}
	binding, err := eventstore.Bind(c.Name)
	if err != nil {
		return nil, err
	}
	lanes, events, err := eventstore.ReadDisplayContext(ctx, binding)
	if err != nil {
		return nil, err
	}
	association, err := readContext(ctx, c, selection)
	if err != nil {
		return nil, err
	}
	selected := map[string]object{}
	if selection.Lane != "" {
		selected[selection.Lane] = object{"kind": "lane_identity"}
	}
	for _, lane := range lanes {
		if association.aliases[text(lane["lane"])] {
			selected[text(lane["lane"])] = object{"kind": "lane_identity"}
		}
	}
	for _, scope := range association.scopes {
		if scope["config"] == c.Name && association.aliases[text(scope["instance"])] {
			selected[text(scope["lane"])] = object{"kind": "stored_history_scope", "record": scope["id"]}
		}
	}
	for _, e := range events {
		if eventstore.ExternallyAppended(e) {
			continue
		}
		lane, p := text(e["lane"]), obj(e["payload"])
		if lane == "" {
			continue
		}
		if selection.Instance == "" && selection.Lane == "" {
			selected[lane] = object{"kind": "configuration"}
			continue
		}
		if selection.Instance != "" && association.references(e) {
			selected[lane] = object{"kind": "recorded_reference", "event": e["seq"]}
		}
		if selection.Instance != "" && e["kind"] == "lane.started" && association.projects[text(p["project"])] {
			if selected[lane] == nil {
				selected[lane] = object{"kind": "configured_project", "project": p["project"]}
			}
		}
	}
	type turn struct {
		start, end object
		brief      object
	}
	turns, rendered := map[string]*turn{}, map[string]object{}
	order := []string{}
	for _, e := range events {
		if eventstore.ExternallyAppended(e) {
			continue
		}
		lane, p := text(e["lane"]), obj(e["payload"])
		if e["kind"] == "brief.rendered" {
			rendered[text(obj(p["output"])["sha256"])] = e
		}
		if selected[lane] == nil {
			continue
		}
		key := lane + "/" + fmt.Sprint(p["run"])
		if e["kind"] == "lane.started" {
			turns[key] = &turn{start: e, brief: rendered[text(obj(p["brief"])["sha256"])]}
			order = append(order, key)
		}
		if e["kind"] == "lane.ended" || e["kind"] == "lane.lost" || e["kind"] == "lane.gone" {
			if turns[key] != nil {
				turns[key].end = e
			}
		}
	}
	rows, tasks := []object{}, []object{}
	summary := object{"tasks_done": nil, "tasks_failed": nil, "tasks_running": nil, "success_rate": nil, "median_duration_seconds": nil, "resumes": nil, "refusals": nil, "messages_sent": nil, "messages_received": nil, "input_tokens": nil, "output_tokens": nil, "cached_tokens": nil, "cost_usd": nil, "usage_partial": false}
	latest := map[string]object{}
	durations := []float64{}
	days := map[string]object{}
	for _, key := range order {
		t := turns[key]
		p := obj(t.start["payload"])
		lane := text(t.start["lane"])
		stamp := at(t.start)
		if t.end != nil {
			stamp = at(t.end)
		}
		if !after(stamp, since) {
			continue
		}
		title, originalHash, err := readTitle(binding, lane, t.brief)
		if err != nil {
			return nil, err
		}
		row := object{"kind": "task", "time": stamp, "lane": lane, "run": p["run"], "start": at(t.start), "end": nil, "outcome": "running", "exit_code": nil, "duration_seconds": nil, "brief_title": title, "brief_sha256": obj(p["brief"])["sha256"], "original_brief_sha256": originalHash, "runner": p["runner"], "model": p["model"], "account": p["account"], "input_tokens": nil, "output_tokens": nil, "cached_tokens": nil, "cost_usd": nil, "usage_partial": false, "events": []any{t.start["seq"]}, "association": selected[lane], "source": source(lane, "")}
		if t.end != nil {
			end := obj(t.end["payload"])
			row["end"], row["outcome"], row["exit_code"], row["duration_seconds"] = at(t.end), outcome(t.end), end["exit_code"], end["duration_seconds"]
			row["events"] = append(row["events"].([]any), t.end["seq"])
			if n, ok := numeric(end["duration_seconds"]); ok {
				durations = append(durations, n)
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scan, err := eventstore.ReadRunUsageContext(ctx, binding, lane, text(p["launch"]), cache)
		if err != nil {
			return nil, err
		}
		receipts, available := scan.Records, scan.Available
		row["usage_skipped_lines"], row["usage_bytes_read"], row["usage_capped"] = scan.SkippedLines, scan.BytesRead, scan.Capped
		if scan.Partial || !available || len(receipts) == 0 || t.end == nil {
			row["usage_partial"] = true
		}
		for _, receipt := range receipts {
			u := obj(receipt["usage"])
			for _, field := range []string{"input_tokens", "output_tokens"} {
				if !add(row, field, u[field]) {
					row["usage_partial"] = true
				}
			}
			cached := u["cached_input_tokens"]
			if cached == nil {
				cached = u["cache_read_input_tokens"]
			}
			cachedOK := add(row, "cached_tokens", cached)
			costOK := add(row, "cost_usd", receipt["total_cost_usd"])
			if !cachedOK || !costOK {
				row["usage_partial"] = true
			}
		}
		for _, field := range []string{"input_tokens", "output_tokens", "cached_tokens", "cost_usd"} {
			add(summary, field, row[field])
		}
		if row["usage_partial"] == true {
			summary["usage_partial"] = true
		}
		latest[lane] = row
		tasks = append(tasks, row)
		rows = append(rows, row)
		day := text(row["start"])
		if parsed, e := time.Parse(time.RFC3339Nano, day); e == nil {
			day = parsed.UTC().Format("2006-01-02")
		}
		if days[day] == nil {
			q := url.Values{}
			if selection.Instance != "" {
				q.Set("instance", selection.Instance)
			}
			if selection.Lane != "" {
				q.Set("lane", selection.Lane)
			}
			q.Set("since", day)
			days[day] = object{"day": day, "tasks": 0, "success": 0, "ended": 0, "success_rate": nil, "source": "/api/ledger?" + q.Encode()}
		}
		d := days[day]
		d["tasks"] = d["tasks"].(int) + 1
		if t.end != nil {
			d["ended"] = d["ended"].(int) + 1
			if row["outcome"] == "success" {
				d["success"] = d["success"].(int) + 1
			}
		}
	}
	counts := map[string]int{"resumes": 0, "refusals": 0, "messages_sent": 0, "messages_received": 0}
	for _, e := range events {
		lane, p, kind := text(e["lane"]), obj(e["payload"]), text(e["kind"])
		linked := selected[lane] != nil || association.references(e)
		if kind == "rule.proposal" {
			for _, name := range list(p["lanes"]) {
				linked = linked || selected[text(name)] != nil
			}
		}
		if kind == "tool.submitted" {
			linked = linked || selected[text(p["lane"])] != nil
		}
		if !after(at(e), since) || !linked && !(selection.Lane == "" && selection.Instance == "") {
			continue
		}
		row := object{"time": at(e), "lane": e["lane"], "event": e["seq"], "source": source(lane, kind)}
		if eventstore.ExternallyAppended(e) {
			row["kind"], row["action"], row["reason"], row["actor"], row["externally_appended"] = "external_lifecycle", kind, "Externally appended lifecycle event", e["actor"], true
			rows = append(rows, row)
			continue
		}
		switch {
		case kind == "rule.proposal":
			row["kind"], row["proposal_id"], row["rule_id"], row["note"], row["count"], row["source"] = "proposal", e["id"], p["rule_id"], p["note"], p["count"], "/api/proposals"
			rows = append(rows, row)
		case kind == "tool.submitted":
			row["kind"], row["path"], row["sha256"], row["purpose"], row["preview"], row["source"] = "tool", p["path"], p["sha256"], p["purpose"], p["preview"], "/api/tools"
			rows = append(rows, row)
		case kind == "lane.resumed":
			if faults.Get("ledger-drop-resumes").Point != "" {
				continue
			}
			counts["resumes"]++
			row["kind"], row["run"], row["reason"], row["message_sha256"] = "resume", p["run"], p["after"], obj(p["message"])["sha256"]
			rows = append(rows, row)
		case kind == "lane.refusal":
			counts["refusals"]++
			row["kind"], row["rule_id"] = "refusal", p["guard"]
			rows = append(rows, row)
		case strings.Contains(kind, "message") || kind == "lane.mailed" || kind == "lane.inbox" || kind == "lane.outbox":
			from, to := text(p["from"]), text(p["to"])
			if from == "" {
				from = text(p["sender"])
			}
			if from == "" {
				from = text(e["actor"])
			}
			if to == "" {
				to = text(p["instance"])
			}
			if to == "" {
				to = lane
			}
			sent, received := association.aliases[from], association.aliases[to] || selected[lane] != nil && !association.aliases[from]
			if selection.Instance == "" && selection.Lane == "" {
				sent, received = strings.HasSuffix(kind, ".sent"), strings.HasSuffix(kind, ".received") || kind == "lane.mailed"
			}
			if sent {
				counts["messages_sent"]++
			}
			if received {
				counts["messages_received"]++
			}
			row["kind"], row["from"], row["to"], row["sent"], row["received"], row["source"] = "message", from, to, sent, received, "/api/messages"
			rows = append(rows, row)
		case strings.HasPrefix(kind, "decision.") || strings.HasPrefix(kind, "decisions.") || strings.HasPrefix(kind, "history."):
			ids := p["ids"]
			if ids == nil && p["decision_id"] != nil {
				ids = []any{p["decision_id"]}
			}
			if ids != nil {
				row["kind"], row["action"], row["decision_ids"] = "decision", kind, ids
				rows = append(rows, row)
			}
		}
	}
	for _, feedback := range association.feedback {
		if feedback["event"] != "cited" || !after(text(feedback["at"]), since) {
			continue
		}
		owner := strings.TrimPrefix(text(feedback["source"]), "lane:")
		instance := strings.TrimPrefix(text(feedback["source"]), "instance:")
		if selected[owner] == nil && !association.aliases[instance] && !(selection.Instance == "" && selection.Lane == "") {
			continue
		}
		rows = append(rows, object{"kind": "decision", "time": feedback["at"], "action": "cited", "decision_ids": []any{feedback["case_id"]}, "source_record": feedback["source"], "source": "/api/decisions?q=" + url.QueryEscape(text(feedback["case_id"]))})
	}
	if len(obj(c.Data["judges"])) > 0 {
		judgments, err := judge.ReadDecisionsContext(ctx, c.Name)
		if err != nil {
			return nil, err
		}
		for _, decision := range judgments {
			if !after(text(decision["time"]), since) || selected[text(decision["lane"])] == nil && !(selection.Instance == "" && selection.Lane == "") {
				continue
			}
			rows = append(rows, object{"kind": "judgment", "time": decision["time"], "lane": decision["lane"], "ask": decision["ask"], "answer": decision["answer"], "latency_ms": decision["latency_ms"], "source": "/api/judge"})
		}
	}
	for _, lookup := range association.lookups {
		if (selection.Instance == "" && selection.Lane == "" || association.aliases[text(lookup["instance"])]) && after(text(lookup["time"]), since) {
			rows = append(rows, object{"kind": "decision", "time": lookup["time"], "action": "looked_up", "decision_ids": lookup["decision_ids"], "source": "/api/decisions"})
		}
	}
	for _, message := range association.messages {
		if !after(text(message["time"]), since) || !association.aliases[text(message["to"])] && !association.aliases[text(message["from"])] && !(selection.Lane == "" && selection.Instance == "") {
			continue
		}
		sent, received := association.aliases[text(message["from"])], association.aliases[text(message["to"])]
		if selection.Lane == "" && selection.Instance == "" {
			received = true
		}
		if sent {
			counts["messages_sent"]++
		}
		if received {
			counts["messages_received"]++
		}
		rows = append(rows, object{"kind": "message", "time": message["time"], "message_id": message["id"], "from": message["from"], "to": message["to"], "sent": sent, "received": received, "source": "/api/messages"})
	}
	if len(rows) > 0 {
		for key, value := range counts {
			summary[key] = value
		}
	}
	if len(latest) > 0 {
		done, failed, running := 0, 0, 0
		for _, task := range latest {
			switch task["outcome"] {
			case "success":
				done++
			case "running":
				running++
			default:
				failed++
			}
		}
		summary["tasks_done"], summary["tasks_failed"], summary["tasks_running"] = done, failed, running
		if done+failed > 0 {
			summary["success_rate"] = float64(done) / float64(done+failed)
		}
	}
	if len(durations) > 0 {
		sort.Float64s(durations)
		middle := len(durations) / 2
		median := durations[middle]
		if len(durations)%2 == 0 {
			median = (durations[middle-1] + median) / 2
		}
		summary["median_duration_seconds"] = median
	}
	trend := []object{}
	dayKeys := []string{}
	for day := range days {
		dayKeys = append(dayKeys, day)
	}
	sort.Strings(dayKeys)
	for _, day := range dayKeys {
		d := days[day]
		if d["ended"].(int) > 0 {
			d["success_rate"] = float64(d["success"].(int)) / float64(d["ended"].(int))
		}
		trend = append(trend, d)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, text(rows[i]["time"]))
		b, _ := time.Parse(time.RFC3339Nano, text(rows[j]["time"]))
		return a.Before(b)
	})
	result := object{"config": c.Name, "employee": object{"kind": association.kind, "id": association.id}, "since": selection.Since, "available": len(rows) > 0, "summary": summary, "tasks": tasks, "rows": rows, "trend": trend}
	return eventstore.ScreenValue(result).(map[string]any), nil
}
