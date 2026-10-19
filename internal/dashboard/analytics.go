package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
)

type runMetric struct {
	start, end object
	first      object
}
type durationMetric struct {
	lane, turn, first []float64
	refs              []any
	runner, model     string
}

func metricTime(e object) time.Time { at, _ := time.Parse(time.RFC3339Nano, str(when(e))); return at }
func hour(at time.Time) string      { return at.UTC().Truncate(time.Hour).Format(time.RFC3339) }
func inWindow(at, since, until time.Time) bool {
	return !at.IsZero() && !at.Before(since) && !at.After(until)
}
func bump(row object, key string) { row[key] = int(number(row[key])) + 1 }
func addNumber(row object, key string, value any) bool {
	if value == nil {
		return false
	}
	plain := eventstore.ScreenValue(value)
	switch plain.(type) {
	case int, int64, float64, json.Number:
	default:
		return false
	}
	n := number(plain)
	if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
		return false
	}
	row[key] = number(row[key]) + n
	return true
}
func metricRows(rows map[string]object) []object {
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := []object{}
	for _, key := range keys {
		result = append(result, rows[key])
	}
	return result
}
func percentiles(values []float64) any {
	if len(values) == 0 {
		return nil
	}
	sort.Float64s(values)
	return object{"count": len(values), "p50": values[int(math.Ceil(float64(len(values))*.5))-1], "p90": values[int(math.Ceil(float64(len(values))*.9))-1], "max": values[len(values)-1]}
}
func eventSource(since, until time.Time, lane, kind string) string {
	query := url.Values{"since": {since.UTC().Format(time.RFC3339Nano)}, "until": {until.UTC().Format(time.RFC3339Nano)}, "limit": {"1000"}}
	if lane != "" {
		query.Set("lane", lane)
	}
	if kind != "" {
		query.Set("kind", kind)
	}
	return "/api/events?" + query.Encode()
}
func bucketSource(since, until, at time.Time, lane, kind string) string {
	start := at.UTC().Truncate(time.Hour)
	end := start.Add(time.Hour - time.Nanosecond)
	if since.After(start) {
		start = since
	}
	if until.Before(end) {
		end = until
	}
	return eventSource(start, end, lane, kind)
}
func groupSource(source, runner, model string) string {
	if runner != "" {
		source += "&runner=" + url.QueryEscape(runner)
	}
	if model != "" {
		source += "&model=" + url.QueryEscape(model)
	}
	return source
}
func outcome(e object) string {
	p := obj(e["payload"])
	switch p["reason"] {
	case "timeout":
		return "stopped_at_budget"
	case "hook-config":
		return "hook_config_failure"
	case "stopped":
		return "stopped"
	}
	if p["reason"] == "exit" && p["exit_code"] != nil && number(p["exit_code"]) == 0 {
		return "success"
	}
	return "failed"
}

// analytics scans the whole selected event window and each associated run's
// complete recorded usage interval. Missing measurements remain null.
func analytics(ctx context.Context, binding *eventstore.Configuration, lanes, events []object, window string, idle int, now time.Time, cache *eventstore.UsageCache) (object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	span := time.Hour
	if window == "24h" {
		span = 24 * time.Hour
	}
	if window == "7d" {
		span = 7 * 24 * time.Hour
	}
	since := now.Add(-span)
	runs := map[string]*runMetric{}
	current := map[string]*runMetric{}
	latest := map[string]object{}
	volume, groups, rules, refusalHours, resumes, seats := map[string]object{}, map[string]object{}, map[string]object{}, map[string]object{}, map[string]object{}, map[string]object{}
	durations := map[string]*durationMetric{}
	failures := map[string][]object{}
	count := 0
	for _, e := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if eventstore.ExternallyAppended(e) {
			continue
		}
		if faults.Get("dashboard-analytics-drop-ended").Point != "" && e["kind"] == "lane.ended" {
			continue
		}
		lane := str(e["lane"])
		p := obj(e["payload"])
		at := metricTime(e)
		if lane != "" {
			latest[lane] = e
		}
		if e["kind"] == "lane.started" {
			run := &runMetric{start: e}
			runs[fmt.Sprint(e["seq"])] = run
			current[lane] = run
		}
		run := current[lane]
		if e["kind"] == "lane.ended" && run != nil {
			run.end = e
		}
		report := false
		if e["kind"] == "lane.ingested" {
			for _, entry := range listContent(p["rows"]) {
				if strings.Contains(str(obj(entry)["id"]), "/report/") {
					report = true
				}
			}
		}
		if run != nil && run.first == nil && (strings.HasSuffix(str(e["kind"]), ".commit") || strings.HasSuffix(str(e["kind"]), ".reported") || e["kind"] == "report.created" || report) {
			if !at.Before(metricTime(run.start)) {
				run.first = e
			}
		}
		if !inWindow(at, since, now) {
			continue
		}
		count++
		key := hour(at) + "\n" + str(e["kind"])
		if volume[key] == nil {
			volume[key] = object{"hour": hour(at), "kind": e["kind"], "count": nil, "events": []any{}, "source": bucketSource(since, now, at, "", str(e["kind"]))}
		}
		bump(volume[key], "count")
		volume[key]["events"] = append(volume[key]["events"].([]any), e["seq"])
		if e["kind"] == "lane.started" || e["kind"] == "lane.ended" || e["kind"] == "lane.refusal" {
			meta := p
			if run != nil {
				meta = obj(run.start["payload"])
			}
			key = hour(at) + "\n" + str(meta["runner"]) + "\n" + str(meta["model"])
			if groups[key] == nil {
				groups[key] = object{"hour": hour(at), "runner": meta["runner"], "model": meta["model"], "started": nil, "ended": nil, "outcomes": object{}, "events": []any{}, "source": groupSource(bucketSource(since, now, at, "", ""), str(meta["runner"]), str(meta["model"]))}
			}
			row := groups[key]
			row["events"] = append(row["events"].([]any), e["seq"])
			if e["kind"] == "lane.started" {
				bump(row, "started")
			} else if e["kind"] == "lane.refusal" {
				bump(obj(row["outcomes"]), "refused")
			} else {
				bump(row, "ended")
				bump(obj(row["outcomes"]), outcome(e))
				failures[lane] = append(failures[lane], e)
			}
		}
		if e["kind"] == "lane.refusal" {
			key = str(p["guard"])
			if rules[key] == nil {
				rules[key] = object{"rule_id": p["guard"], "count": nil, "events": []any{}, "source": eventSource(since, now, "", "lane.refusal") + "&rule=" + url.QueryEscape(key)}
			}
			bump(rules[key], "count")
			rules[key]["events"] = append(rules[key]["events"].([]any), e["seq"])
			key = hour(at) + "\n" + lane + "\n" + str(p["guard"])
			if refusalHours[key] == nil {
				refusalHours[key] = object{"hour": hour(at), "lane": lane, "rule_id": p["guard"], "count": nil, "events": []any{}, "source": bucketSource(since, now, at, lane, "lane.refusal") + "&rule=" + url.QueryEscape(str(p["guard"]))}
			}
			bump(refusalHours[key], "count")
			refusalHours[key]["events"] = append(refusalHours[key]["events"].([]any), e["seq"])
		}
		if e["kind"] == "lane.resumed" {
			if resumes[lane] == nil {
				resumes[lane] = object{"lane": lane, "count": nil, "events": []any{}, "source": eventSource(since, now, lane, "lane.resumed")}
			}
			bump(resumes[lane], "count")
			resumes[lane]["events"] = append(resumes[lane]["events"].([]any), e["seq"])
		}
	}
	usageRows := []object{}
	totals := object{"input_tokens": nil, "output_tokens": nil, "cached_tokens": nil, "cost_usd": nil}
	partial := false
	for _, run := range runs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := obj(run.start["payload"])
		lane := str(run.start["lane"])
		at := metricTime(run.start)
		if run.end != nil {
			at = metricTime(run.end)
		}
		runInWindow := inWindow(at, since, now)
		if metricTime(run.start).After(now) || run.end != nil && metricTime(run.end).Before(since) {
			continue
		}
		key := str(p["runner"]) + "\n" + str(p["model"])
		if durations[key] == nil {
			durations[key] = &durationMetric{runner: str(p["runner"]), model: str(p["model"])}
		}
		d := durations[key]
		d.refs = append(d.refs, run.start["seq"])
		if runInWindow && run.end != nil && obj(run.end["payload"])["duration_seconds"] != nil {
			seconds := number(eventstore.ScreenValue(obj(run.end["payload"])["duration_seconds"]))
			d.lane = append(d.lane, seconds)
			d.refs = append(d.refs, run.end["seq"])
		}
		if runInWindow && run.first != nil {
			d.first = append(d.first, metricTime(run.first).Sub(metricTime(run.start)).Seconds())
			d.refs = append(d.refs, run.first["seq"])
		}
		scan, err := eventstore.ReadRunUsageContext(ctx, binding, lane, str(p["launch"]), cache)
		if err != nil {
			return nil, err
		}
		receipts, available := scan.Records, scan.Available
		row := object{"lane": lane, "runner": p["runner"], "model": p["model"], "account": p["account"], "run": p["run"], "input_tokens": nil, "output_tokens": nil, "cached_tokens": nil, "cost_usd": nil, "records": []any{}, "partial": false, "source": "/api/logs?" + url.Values{"lane": {lane}, "tail": {"2000"}}.Encode(), "event": run.start["seq"]}
		row["usage_skipped_lines"], row["usage_bytes_read"], row["usage_capped"] = scan.SkippedLines, scan.BytesRead, scan.Capped
		if scan.Partial || !available || len(receipts) == 0 || run.end == nil {
			row["partial"] = true
		}
		turnDurations := 0
		includedReceipts := 0
		for _, receipt := range receipts {
			receiptAt := at
			if stamp := str(receipt["timestamp"]); stamp != "" {
				t, e := time.Parse(time.RFC3339Nano, stamp)
				if e != nil || !inWindow(t, since, now) {
					continue
				}
				receiptAt = t
			} else if !runInWindow {
				continue
			}
			includedReceipts++
			u := obj(receipt["usage"])
			inputOK := addNumber(row, "input_tokens", u["input_tokens"])
			outputOK := addNumber(row, "output_tokens", u["output_tokens"])
			if !inputOK || !outputOK {
				row["partial"] = true
				partial = true
			}
			cached := u["cached_input_tokens"]
			if cached == nil {
				cached = u["cache_read_input_tokens"]
			}
			if !addNumber(row, "cached_tokens", cached) {
				row["partial"] = true
				partial = true
			}
			if !addNumber(row, "cost_usd", receipt["total_cost_usd"]) {
				row["partial"] = true
				partial = true
			}
			if receipt["duration_ms"] != nil {
				d.turn = append(d.turn, number(eventstore.ScreenValue(receipt["duration_ms"]))/1000)
				turnDurations++
			}
			row["records"] = append(row["records"].([]any), object{"line": receipt["line"], "type": receipt["type"], "event": run.start["seq"], "time": receiptAt.UTC().Format(time.RFC3339Nano), "vendor_timestamp": receipt["timestamp"] != nil})
			if p["account"] != nil {
				key = hour(receiptAt) + "\n" + str(p["account"])
				if seats[key] == nil {
					seats[key] = object{"hour": hour(receiptAt), "account": p["account"], "turns": nil, "events": []any{}, "source": eventSource(since, now, "", "") + "&account=" + url.QueryEscape(str(p["account"]))}
				}
				bump(seats[key], "turns")
				seats[key]["events"] = append(seats[key]["events"].([]any), run.start["seq"])
			}
		}
		if !runInWindow && includedReceipts == 0 {
			continue
		}
		if flag(row["partial"]) {
			partial = true
		}
		if _, turn := p["mail"]; turn && runInWindow && turnDurations == 0 && run.end != nil && obj(run.end["payload"])["duration_seconds"] != nil {
			d.turn = append(d.turn, number(eventstore.ScreenValue(obj(run.end["payload"])["duration_seconds"])))
		}
		for _, field := range []string{"input_tokens", "output_tokens", "cached_tokens", "cost_usd"} {
			addNumber(totals, field, row[field])
		}
		usageRows = append(usageRows, row)
	}
	models, accounts := map[string]object{}, map[string]object{}
	for _, row := range usageRows {
		for group, key := range map[string]string{"model": str(row["model"]), "account": str(row["account"])} {
			target := models
			if group == "account" {
				target = accounts
			}
			if key == "" {
				continue
			}
			if target[key] == nil {
				target[key] = object{group: key, "input_tokens": nil, "output_tokens": nil, "cached_tokens": nil, "cost_usd": nil, "partial": false, "events": []any{}, "source": eventSource(since, now, "", "") + "&" + group + "=" + url.QueryEscape(key)}
			}
			if flag(row["partial"]) {
				target[key]["partial"] = true
			}
			for _, field := range []string{"input_tokens", "output_tokens", "cached_tokens", "cost_usd"} {
				addNumber(target[key], field, row[field])
			}
			target[key]["events"] = append(target[key]["events"].([]any), row["event"])
		}
	}
	sort.Slice(usageRows, func(i, j int) bool {
		return str(usageRows[i]["lane"])+fmt.Sprint(usageRows[i]["run"]) < str(usageRows[j]["lane"])+fmt.Sprint(usageRows[j]["run"])
	})
	top := append([]object{}, usageRows...)
	sort.SliceStable(top, func(i, j int) bool {
		return number(top[i]["input_tokens"])+number(top[i]["output_tokens"]) > number(top[j]["input_tokens"])+number(top[j]["output_tokens"])
	})
	if len(top) > 10 {
		top = top[:10]
	}
	times := []object{}
	keys := []string{}
	for key := range durations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		d := durations[key]
		times = append(times, object{"runner": d.runner, "model": d.model, "lane_duration_seconds": percentiles(d.lane), "turn_duration_seconds": percentiles(d.turn), "first_commit_or_report_seconds": percentiles(d.first), "events": d.refs, "source": groupSource(eventSource(since, now, "", ""), d.runner, d.model)})
	}
	stuck, repeated := []object{}, []object{}
	for _, lane := range lanes {
		name := str(lane["lane"])
		e := latest[name]
		if flag(lane["running"]) && e != nil && now.Sub(metricTime(e)) > time.Duration(idle)*time.Minute {
			stuck = append(stuck, object{"lane": name, "idle_seconds": now.Sub(metricTime(e)).Seconds(), "last_event": e["seq"], "source": eventSource(since, now, name, "")})
		}
	}
	for lane, list := range failures {
		if len(list) < 2 {
			continue
		}
		last := list[len(list)-1]
		if outcome(last) == "success" {
			continue
		}
		key := fmt.Sprint(obj(last["payload"])["reason"], "/", obj(last["payload"])["exit_code"])
		n := 0
		refs := []any{}
		for i := len(list) - 1; i >= 0; i-- {
			if fmt.Sprint(obj(list[i]["payload"])["reason"], "/", obj(list[i]["payload"])["exit_code"]) != key {
				break
			}
			n++
			refs = append(refs, list[i]["seq"])
		}
		if n >= 2 {
			repeated = append(repeated, object{"lane": lane, "failure": key, "count": n, "events": refs, "source": eventSource(since, now, lane, "lane.ended")})
		}
	}
	sort.Slice(stuck, func(i, j int) bool { return str(stuck[i]["lane"]) < str(stuck[j]["lane"]) })
	sort.Slice(repeated, func(i, j int) bool { return str(repeated[i]["lane"]) < str(repeated[j]["lane"]) })
	topRules := metricRows(rules)
	sort.SliceStable(topRules, func(i, j int) bool { return number(topRules[i]["count"]) > number(topRules[j]["count"]) })
	var eventCount any
	if count > 0 {
		eventCount = count
	}
	return object{"window": window, "since": since.UTC().Format(time.RFC3339Nano), "until": now.UTC().Format(time.RFC3339Nano), "event_count": eventCount, "lanes": metricRows(groups), "time": times, "usage": object{"totals": totals, "rows": usageRows, "by_model": metricRows(models), "by_account": metricRows(accounts), "top10": top, "partial": partial, "source": eventSource(since, now, "", "")}, "refusals": metricRows(refusalHours), "top_rules": topRules, "stuck": stuck, "repeated_failures": repeated, "resumes": metricRows(resumes), "seats": metricRows(seats), "event_volume": metricRows(volume), "idle_minutes": idle}, nil
}
