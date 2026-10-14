package lane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

var timeKinds = strings.Fields("planned started ended timeout stuck resumed lost cleaned")
var landingKinds = strings.Fields("merged deployed landed")
var baseFields = strings.Fields("lane state state_at times landing run running runner model effort account worktree branch reason exit_code resumes lost cleaned events last_seq")

func emptyProjection(lane string) object {
	r := object{}
	for _, k := range baseFields {
		r[k] = nil
	}
	times, landing := object{}, object{}
	for _, k := range timeKinds {
		times[k] = nil
	}
	for _, k := range landingKinds {
		landing[k] = nil
	}
	r["lane"] = lane
	r["times"] = times
	r["landing"] = landing
	r["run"] = 0
	r["running"] = false
	r["resumes"] = 0
	r["lost"] = 0
	r["cleaned"] = false
	r["events"] = 0
	return r
}
func exactKeys(m object, fields []string) bool {
	if m == nil || len(m) != len(fields) {
		return false
	}
	for _, k := range fields {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func currentProjection(m object) bool {
	if m == nil || !exactKeys(obj(m["times"]), timeKinds) {
		return false
	}
	for _, k := range baseFields {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	for k := range m {
		if !contains(baseFields, k) && k != "mail" && k != "refusals" {
			return false
		}
	}
	if v, ok := m["refusals"]; ok && !exactKeys(obj(v), strings.Fields("recorded suspected verdicts unreviewed")) {
		return false
	}
	if v, ok := m["mail"]; ok && !exactKeys(obj(v), strings.Fields("turn_based idle_seconds last waiting returned in_flight delivered settled")) {
		return false
	}
	return true
}
func numeric(v any) bool {
	switch v.(type) {
	case int, int64, float64, json.Number:
		return true
	}
	return false
}
func whole(v any, min, max float64) bool {
	var n int64
	switch value := v.(type) {
	case int:
		n = int64(value)
	case int64:
		n = value
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return false
		}
		var err error
		n, err = value.Int64()
		if err != nil {
			return false
		}
	default:
		return false
	}
	return n >= int64(min) && n <= int64(max)
}
func absValue(v any) bool {
	return filepath.IsAbs(str(v)) && len(str(v)) <= 4096 && strings.IndexFunc(str(v), func(r rune) bool { return r < 32 || r == 127 }) < 0
}
func fileValue(v any) bool {
	m := obj(v)
	return exactKeys(m, []string{"path", "sha256"}) && absValue(m["path"]) && match(`[0-9a-f]{64}`, str(m["sha256"]))
}
func validatePayload(kind, lane string, p object) error {
	p = obj(nativeJSON(p))
	forms := map[string]string{
		"lane.planned": "", "lane.state": "state", "lane.merged": "", "lane.deployed": "", "lane.landed": "",
		"lane.started": "run how launch runner model effort account chosen_by difficulty project worktree branch base repository budget_minutes quiet_seconds brief log session touches claims",
		"lane.adopted": "runner model effort account chosen_by difficulty project worktree branch base repository budget_minutes quiet_seconds brief log session touches claims session_id idle_seconds",
		"lane.resumed": "run after message", "lane.ended": "run reason exit_code signal duration_seconds pattern classification survivors", "lane.timeout": "run budget_minutes elapsed_seconds", "lane.stuck": "run quiet_seconds output_bytes", "lane.lost": "run survivors", "lane.gone": "run launch", "lane.cleaned": "removed kept", "lane.delivered": "run sequences", "lane.returned": "run sequences reason",
		"lane.refusal":              "run refusal guard kind format via hook tool at command message targets call record workarounds_checked",
		"lane.workaround_suspected": "run suspicion refusal how paths tool at command call similarity", "lane.refusal_reviewed": "refusal path verdict suspicions note", "lane.mailed": "sequence sender sha256 bytes", "lane.ingested": "lane rows_added rows_existing rows",
	}
	fields, ok := forms[kind]
	if !ok || lane == "" {
		return refuse("kind or lane is not a documented lane event")
	}
	keys := strings.Fields(fields)
	for _, pair := range [][2]string{{"lane.started", "session_id"}, {"lane.ended", "prompt"}, {"lane.state", "not_covered"}, {"lane.state", "held"}} {
		if kind == pair[0] {
			if _, ok = p[pair[1]]; ok {
				keys = append(keys, pair[1])
			}
		}
	}
	if kind == "lane.started" {
		if _, ok = p["mail"]; ok {
			keys = append(keys, "mail", "idle_seconds")
		}
	}
	if !exactKeys(p, keys) {
		return refuse("%s payload must hold exactly its documented fields", kind)
	}
	fail := func(k string) error { return refuse("%s payload.%s: invalid field", kind, k) }
	for k, v := range p {
		switch k {
		case "run":
			if !whole(v, 1, 1000000) {
				return fail(k)
			}
		case "launch":
			if !match(`[0-9a-f]{32}`, str(v)) {
				return fail(k)
			}
		case "runner", "project":
			if v != nil && !match(`[a-z0-9][a-z0-9-]{0,31}`, str(v)) {
				return fail(k)
			}
		case "model":
			if !match(`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`, str(v)) || !strings.ContainsAny(str(v), "0123456789") {
				return fail(k)
			}
		case "account":
			if v != nil && !match(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, str(v)) {
				return fail(k)
			}
		case "effort":
			if v != nil && !match(`[a-z0-9][a-z0-9-]{0,31}`, str(v)) {
				return fail(k)
			}
		case "worktree", "log":
			if !absValue(v) {
				return fail(k)
			}
		case "repository", "claims":
			if v != nil && !absValue(v) {
				return fail(k)
			}
		case "branch":
			if v != nil && !match(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`, str(v)) {
				return fail(k)
			}
		case "base":
			if v != nil && !match(`[0-9a-f]{40}|[0-9a-f]{64}`, str(v)) {
				return fail(k)
			}
		case "brief":
			if !fileValue(v) {
				return fail(k)
			}
		case "message":
			if kind == "lane.resumed" && v != nil && !fileValue(v) {
				return fail(k)
			}
		case "budget_minutes":
			if !numeric(v) || number(v) <= 0 || number(v) > 10080 {
				return fail(k)
			}
		case "quiet_seconds":
			if !whole(v, 1, 604800) {
				return fail(k)
			}
		case "idle_seconds":
			if v != nil && !whole(v, 1, 604800) {
				return fail(k)
			}
		case "survivors":
			if !whole(v, 0, 1000000) {
				return fail(k)
			}
		case "duration_seconds", "elapsed_seconds":
			if !numeric(v) || number(v) < 0 || number(v) > 1e9 {
				return fail(k)
			}
		case "output_bytes":
			if !whole(v, 0, 1<<62) {
				return fail(k)
			}
		case "exit_code":
			if v != nil && !whole(v, 0, 255) {
				return fail(k)
			}
		case "signal":
			if v != nil && !whole(v, 1, 127) {
				return fail(k)
			}
		case "state":
			if !contains(strings.Fields("queued running verifying accepted merged abandoned waiting"), str(v)) {
				return fail(k)
			}
		case "how":
			if kind == "lane.started" && !contains([]string{"start", "resume", "reuse"}, str(v)) {
				return fail(k)
			}
		case "after":
			if v != nil && !contains(strings.Fields("exit timeout stopped limit dropped hook-config lost"), str(v)) {
				return fail(k)
			}
		case "reason":
			if kind == "lane.ended" && !contains(strings.Fields("exit timeout stopped limit dropped hook-config"), str(v)) {
				return fail(k)
			}
		case "session_id":
			if !match(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, str(v)) {
				return fail(k)
			}
		case "session":
			m := obj(v)
			if !exactKeys(m, []string{"socket", "name"}) || !absValue(m["socket"]) || !match(`[a-z0-9][a-z0-9_-]{0,63}`, str(m["name"])) {
				return fail(k)
			}
		case "chosen_by":
			m := obj(v)
			if !exactKeys(m, strings.Fields("runner model effort account")) {
				return fail(k)
			}
			for name, part := range m {
				if part == nil && (name == "effort" || name == "account") {
					continue
				}
				if !contains(strings.Fields("routing supervisor default previous room"), str(part)) {
					return fail(k)
				}
			}
		case "touches":
			a := stringsOf(v)
			if list(v) == nil || len(a) != len(unique(append([]string{}, a...))) {
				return fail(k)
			}
			for _, x := range a {
				if !contains([]string{"billing", "deploy"}, x) {
					return fail(k)
				}
			}
			if !sort.StringsAreSorted(a) {
				return fail(k)
			}
		case "refusal":
			if !match(`rf-[0-9a-f]{24}`, str(v)) {
				return fail(k)
			}
		case "suspicion":
			if !match(`ws-[0-9a-f]{24}`, str(v)) {
				return fail(k)
			}
		}
	}
	if kind == "lane.started" {
		if (str(p["how"]) == "start") != (integer(p["run"]) == 1) {
			return fail("run")
		}
		if (p["repository"] == nil) != (p["branch"] == nil) {
			return fail("branch")
		}
		if (p["effort"] == nil) != (obj(p["chosen_by"])["effort"] == nil) || (p["account"] == nil) != (obj(p["chosen_by"])["account"] == nil) {
			return fail("chosen_by")
		}
		if _, ok := p["mail"]; ok {
			if p["session_id"] == nil {
				return fail("session_id")
			}
			if str(p["how"]) != "resume" && len(list(p["mail"])) != 0 {
				return fail("mail")
			}
		}
	}
	if kind == "lane.ended" {
		if p["exit_code"] != nil && p["signal"] != nil {
			return fail("exit_code")
		}
		pat := str(p["pattern"])
		reason := str(p["reason"])
		if (pat != "") != contains([]string{"limit", "dropped"}, reason) || (pat != "" && !strings.HasPrefix(pat, reason+"_patterns[")) {
			return fail("pattern")
		}
		if (pat != "") != (str(p["classification"]) == "matched") {
			return fail("classification")
		}
		if contains([]string{"timeout", "stopped"}, reason) && p["classification"] != nil {
			return fail("classification")
		}
		if fate := obj(p["prompt"]); fate != nil {
			if !exactKeys(fate, strings.Fields("state bytes length")) || !contains([]string{"written", "cut"}, str(fate["state"])) || number(fate["bytes"]) > number(fate["length"]) || (str(fate["state"]) == "written") != (number(fate["bytes"]) == number(fate["length"])) {
				return fail("prompt")
			}
		}
	}
	return validateExtra(kind, p)
}
func (s *session) validateBinding(kind, lane string, p object) error {
	p = obj(nativeJSON(p))
	rendered := func(v any) bool {
		if v == nil {
			return true
		}
		m := obj(v)
		return str(m["path"]) == s.lanePath(lane, "rendered", str(m["sha256"])+".md")
	}
	if kind == "lane.started" || kind == "lane.adopted" {
		session := obj(p["session"])
		if str(session["socket"]) != socketPath(s.c) || str(session["name"]) != sessionName(lane) || str(p["log"]) != s.lanePath(lane, "output.log") || !rendered(p["brief"]) {
			return refuse("%s: payload is not bound to this lane's files and tmux session", kind)
		}
	}
	if kind == "lane.resumed" && !rendered(p["message"]) {
		return refuse("lane.resumed: message is not this lane's rendered file")
	}
	return nil
}
func refusalState(row object) object {
	if m := obj(row["refusals"]); m != nil {
		return m
	}
	return object{"recorded": object{}, "suspected": object{}, "verdicts": []any{}, "unreviewed": []any{}}
}
func unreviewed(found object) []any {
	reviewed := map[string]bool{}
	for _, v := range list(found["verdicts"]) {
		m := obj(v)
		for _, id := range stringsOf(m["suspicions"]) {
			reviewed[id+"\x00"+str(m["path"])] = true
		}
	}
	open := map[string][]string{}
	for id, v := range obj(found["suspected"]) {
		m := obj(v)
		for _, path := range stringsOf(m["paths"]) {
			if !reviewed[id+"\x00"+path] {
				key := str(m["refusal"]) + "\x00" + path
				open[key] = append(open[key], id)
			}
		}
	}
	keys := []string{}
	for k := range open {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := []any{}
	for _, key := range keys {
		p := strings.SplitN(key, "\x00", 2)
		sort.Strings(open[key])
		result = append(result, object{"refusal": p[0], "path": p[1], "suspicions": open[key]})
	}
	return result
}
func checkTransition(row object, e object) error {
	lane, kind := str(e["lane"]), str(e["kind"])
	p := obj(e["payload"])
	if row == nil {
		row = emptyProjection(lane)
	}
	run := integer(row["run"])
	running := flag(row["running"])
	mail := obj(row["mail"])
	based := flag(mail["turn_based"])
	if kind == "lane.ingested" && running {
		return refuse("lane.ingested: the lane started running while its history was read; the receipt was not recorded")
	}
	if kind == "lane.adopted" && integer(row["events"]) != 0 {
		return refuse("lane.adopted: an adoption is only for a lane with no event yet")
	}
	if kind == "lane.mailed" {
		if !based {
			return refuse("lane.mailed: lane is not turn-based")
		}
		if flag(row["cleaned"]) || str(row["state"]) == "abandoned" {
			return refuse("lane.mailed: lane was cleaned or abandoned")
		}
		if integer(p["sequence"]) != integer(mail["last"])+1 {
			return refuse("lane.mailed: sequence must follow the lane's last")
		}
		if len(list(mail["waiting"]))+len(list(mail["returned"])) >= 1000 {
			return refuse("lane.mailed: lane already holds the most queued messages")
		}
	}
	if kind == "lane.started" || kind == "lane.resumed" {
		if running {
			return refuse("%s: lane %s is running run %d", kind, lane, run)
		}
		if integer(p["run"]) != run+1 {
			return refuse("%s: payload.run must be %d, the run after the lane's last", kind, run+1)
		}
	}
	if kind == "lane.started" && str(p["how"]) == "reuse" {
		if !contains([]string{"merged", "abandoned"}, str(row["state"])) {
			return refuse("lane can be started again only when merged or abandoned")
		}
		if len(list(mail["waiting"]))+len(list(mail["returned"])) > 0 {
			return refuse("a new life is never sent mail written for the old one")
		}
	}
	if contains([]string{"lane.ended", "lane.timeout", "lane.stuck", "lane.lost"}, kind) && (!running || integer(p["run"]) != run) {
		return refuse("%s: lane %s has no run %d going on", kind, lane, integer(p["run"]))
	}
	if kind == "lane.gone" && integer(p["run"]) != run {
		return refuse("lane.gone must name the latest run")
	}
	if kind == "lane.cleaned" && (running || !contains([]string{"merged", "abandoned"}, str(row["state"]))) {
		return refuse("lane.cleaned: lane must be merged or abandoned and not running")
	}
	if kind == "lane.state" {
		if str(p["state"]) == "waiting" {
			return refuse("waiting is set only by the end of a run")
		}
		if based && str(p["state"]) != "abandoned" {
			return refuse("lane is turn-based, so only abandoned can be recorded")
		}
	}
	if based && str(row["state"]) == "abandoned" && (kind == "lane.resumed" || (kind == "lane.started" && str(p["how"]) == "resume")) {
		return refuse("lane is abandoned, so no turn starts")
	}
	if kind == "lane.started" && str(p["how"]) == "resume" {
		if _, ok := p["mail"]; ok {
			if !based {
				return refuse("a turn resumes a turn-based lane")
			}
			queue := append(append([]any{}, list(mail["returned"])...), list(mail["waiting"])...)
			carried := list(p["mail"])
			if len(carried) > len(queue) || !bytes.Equal(canonical(carried), canonical(queue[:len(carried)])) {
				return refuse("payload.mail must be the head of the queue")
			}
		} else if based {
			return refuse("lane is turn-based; lane resume is refused")
		}
	}
	found := refusalState(row)
	if contains([]string{"lane.refusal", "lane.workaround_suspected"}, kind) && (integer(p["run"]) < 1 || integer(p["run"]) > run) {
		return refuse("a refusal must belong to a started run")
	}
	if kind == "lane.workaround_suspected" || kind == "lane.refusal_reviewed" {
		original := obj(obj(found["recorded"])[str(p["refusal"])])
		if original == nil {
			return refuse("lane has no recorded refusal")
		}
		if kind == "lane.workaround_suspected" && integer(p["run"]) < integer(original["run"]) {
			return refuse("a suspicion comes after its refusal")
		}
		if kind == "lane.refusal_reviewed" {
			for _, id := range stringsOf(p["suspicions"]) {
				m := obj(obj(found["suspected"])[id])
				if m == nil || m["refusal"] != p["refusal"] || !contains(stringsOf(m["paths"]), str(p["path"])) {
					return refuse("suspicion is not a recorded suspicion naming the reviewed path")
				}
			}
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		settled := obj(mail["settled"])
		if running || settled == nil || flag(settled["announced"]) || integer(settled["run"]) != run || str(settled["outcome"]) != strings.TrimPrefix(kind, "lane.") || integer(p["run"]) != run || !bytes.Equal(canonical(p["sequences"]), canonical(settled["sequences"])) || (kind == "lane.returned" && p["reason"] != settled["reason"]) {
			return refuse("no matching settlement is due to be announced")
		}
	}
	return nil
}
func applyProjection(row object, e object) object {
	if row == nil {
		row = emptyProjection(str(e["lane"]))
	}
	p := obj(e["payload"])
	name := strings.TrimPrefix(str(e["kind"]), "lane.")
	at := e["occurred_at"]
	if at == nil {
		at = e["recorded_at"]
	}
	if contains(timeKinds, name) {
		obj(row["times"])[name] = at
	}
	if contains(landingKinds, name) {
		obj(row["landing"])[name] = at
	}
	state := map[string]string{"planned": "queued", "started": "running", "ended": "verifying", "lost": "verifying", "gone": "verifying", "adopted": "waiting"}[name]
	if name == "state" {
		state = str(p["state"])
	}
	mail := obj(row["mail"])
	closing := contains([]string{"ended", "lost", "gone"}, name)
	if closing && mail != nil {
		if str(row["state"]) == "abandoned" {
			state = ""
		} else if flag(mail["turn_based"]) {
			state = "waiting"
		}
	}
	if state != "" {
		row["state"] = state
		row["state_at"] = at
	}
	if name == "started" || name == "adopted" {
		row["run"] = p["run"]
		row["running"] = name == "started"
		row["reason"] = nil
		row["exit_code"] = nil
		row["cleaned"] = false
		for _, k := range strings.Fields("runner model effort account worktree branch") {
			row[k] = p[k]
		}
		if name == "adopted" {
			row["run"] = 1
			row["mail"] = object{"turn_based": true, "idle_seconds": p["idle_seconds"], "last": 0, "waiting": []any{}, "returned": []any{}, "in_flight": nil, "delivered": 0, "settled": nil}
		} else if carried, ok := p["mail"]; ok {
			if mail == nil {
				mail = object{"turn_based": false, "idle_seconds": nil, "last": 0, "waiting": []any{}, "returned": []any{}, "in_flight": nil, "delivered": 0, "settled": nil}
				row["mail"] = mail
			}
			mail["turn_based"] = true
			mail["idle_seconds"] = p["idle_seconds"]
			for _, k := range []string{"waiting", "returned"} {
				remaining := []any{}
				for _, v := range list(mail[k]) {
					taken := false
					for _, seq := range list(carried) {
						if number(v) == number(seq) {
							taken = true
						}
					}
					if !taken {
						remaining = append(remaining, v)
					}
				}
				mail[k] = remaining
			}
			mail["in_flight"] = nil
			if len(list(carried)) > 0 {
				mail["in_flight"] = object{"run": p["run"], "sequences": carried}
			}
		} else if mail != nil {
			mail["turn_based"] = false
		}
	}
	if name == "resumed" {
		row["resumes"] = integer(row["resumes"]) + 1
	}
	if name == "ended" {
		row["running"] = false
		row["reason"] = p["reason"]
		row["exit_code"] = p["exit_code"]
	}
	if name == "lost" {
		row["running"] = false
		row["reason"] = "lost"
		row["exit_code"] = nil
		row["lost"] = integer(row["lost"]) + 1
	}
	if name == "gone" {
		row["running"] = false
	}
	if name == "cleaned" {
		row["cleaned"] = true
	}
	if closing && mail != nil {
		flight := obj(mail["in_flight"])
		if flight != nil && integer(flight["run"]) == integer(p["run"]) {
			outcome, reason := settlement(name, p)
			mail["in_flight"] = nil
			if outcome == "delivered" {
				mail["delivered"] = integer(mail["delivered"]) + len(list(flight["sequences"]))
			} else {
				values := map[int]any{}
				for _, v := range append(list(mail["returned"]), list(flight["sequences"])...) {
					values[integer(v)] = v
				}
				keys := []int{}
				for k := range values {
					keys = append(keys, k)
				}
				sort.Ints(keys)
				returned := []any{}
				for _, k := range keys {
					returned = append(returned, values[k])
				}
				mail["returned"] = returned
			}
			mail["settled"] = object{"run": flight["run"], "outcome": outcome, "reason": reason, "sequences": flight["sequences"], "announced": false}
		}
	}
	if name == "delivered" || name == "returned" {
		obj(mail["settled"])["announced"] = true
	}
	if name == "mailed" {
		mail["last"] = p["sequence"]
		mail["waiting"] = append(list(mail["waiting"]), p["sequence"])
	}
	if contains([]string{"refusal", "workaround_suspected", "refusal_reviewed"}, name) {
		found := refusalState(row)
		if name == "refusal" {
			obj(found["recorded"])[str(p["refusal"])] = object{"run": p["run"], "seq": e["seq"], "guard": p["guard"], "tool": p["tool"]}
		} else if name == "workaround_suspected" {
			obj(found["suspected"])[str(p["suspicion"])] = object{"refusal": p["refusal"], "run": p["run"], "seq": e["seq"], "how": p["how"], "paths": p["paths"]}
		} else {
			found["verdicts"] = append(list(found["verdicts"]), object{"refusal": p["refusal"], "path": p["path"], "verdict": p["verdict"], "suspicions": p["suspicions"], "seq": e["seq"]})
		}
		found["unreviewed"] = unreviewed(found)
		row["refusals"] = found
	}
	row["events"] = integer(row["events"]) + 1
	row["last_seq"] = e["seq"]
	return row
}
func settlement(name string, p object) (string, any) {
	if name == "lost" || name == "gone" {
		return "returned", name
	}
	if str(p["reason"]) == "exit" && p["exit_code"] != nil && integer(p["exit_code"]) == 0 {
		if str(obj(p["prompt"])["state"]) == "written" {
			return "delivered", nil
		}
		return "returned", "cut"
	}
	return "returned", p["reason"]
}
func eventPointer(e object) any {
	if e == nil {
		return nil
	}
	return object{"id": e["id"], "seq": e["seq"]}
}
func eventLabel(e object) string { return fmt.Sprintf("event seq %d", integer(e["seq"])) }
