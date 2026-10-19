package start

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/lanesandbox"
	"laneboss.io/laneboss/internal/observation"
	"laneboss.io/laneboss/internal/rolepolicy"
	"laneboss.io/laneboss/internal/settings"
)

var laneRE = rx(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var digestRE = rx(`^[0-9a-f]{64}$`)
var timestampRE = rx(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)
var times = strings.Fields("planned started ended timeout stuck resumed lost cleaned")
var landings = strings.Fields("merged deployed landed")
var closing = strings.Fields("ended lost gone")
var reasons = strings.Fields("exit timeout stopped limit dropped hook-config")

func integer(v any) int64 { n, _ := intValue(v); return n }
func timestampCheck(l string, v any, p string) error {
	s, ok := v.(string)
	if !ok || !timestampRE.MatchString(s) {
		return invalid(l, p, "must be a timestamp")
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
		return invalid(l, p, "is not a valid date and time")
	}
	return nil
}
func exactObject(fields map[string]validator) validator {
	return tableCheck(fields, sortedKeysChecks(fields)...)
}
func sortedKeysChecks(m map[string]validator) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func sortedList(check validator, min, max int) validator {
	return func(l string, v any, p string) error {
		if err := listCheck(check, min > 0, true, max)(l, v, p); err != nil {
			return err
		}
		a := array(v)
		if len(a) < min {
			return invalid(l, p, "has too few items")
		}
		for i := 1; i < len(a); i++ {
			before, ok1 := numberValue(a[i-1])
			after, ok2 := numberValue(a[i])
			if ok1 && ok2 {
				if before >= after {
					return invalid(l, p, "must be sorted, without repeats")
				}
			} else if str(a[i-1]) >= str(a[i]) {
				return invalid(l, p, "must be sorted, without repeats")
			}
		}
		return nil
	}
}
func recordPathCheck(l string, v any, p string) error {
	s, ok := v.(string)
	if ok && (rx(`^\(withheld [0-9a-f]{64}\)$`).MatchString(s) || rx(`^\([1-9][0-9]{0,8} more\)$`).MatchString(s)) {
		return nil
	}
	return absoluteCheck(l, v, p)
}
func suspectedPathCheck(l string, v any, p string) error {
	if v == "(command)" {
		return nil
	}
	return recordPathCheck(l, v, p)
}
func plainTextCheck(limit int) validator {
	return func(l string, v any, p string) error {
		s, ok := v.(string)
		if !ok || utf8.RuneCountInString(s) > limit {
			return invalid(l, p, "must be a bounded text")
		}
		return nil
	}
}
func excerptCheck(l string, v any, p string) error {
	fields := map[string]validator{"text": nullable(plainTextCheck(400)), "withheld": boolCheck, "length": integerCheck(0, 1<<62), "sha256": textCheck(`[0-9a-f]{64}`, 64)}
	if err := exactObject(fields)(l, v, p); err != nil {
		return err
	}
	m := object(v)
	if m["withheld"] == true {
		if m["text"] != nil {
			return invalid(l, p+".text", "is null when the excerpt is withheld")
		}
	} else {
		if _, ok := m["text"].(string); !ok || int64(utf8.RuneCountInString(str(m["text"]))) > integer(m["length"]) {
			return invalid(l, p+".text", "must be the start of the text")
		}
	}
	return nil
}
func noteCheck(l string, v any, p string) error {
	if err := exactObject(map[string]validator{"text": plainTextCheck(4000), "sha256": textCheck(`[0-9a-f]{64}`, 64)})(l, v, p); err != nil {
		return err
	}
	if strings.TrimSpace(str(object(v)["text"])) == "" {
		return invalid(l, p+".text", "must not be empty")
	}
	return nil
}
func cleanCheck(kept bool) validator {
	return func(l string, v any, p string) error {
		m := object(v)
		kind := str(m["item"])
		fields := map[string]validator{"item": choices("worktree", "branch", "session", "lane-directory")}
		if kind == "branch" || kind == "session" {
			fields["name"] = textCheck(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`, 255)
		} else {
			fields["path"] = absoluteCheck
		}
		if kept {
			fields["why"] = choices("not-created", "missing", "not-this-lane", "abandoned", "not-merged", "record")
		}
		return exactObject(fields)(l, v, p)
	}
}
func heldCheck(l string, v any, p string) error {
	if err := listCheck(exactObject(map[string]validator{"resource": textCheck(`rs-[0-9a-f]{24}`, 27), "state": choices("intent", "acquired")}), false, false, 256)(l, v, p); err != nil {
		return err
	}
	last := ""
	for _, item := range array(v) {
		name := str(object(item)["resource"])
		if name <= last {
			return invalid(l, p, "must be sorted by resource, without repeats")
		}
		last = name
	}
	return nil
}
func touchesCheck(l string, v any, p string) error {
	return sortedList(choices("billing", "deploy"), 0, 2)(l, v, p)
}
func lanePayload(kind, lane string, p map[string]any) error {
	label := kind
	run := integerCheck(1, 1000000)
	name := textCheck(nameRule, 32)
	nullableName := nullable(name)
	file := exactObject(map[string]validator{"path": absoluteCheck, "sha256": textCheck(`[0-9a-f]{64}`, 64)})
	carried := sortedList(integerCheck(1, 999999999), 0, 64)
	announced := sortedList(integerCheck(1, 999999999), 1, 64)
	chosen := exactObject(map[string]validator{"runner": choices("routing", "supervisor", "previous", "settings"), "model": choices("routing", "supervisor", "previous", "settings"), "effort": nullable(choices("routing", "supervisor", "previous", "settings")), "account": nullable(choices("supervisor", "default", "previous", "room", "settings"))})
	fields := map[string]validator{}
	switch kind {
	case "lane.planned", "lane.merged", "lane.deployed", "lane.landed":
	case "lane.state":
		fields["state"] = choices("queued", "running", "verifying", "accepted", "merged", "abandoned", "waiting")
		if _, ok := p["not_covered"]; ok {
			fields["not_covered"] = listCheck(exactObject(map[string]validator{"run": run, "reason": textCheck(`[a-z][a-z-]{0,39}`, 40), "path": nullable(textCheck("", 4096))}), true, false, 4096)
		}
		if _, ok := p["held"]; ok {
			fields["held"] = heldCheck
		}
	case "lane.started", "lane.adopted":
		if err := records.Validate(p); err != nil {
			return invalid(label, "payload report line", err.Error())
		}
		fields = map[string]validator{"runner": name, "model": modelCheck, "effort": nullableName, "account": nullable(textCheck(accountRule, 64)), "chosen_by": chosen, "difficulty": nullable(choices("mechanical", "standard", "hard", "review")), "project": nullableName, "worktree": absoluteCheck, "branch": nullable(textCheck(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`, 255)), "base": nullable(textCheck(`[0-9a-f]{40}|[0-9a-f]{64}`, 64)), "repository": nullable(absoluteCheck), "budget_minutes": numberCheck(0, 10080, true), "quiet_seconds": integerCheck(1, 604800), "brief": file, "log": absoluteCheck, "session": exactObject(map[string]validator{"socket": absoluteCheck, "name": textCheck(`[a-z0-9][a-z0-9_-]{0,63}`, 64)}), "touches": touchesCheck, "claims": nullable(absoluteCheck)}
		for _, key := range []string{"level", "level_source", "starter"} {
			if _, ok := p[key]; ok {
				fields[key] = func(label string, value any, path string) error {
					if err := records.Field(key, value); err != nil {
						return invalid(label, path, err.Error())
					}
					return nil
				}
			}
		}
		if kind == "lane.started" {
			fields["run"] = run
			fields["how"] = choices("start", "resume", "reuse")
			fields["launch"] = textCheck(`[0-9a-f]{32}`, 32)
		}
		if _, ok := p["session_id"]; ok || kind == "lane.adopted" {
			fields["session_id"] = textCheck(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, 36)
		}
		if _, ok := p["mail"]; ok && kind == "lane.started" {
			fields["mail"] = carried
			fields["idle_seconds"] = nullable(integerCheck(1, 604800))
		} else if _, ok := p["idle_seconds"]; ok && kind != "lane.adopted" {
			return invalid(label, "payload.idle_seconds", "is there only together with payload.mail")
		}
		if kind == "lane.adopted" {
			fields["idle_seconds"] = nullable(integerCheck(1, 604800))
		}
	case "lane.resumed":
		fields = map[string]validator{"run": integerCheck(2, 1000000), "after": nullable(choices("exit", "timeout", "stopped", "limit", "dropped", "hook-config", "lost")), "message": nullable(file)}
	case "lane.ended":
		fields = map[string]validator{"run": run, "reason": choices(reasons...), "exit_code": nullable(integerCheck(0, 255)), "signal": nullable(integerCheck(1, 127)), "duration_seconds": numberCheck(0, 1e9, false), "pattern": nullable(textCheck(`(?:limit|dropped)_patterns\[[0-9]{1,4}\]`, 1000)), "classification": nullable(choices("matched", "unmatched", "timed-out")), "survivors": integerCheck(0, 1000000)}
		if _, ok := p["prompt"]; ok {
			fields["prompt"] = exactObject(map[string]validator{"state": choices("written", "cut"), "bytes": integerCheck(0, 1<<62), "length": integerCheck(1, 1<<62)})
		}
	case "lane.timeout":
		fields = map[string]validator{"run": run, "budget_minutes": numberCheck(0, 10080, true), "elapsed_seconds": numberCheck(0, 1e9, false)}
	case "lane.stuck":
		fields = map[string]validator{"run": run, "quiet_seconds": integerCheck(1, 604800), "output_bytes": integerCheck(0, 1<<62)}
	case "lane.lost":
		fields = map[string]validator{"run": run, "survivors": integerCheck(0, 1000000)}
	case "lane.gone":
		fields = map[string]validator{"run": run, "launch": textCheck(`[0-9a-f]{32}`, 32)}
	case "lane.cleaned":
		fields = map[string]validator{"removed": listCheck(cleanCheck(false), false, false, 64), "kept": listCheck(cleanCheck(true), false, false, 64)}
	case "lane.mailed":
		fields = map[string]validator{"sequence": integerCheck(1, 999999999), "sender": func(label string, value any, path string) error {
			id, ok := value.(string)
			if !ok || !records.ValidSender(id) {
				return invalid(label, path, "must be a sender label or principal node id")
			}
			return nil
		}, "sha256": textCheck(`[0-9a-f]{64}`, 64), "bytes": integerCheck(1, 262144)}
		if _, exists := p["legacy_relationship"]; exists {
			fields["legacy_relationship"] = func(label string, value any, path string) error {
				if value != true {
					return invalid(label, path, "must be true when present")
				}
				return nil
			}
		}
	case "lane.delivered", "lane.returned":
		fields = map[string]validator{"run": integerCheck(2, 1000000), "sequences": announced}
		if kind == "lane.returned" {
			fields["reason"] = choices("exit", "timeout", "stopped", "limit", "dropped", "hook-config", "lost", "gone", "cut")
		}
	case "lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed":
		position := exactObject(map[string]validator{"path": recordPathCheck, "line": integerCheck(1, 1<<62), "offset": integerCheck(0, 1<<62), "item": integerCheck(0, 1000000)})
		refusalID := textCheck(`rf-[0-9a-f]{24}`, 27)
		suspicionID := textCheck(`ws-[0-9a-f]{24}`, 27)
		tool := textCheck(`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`, 64)
		callID := nullable(textCheck(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, 128))
		call := exactObject(map[string]validator{"id": callID, "record": position})
		if kind == "lane.refusal" {
			fields = map[string]validator{"run": run, "refusal": refusalID, "guard": textCheck(accountRule, 64), "kind": nullable(choices("hook", "permission", "harness")), "format": choices("claude-code", "text"), "via": choices("tool-result", "hook", "log"), "hook": nullable(exactObject(map[string]validator{"event": nullable(textCheck(`[A-Za-z][A-Za-z0-9_]{0,63}`, 64)), "name": nullable(textCheck(`[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}`, 128))})), "tool": nullable(tool), "at": nullable(timestampCheck), "command": nullable(excerptCheck), "message": excerptCheck, "targets": sortedList(recordPathCheck, 0, 1024), "call": nullable(exactObject(map[string]validator{"id": callID, "record": nullable(position)})), "record": position, "workarounds_checked": boolCheck}
		}
		if kind == "lane.workaround_suspected" {
			fields = map[string]validator{"run": run, "suspicion": suspicionID, "refusal": nullable(refusalID), "how": sortedList(choices("reworded", "shell-write", "shell-substitution-in-text"), 1, 2), "paths": sortedList(suspectedPathCheck, 1, 1024), "tool": tool, "at": nullable(timestampCheck), "command": excerptCheck, "call": call, "similarity": nullable(exactObject(map[string]validator{"containment": numberCheck(0, 1, false), "coverage": numberCheck(0, 1, false)}))}
		}
		if kind == "lane.refusal_reviewed" {
			fields = map[string]validator{"refusal": refusalID, "path": suspectedPathCheck, "verdict": choices("clean", "workaround"), "suspicions": sortedList(suspicionID, 1, 4096), "note": nullable(noteCheck)}
		}
	case "lane.ingested":
		fields = map[string]validator{"lane": textCheck(`[a-z0-9][a-z0-9._-]{0,63}`, 64), "rows_added": integerCheck(0, 4096), "rows_existing": integerCheck(0, 4096), "rows": listCheck(exactObject(map[string]validator{"id": textCheck(`[a-z0-9][a-z0-9-]{0,31}/[a-z0-9][a-z0-9._-]{0,63}/(?:report|events|attachment)/[0-9a-f]{16}`, 255), "sha256": textCheck(`[0-9a-f]{64}`, 64)}), false, false, 4096)}
	default:
		return integrity("kind: unknown lane event")
	}
	if !laneRE.MatchString(lane) {
		return integrity("lane: is required for lane events")
	}
	if kind == "lane.started" || kind == "lane.adopted" {
		if _, exists := p["settings"]; exists {
			check := settings.EventField(p)
			fields["settings"] = func(_ string, value any, path string) error { return check(value, path) }
		}
		if _, exists := p["runner_sandbox"]; exists {
			fields["runner_sandbox"] = choices(lanesandbox.RunnerReplaced)
		}
		if err := rolepolicy.ValidateEvent(p); err != nil {
			return integrity(err.Error())
		}
		if _, exists := p["role_context"]; exists {
			for _, key := range []string{"role", "role_context"} {
				check := rolepolicy.EventField(p, key)
				fields[key] = func(_ string, value any, path string) error { return check(value, path) }
			}
		}
	}
	if err := exactObject(fields)(label, p, "payload"); err != nil {
		return integrity(err.Error())
	}
	bad := func(field, message string) error { return integrity(kind + " payload." + field + ": " + message) }
	if kind == "lane.started" || kind == "lane.adopted" {
		choice := object(p["chosen_by"])
		for _, key := range []string{"effort", "account"} {
			if (p[key] == nil) != (choice[key] == nil) {
				return bad("chosen_by."+key, "is null exactly when its value is null")
			}
		}
		if (p["repository"] == nil) != (p["branch"] == nil) {
			return bad("branch", "is null exactly when repository is null")
		}
		if kind == "lane.started" {
			if (p["how"] == "start") != (integer(p["run"]) == 1) {
				return bad("run", "is 1 exactly when how is start")
			}
			if mail, ok := p["mail"]; ok {
				if p["session_id"] == nil {
					return bad("session_id", "is required when mail is there")
				}
				if p["how"] != "resume" && len(array(mail)) > 0 {
					return bad("mail", "must be empty for a first run or reuse")
				}
			}
		} else {
			if p["difficulty"] != nil {
				return bad("difficulty", "is null for an adoption")
			}
			for _, key := range []string{"runner", "model", "effort", "account"} {
				if choice[key] != nil && choice[key] != "supervisor" {
					return bad("chosen_by."+key, "is supervisor for an adoption")
				}
			}
		}
	}
	if kind == "lane.ended" {
		if p["exit_code"] != nil && p["signal"] != nil {
			return bad("exit_code", "at most one of exit_code and signal is set")
		}
		pattern := p["pattern"] != nil
		matched := p["classification"] == "matched"
		limited := p["reason"] == "limit" || p["reason"] == "dropped"
		if pattern != limited || pattern && !strings.HasPrefix(str(p["pattern"]), str(p["reason"])+"_") {
			return bad("pattern", "names the matching pattern exactly when the reason is limit or dropped")
		}
		if pattern != matched {
			return bad("classification", "is matched exactly when a pattern is named")
		}
		if (p["reason"] == "timeout" || p["reason"] == "stopped") && p["classification"] != nil {
			return bad("classification", "is null for a stopped or timed out run")
		}
		if fate, ok := p["prompt"]; ok {
			m := object(fate)
			if (m["state"] == "written") != (integer(m["bytes"]) == integer(m["length"])) || integer(m["bytes"]) > integer(m["length"]) {
				return bad("prompt", "is written exactly when every byte was written")
			}
		}
	}
	if kind == "lane.state" {
		for _, key := range []string{"held", "not_covered"} {
			if value, ok := p[key]; ok && (!contains([]string{"accepted", "merged"}, str(p["state"])) || len(array(value)) == 0) {
				return bad(key, "is a nonempty list only when accepted or merged")
			}
		}
	}
	if kind == "lane.refusal" {
		if (p["format"] == "text") != (p["via"] == "log") {
			return bad("via", "is log exactly for a text record")
		}
		if (p["via"] == "hook") != (p["hook"] != nil) {
			return bad("hook", "names the hook exactly when the refusal came through it")
		}
		if p["format"] == "text" {
			if p["tool"] != nil || p["command"] != nil || p["call"] != nil || len(array(p["targets"])) != 0 || p["workarounds_checked"] != false {
				return bad("format", "a text record names no tool, command, call or target")
			}
		} else if p["call"] == nil {
			return bad("call", "is required for a refusal in a claude-code record")
		}
	}
	if kind == "lane.workaround_suspected" {
		if err := observation.Check(p); err != nil {
			return integrity(kind + ": " + err.Error())
		}
		if (p["similarity"] != nil) != contains(stringsOf(p["how"]), "reworded") {
			return bad("similarity", "is given exactly when the way includes reworded")
		}
	}
	if kind == "lane.refusal_reviewed" && rx(`^\([1-9][0-9]{0,8} more\)$`).MatchString(str(p["path"])) {
		return bad("path", "a verdict names one path")
	}
	return nil
}

func emptyLane(lane string) map[string]any {
	t, l := map[string]any{}, map[string]any{}
	for _, key := range times {
		t[key] = nil
	}
	for _, key := range landings {
		l[key] = nil
	}
	return map[string]any{"lane": lane, "state": nil, "state_at": nil, "times": t, "landing": l, "run": int64(0), "running": false, "runner": nil, "model": nil, "effort": nil, "account": nil, "worktree": nil, "branch": nil, "reason": nil, "exit_code": nil, "resumes": int64(0), "lost": int64(0), "cleaned": false, "events": int64(0), "last_seq": nil}
}
func newMail() map[string]any {
	return map[string]any{"turn_based": false, "idle_seconds": nil, "last": int64(0), "waiting": []any{}, "returned": []any{}, "in_flight": nil, "delivered": int64(0), "settled": nil}
}
func laneTransition(row, event map[string]any) error {
	kind, p, lane := str(event["kind"]), object(event["payload"]), str(event["lane"])
	if row == nil {
		row = emptyLane(lane)
	}
	running := row["running"] == true
	mail := object(row["mail"])
	based := mail["turn_based"] == true
	bad := func(message string) error { return integrity(kind + ": lane " + lane + " " + message) }
	if kind == "lane.started" || kind == "lane.resumed" {
		if running {
			return bad("is running; a new run starts only after it ends")
		}
		if integer(p["run"]) != integer(row["run"])+1 {
			return bad("run must follow the lane's last run")
		}
		if kind == "lane.started" && p["how"] == "reuse" && !contains([]string{"merged", "abandoned"}, str(row["state"])) {
			return bad("can be reused only when merged or abandoned")
		}
	}
	if kind == "lane.adopted" && integer(row["events"]) != 0 {
		return bad("already has events; adoption needs a new lane")
	}
	if contains([]string{"lane.ended", "lane.timeout", "lane.stuck", "lane.lost"}, kind) && (!running || integer(p["run"]) != integer(row["run"])) {
		return bad("has no such run going on")
	}
	if kind == "lane.cleaned" && (running || !contains([]string{"merged", "abandoned"}, str(row["state"]))) {
		return bad("must be merged or abandoned and not running")
	}
	if kind == "lane.gone" && integer(p["run"]) != integer(row["run"]) {
		return bad("the declaration must name its latest run")
	}
	if kind == "lane.mailed" {
		if !based || row["cleaned"] == true || row["state"] == "abandoned" {
			return bad("does not accept mail in its current state")
		}
		if integer(p["sequence"]) != integer(mail["last"])+1 {
			return bad("mail sequence must follow its last")
		}
		if len(array(mail["waiting"]))+len(array(mail["returned"])) >= 1000 {
			return bad("holds the maximum number of queued messages")
		}
	}
	if (kind == "lane.resumed" || kind == "lane.started" && p["how"] == "resume") && based && row["state"] == "abandoned" {
		return bad("is abandoned, so no turn starts")
	}
	if kind == "lane.started" {
		if p["how"] == "reuse" && (len(array(mail["waiting"])) > 0 || len(array(mail["returned"])) > 0) {
			return bad("has messages for its previous life")
		}
		if carried, ok := p["mail"]; ok && p["how"] == "resume" {
			queue := append(append([]any{}, array(mail["returned"])...), array(mail["waiting"])...)
			n := len(array(carried))
			if !based || n > len(queue) || !same(carried, queue[:n]) {
				return bad("mail must be the head of its turn queue")
			}
		} else if !ok && p["how"] == "resume" && based {
			return bad("is turn-based, so a resume carries mail")
		}
	}
	if kind == "lane.state" {
		if p["state"] == "waiting" {
			return bad("waiting is set only by the end of a turn")
		}
		if based && p["state"] != "abandoned" {
			return bad("is turn-based, so only abandoned can be recorded")
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		settled := object(mail["settled"])
		wanted := strings.TrimPrefix(kind, "lane.")
		if running || len(settled) == 0 || integer(settled["run"]) != integer(row["run"]) || settled["announced"] == true || settled["outcome"] != wanted || !same(p["run"], settled["run"]) || !same(p["sequences"], settled["sequences"]) || kind == "lane.returned" && p["reason"] != settled["reason"] {
			return bad("has no matching unannounced settlement of its latest run")
		}
	}
	if contains([]string{"lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed"}, kind) {
		found := refusalState(row)
		recorded, suspected := object(found["recorded"]), object(found["suspected"])
		rid := str(p["refusal"])
		if kind != "lane.refusal_reviewed" && (integer(p["run"]) < 1 || integer(p["run"]) > integer(row["run"])) {
			return bad("has no such run")
		}
		if kind == "lane.refusal" {
			if recorded[rid] != nil {
				return bad("already records this refusal")
			}
		} else if !(kind == "lane.workaround_suspected" && p["refusal"] == nil) && recorded[rid] == nil {
			return bad("has no recorded refusal for this event")
		}
		if kind == "lane.workaround_suspected" {
			if suspected[str(p["suspicion"])] != nil || p["refusal"] != nil && integer(p["run"]) < integer(object(recorded[rid])["run"]) {
				return bad("the suspicion is duplicate or precedes its refusal")
			}
		}
		if kind == "lane.refusal_reviewed" {
			for _, sid := range stringsOf(p["suspicions"]) {
				item := object(suspected[sid])
				if item["refusal"] != rid || !contains(stringsOf(item["paths"]), str(p["path"])) {
					return bad("a reviewed suspicion does not name this refusal and path")
				}
			}
		}
	}
	return nil
}
func refusalState(row map[string]any) map[string]any {
	if value, ok := row["refusals"]; ok {
		return object(value)
	}
	return map[string]any{"recorded": map[string]any{}, "suspected": map[string]any{}, "verdicts": []any{}, "unreviewed": []any{}}
}
func applyRefusal(row, event map[string]any) {
	found := refusalState(row)
	p := object(event["payload"])
	switch event["kind"] {
	case "lane.refusal":
		object(found["recorded"])[str(p["refusal"])] = map[string]any{"run": p["run"], "seq": event["seq"], "guard": p["guard"], "tool": p["tool"]}
	case "lane.workaround_suspected":
		object(found["suspected"])[str(p["suspicion"])] = map[string]any{"refusal": p["refusal"], "run": p["run"], "seq": event["seq"], "how": p["how"], "paths": p["paths"]}
	default:
		found["verdicts"] = append(array(found["verdicts"]), map[string]any{"refusal": p["refusal"], "path": p["path"], "verdict": p["verdict"], "suspicions": p["suspicions"], "seq": event["seq"]})
	}
	reviewed := map[string]bool{}
	for _, value := range array(found["verdicts"]) {
		v := object(value)
		for _, sid := range stringsOf(v["suspicions"]) {
			reviewed[sid+"\x00"+str(v["path"])] = true
		}
	}
	open := map[string]any{}
	for _, sid := range sortedKeys(object(found["suspected"])) {
		item := object(object(found["suspected"])[sid])
		if item["refusal"] == nil {
			continue
		}
		for _, path := range stringsOf(item["paths"]) {
			if reviewed[sid+"\x00"+path] {
				continue
			}
			key := str(item["refusal"]) + "\x00" + path
			entry := object(open[key])
			if len(entry) == 0 {
				entry = map[string]any{"refusal": item["refusal"], "path": path, "suspicions": []any{}}
				open[key] = entry
			}
			entry["suspicions"] = append(array(entry["suspicions"]), sid)
		}
	}
	out := []any{}
	for _, key := range sortedKeys(open) {
		out = append(out, open[key])
	}
	found["unreviewed"] = out
	row["refusals"] = found
}
func applyLane(row, event map[string]any) {
	p := object(event["payload"])
	name := strings.TrimPrefix(str(event["kind"]), "lane.")
	at := event["occurred_at"]
	if at == nil || at == "" {
		at = event["recorded_at"]
	}
	if contains(times, name) {
		object(row["times"])[name] = at
	}
	if contains(landings, name) {
		object(row["landing"])[name] = at
	}
	var state any
	switch name {
	case "planned":
		state = "queued"
	case "started":
		state = "running"
	case "ended", "lost", "gone":
		state = "verifying"
	case "state":
		state = p["state"]
	case "adopted":
		state = "waiting"
	}
	mail := object(row["mail"])
	if contains(closing, name) && len(mail) > 0 {
		if row["state"] == "abandoned" {
			state = nil
		} else if mail["turn_based"] == true {
			state = "waiting"
		}
	}
	if state != nil {
		row["state"] = state
		row["state_at"] = at
	}
	if name == "started" || name == "adopted" {
		row["run"] = p["run"]
		row["running"] = name == "started"
		row["reason"] = nil
		row["exit_code"] = nil
		row["cleaned"] = false
		for _, key := range []string{"runner", "model", "effort", "account", "worktree", "branch"} {
			row[key] = p[key]
		}
		if name == "adopted" {
			row["run"] = int64(1)
			mail = newMail()
			mail["turn_based"] = true
			mail["idle_seconds"] = p["idle_seconds"]
			row["mail"] = mail
		} else if carried, ok := p["mail"]; ok {
			if len(mail) == 0 {
				mail = newMail()
				row["mail"] = mail
			}
			mail["turn_based"] = true
			mail["idle_seconds"] = p["idle_seconds"]
			for _, key := range []string{"waiting", "returned"} {
				kept := []any{}
				for _, n := range array(mail[key]) {
					in := false
					for _, c := range array(carried) {
						if same(n, c) {
							in = true
							break
						}
					}
					if !in {
						kept = append(kept, n)
					}
				}
				mail[key] = kept
			}
			mail["in_flight"] = nil
			if len(array(carried)) > 0 {
				mail["in_flight"] = map[string]any{"run": p["run"], "sequences": append([]any{}, array(carried)...)}
			}
		} else if len(mail) > 0 {
			mail["turn_based"] = false
		}
	}
	switch name {
	case "resumed":
		row["resumes"] = integer(row["resumes"]) + 1
	case "ended":
		row["running"] = false
		row["reason"] = p["reason"]
		row["exit_code"] = p["exit_code"]
	case "lost":
		row["running"] = false
		row["reason"] = "lost"
		row["exit_code"] = nil
		row["lost"] = integer(row["lost"]) + 1
	case "gone":
		row["running"] = false
	case "cleaned":
		row["cleaned"] = true
	case "mailed":
		mail["last"] = p["sequence"]
		mail["waiting"] = append(array(mail["waiting"]), p["sequence"])
	case "delivered", "returned":
		object(mail["settled"])["announced"] = true
	}
	if contains(closing, name) && len(mail) > 0 {
		settleMail(mail, name, p)
	}
	if contains([]string{"refusal", "workaround_suspected", "refusal_reviewed"}, name) {
		applyRefusal(row, event)
	}
	row["events"] = integer(row["events"]) + 1
	row["last_seq"] = event["seq"]
}
func settleMail(mail map[string]any, name string, p map[string]any) {
	flight := object(mail["in_flight"])
	if len(flight) == 0 || integer(flight["run"]) != integer(p["run"]) {
		return
	}
	outcome, reason := any("returned"), any(p["reason"])
	if name == "lost" || name == "gone" {
		reason = name
	} else if p["reason"] == "exit" && p["exit_code"] != nil && integer(p["exit_code"]) == 0 {
		if object(p["prompt"])["state"] == "written" {
			outcome, reason = "delivered", nil
		} else {
			reason = "cut"
		}
	}
	mail["in_flight"] = nil
	if outcome == "delivered" {
		mail["delivered"] = integer(mail["delivered"]) + int64(len(array(flight["sequences"])))
	} else {
		unique := map[int64]bool{}
		for _, n := range append(append([]any{}, array(mail["returned"])...), array(flight["sequences"])...) {
			unique[integer(n)] = true
		}
		keys := []int64{}
		for n := range unique {
			keys = append(keys, n)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		returned := []any{}
		for _, n := range keys {
			returned = append(returned, n)
		}
		mail["returned"] = returned
	}
	mail["settled"] = map[string]any{"run": flight["run"], "outcome": outcome, "reason": reason, "sequences": append([]any{}, array(flight["sequences"])...), "announced": false}
}
func fold(events []map[string]any) ([]map[string]any, error) {
	rows := map[string]any{}
	resources := map[string]any{}
	for _, event := range events {
		kind, lane := str(event["kind"]), str(event["lane"])
		row := object(rows[lane])
		if len(row) == 0 {
			row = nil
		}
		if strings.HasPrefix(kind, "resource.") {
			if err := resourceTransition(row, resources, event); err != nil {
				return nil, integrity(fmt.Sprintf("event seq %d: %s", integer(event["seq"]), err))
			}
			applyResource(resources, event)
			continue
		}
		if !strings.HasPrefix(kind, "lane.") {
			continue
		}
		if err := laneTransition(row, event); err != nil {
			return nil, integrity(fmt.Sprintf("event seq %d: %s", integer(event["seq"]), err))
		}
		if kind == "lane.state" && contains([]string{"accepted", "merged"}, str(object(event["payload"])["state"])) && atLeastVersion(str(event["protocol_version"]), "1.3.0") {
			if err := checkHeld(resources, event); err != nil {
				return nil, err
			}
		}
		if row == nil {
			row = emptyLane(lane)
			rows[lane] = row
		}
		applyLane(row, event)
	}
	out := []map[string]any{}
	for _, name := range sortedKeys(rows) {
		out = append(out, object(rows[name]))
	}
	return out, nil
}
