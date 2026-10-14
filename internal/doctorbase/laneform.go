package doctorbase

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

func checkNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if !strings.ContainsAny(x.String(), ".eE") {
			if n, err := x.Int64(); err == nil {
				return n
			}
		}
		if n, err := x.Float64(); err == nil {
			return n
		}
		return x
	case map[string]any:
		m := map[string]any{}
		for k, item := range x {
			m[k] = checkNumbers(item)
		}
		return m
	case []any:
		a := make([]any, len(x))
		for i, item := range x {
			a[i] = checkNumbers(item)
		}
		return a
	}
	return v
}
func null(check validator) validator {
	return func(v any, p string) error {
		if v == nil {
			return nil
		}
		return check(v, p)
	}
}
func exact(fields map[string]validator) validator {
	required := make([]string, 0, len(fields))
	for k := range fields {
		required = append(required, k)
	}
	return table(fields, required...)
}
func grammar(rule string) validator {
	r := regexp.MustCompile("^(?:" + rule + ")$")
	return func(v any, p string) error {
		s, ok := v.(string)
		if !ok || !r.MatchString(s) {
			return failure(p, "does not match the required grammar")
		}
		return nil
	}
}
func eventAbsolute(v any, p string) error {
	if err := text("", 4096)(v, p); err != nil {
		return err
	}
	if !strings.HasPrefix(String(v), "/") {
		return failure(p, "must be an absolute path on one line")
	}
	return nil
}
func eventTimestamp(v any, p string) error {
	if !validTimestamp(v) {
		return failure(p, "is not a valid date and time")
	}
	return nil
}
func boundedArray(check validator, min, max int, sorted bool) validator {
	return func(v any, p string) error {
		a, ok := v.([]any)
		if !ok || len(a) < min || len(a) > max {
			return failure(p, fmt.Sprintf("must be a list of %d to %d items", min, max))
		}
		for i, x := range a {
			if err := check(x, fmt.Sprintf("%s[%d]", p, i)); err != nil {
				return err
			}
			if sorted && i > 0 {
				less := false
				if s, ok := x.(string); ok {
					less = String(a[i-1]) < s
				} else {
					less = Number(a[i-1]) < Number(x)
				}
				if !less {
					return failure(p, "must be sorted, without repeats")
				}
			}
		}
		return nil
	}
}
func eventTouches(v any, p string) error {
	return boundedArray(choice("billing", "deploy"), 0, 2, true)(v, p)
}
func recordPath(v any, p string) error {
	s := String(v)
	if regexp.MustCompile(`^(?:\(withheld [0-9a-f]{64}\)|\([1-9][0-9]{0,8} more\))$`).MatchString(s) {
		return nil
	}
	return eventAbsolute(v, p)
}
func suspectedPath(v any, p string) error {
	if v == "(command)" {
		return nil
	}
	return recordPath(v, p)
}
func excerpt(v any, p string) error {
	if err := exact(map[string]validator{"text": func(any, string) error { return nil }, "withheld": boolean, "length": integer(0, 1<<62), "sha256": grammar("[0-9a-f]{64}")})(v, p); err != nil {
		return err
	}
	m := Object(v)
	if m["withheld"] == true {
		if m["text"] != nil {
			return failure(p+".text", "is null when the excerpt is withheld")
		}
	} else {
		s, ok := m["text"].(string)
		if !ok || utf8.RuneCountInString(s) > 400 || float64(utf8.RuneCountInString(s)) > Number(m["length"]) {
			return failure(p+".text", "must be the start of the text, at most 400 characters")
		}
	}
	return nil
}
func eventNote(v any, p string) error {
	if err := exact(map[string]validator{"text": func(any, string) error { return nil }, "sha256": grammar("[0-9a-f]{64}")})(v, p); err != nil {
		return err
	}
	s, ok := Object(v)["text"].(string)
	if !ok || strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > 4000 {
		return failure(p+".text", "must be a text of 1 to 4000 characters")
	}
	return nil
}
func cleanItem(kept bool) validator {
	return func(v any, p string) error {
		m := Object(v)
		item := String(m["item"])
		fields := map[string]validator{"item": choice("worktree", "branch", "session", "lane-directory")}
		if item == "branch" || item == "session" {
			fields["name"] = grammar(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`)
		} else {
			fields["path"] = eventAbsolute
		}
		if kept {
			fields["why"] = choice("not-created", "missing", "not-this-lane", "abandoned", "not-merged", "record")
		}
		return exact(fields)(v, p)
	}
}
func lanePayloads() map[string]map[string]validator {
	run := integer(1, 1000000)
	name := grammar(nameRule)
	token := name
	account := grammar(accountRule)
	digest := grammar("[0-9a-f]{64}")
	launch := grammar("[0-9a-f]{32}")
	branch := grammar(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`)
	commit := grammar("[0-9a-f]{40}|[0-9a-f]{64}")
	sequence := integer(1, 999999999)
	file := exact(map[string]validator{"path": eventAbsolute, "sha256": digest})
	chosen := exact(map[string]validator{"runner": choice("routing", "supervisor", "previous"), "model": choice("routing", "supervisor", "previous"), "effort": null(choice("routing", "supervisor", "previous")), "account": null(choice("supervisor", "default", "previous", "room"))})
	position := exact(map[string]validator{"path": recordPath, "line": integer(1, 1<<62), "offset": integer(0, 1<<62), "item": integer(0, 1000000)})
	start := map[string]validator{"run": run, "how": choice("start", "resume", "reuse"), "launch": launch, "runner": name, "model": model, "effort": null(token), "account": null(account), "chosen_by": chosen, "difficulty": null(choice("mechanical", "standard", "hard", "review")), "project": null(name), "worktree": eventAbsolute, "branch": null(branch), "base": null(commit), "repository": null(eventAbsolute), "budget_minutes": amount(0, 10080, true), "quiet_seconds": integer(1, 604800), "brief": file, "log": eventAbsolute, "session": exact(map[string]validator{"socket": eventAbsolute, "name": grammar("[a-z0-9][a-z0-9_-]{0,63}")}), "touches": eventTouches, "claims": null(eventAbsolute)}
	adopted := map[string]validator{}
	for k, v := range start {
		if k != "run" && k != "how" && k != "launch" {
			adopted[k] = v
		}
	}
	adopted["session_id"] = grammar("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
	adopted["idle_seconds"] = null(integer(1, 604800))
	return map[string]map[string]validator{
		"lane.planned": {}, "lane.state": {"state": choice("queued", "running", "verifying", "accepted", "merged", "abandoned", "waiting")}, "lane.merged": {}, "lane.deployed": {}, "lane.landed": {}, "lane.started": start, "lane.adopted": adopted,
		"lane.resumed": {"run": integer(2, 1000000), "after": null(choice("exit", "timeout", "stopped", "limit", "dropped", "hook-config", "lost")), "message": null(file)},
		"lane.ended":   {"run": run, "reason": choice("exit", "timeout", "stopped", "limit", "dropped", "hook-config"), "exit_code": null(integer(0, 255)), "signal": null(integer(1, 127)), "duration_seconds": amount(0, 1e9, false), "pattern": null(grammar(`(limit|dropped)_patterns\[[0-9]{1,4}\]`)), "classification": null(choice("matched", "unmatched", "timed-out")), "survivors": integer(0, 1000000)},
		"lane.timeout": {"run": run, "budget_minutes": amount(0, 10080, true), "elapsed_seconds": amount(0, 1e9, false)}, "lane.stuck": {"run": run, "quiet_seconds": integer(1, 604800), "output_bytes": integer(0, 1<<62)}, "lane.lost": {"run": run, "survivors": integer(0, 1000000)}, "lane.gone": {"run": run, "launch": launch}, "lane.cleaned": {"removed": boundedArray(cleanItem(false), 0, 64, false), "kept": boundedArray(cleanItem(true), 0, 64, false)},
		"lane.mailed": {"sequence": sequence, "sender": grammar(accountRule), "sha256": digest, "bytes": integer(1, 262144)}, "lane.delivered": {"run": integer(2, 1000000), "sequences": boundedArray(sequence, 1, 64, true)}, "lane.returned": {"run": integer(2, 1000000), "sequences": boundedArray(sequence, 1, 64, true), "reason": choice("exit", "timeout", "stopped", "limit", "dropped", "hook-config", "lost", "gone", "cut")},
		"lane.refusal":              {"run": run, "refusal": grammar("rf-[0-9a-f]{24}"), "guard": grammar(accountRule), "kind": null(choice("hook", "permission", "harness")), "format": choice("claude-code", "text"), "via": choice("tool-result", "hook", "log"), "hook": null(exact(map[string]validator{"event": null(grammar("[A-Za-z][A-Za-z0-9_]{0,63}")), "name": null(grammar("[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}"))})), "tool": null(grammar("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")), "at": null(eventTimestamp), "command": null(excerpt), "message": excerpt, "targets": boundedArray(recordPath, 0, 1024, true), "call": null(exact(map[string]validator{"id": null(grammar("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")), "record": null(position)})), "record": position, "workarounds_checked": boolean},
		"lane.workaround_suspected": {"run": run, "suspicion": grammar("ws-[0-9a-f]{24}"), "refusal": grammar("rf-[0-9a-f]{24}"), "how": boundedArray(choice("reworded", "shell-write"), 1, 2, true), "paths": boundedArray(suspectedPath, 1, 1024, true), "tool": grammar("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}"), "at": null(eventTimestamp), "command": excerpt, "call": exact(map[string]validator{"id": null(grammar("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")), "record": position}), "similarity": null(exact(map[string]validator{"containment": amount(0, 1, false), "coverage": amount(0, 1, false)}))},
		"lane.refusal_reviewed":     {"refusal": grammar("rf-[0-9a-f]{24}"), "path": suspectedPath, "verdict": choice("clean", "workaround"), "suspicions": boundedArray(grammar("ws-[0-9a-f]{24}"), 1, 4096, true), "note": null(eventNote)},
		"lane.ingested":             {"lane": grammar("[a-z0-9][a-z0-9._-]{0,63}"), "rows_added": integer(0, 4096), "rows_existing": integer(0, 4096), "rows": boundedArray(exact(map[string]validator{"id": grammar(`[a-z0-9][a-z0-9-]{0,31}/[a-z0-9][a-z0-9._-]{0,63}/(?:report|events|attachment)/[0-9a-f]{16}`), "sha256": digest}), 0, 4096, false)},
	}
}
func validateLane(event map[string]any) error {
	kind := String(event["kind"])
	fields, ok := lanePayloads()[kind]
	if !ok {
		return fmt.Errorf("kind: an unknown lane event was stored")
	}
	if event["lane"] == nil {
		return fmt.Errorf("lane: is required for lane events")
	}
	p := Object(checkNumbers(event["payload"]))
	if kind == "lane.state" {
		if _, ok := p["not_covered"]; ok {
			fields["not_covered"] = boundedArray(exact(map[string]validator{"run": integer(1, 1000000), "reason": grammar("[a-z][a-z-]{0,39}"), "path": null(text("", 4096))}), 0, 4096, false)
		}
		if _, ok := p["held"]; ok {
			fields["held"] = func(v any, path string) error {
				check := exact(map[string]validator{"resource": grammar("rs-[0-9a-f]{24}"), "state": choice("intent", "acquired")})
				if err := boundedArray(check, 0, 256, false)(v, path); err != nil {
					return err
				}
				a := Array(v)
				for i, x := range a {
					if i > 0 && String(Object(a[i-1])["resource"]) >= String(Object(x)["resource"]) {
						return failure(path, "must be sorted by resource, without repeats")
					}
				}
				return nil
			}
		}
	}
	if kind == "lane.started" {
		if _, ok := p["session_id"]; ok {
			fields["session_id"] = grammar("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
		}
		if _, ok := p["mail"]; ok {
			fields["mail"] = boundedArray(integer(1, 999999999), 0, 64, true)
			fields["idle_seconds"] = null(integer(1, 604800))
		} else if _, ok := p["idle_seconds"]; ok {
			return fmt.Errorf("lane.started payload.idle_seconds: is there only together with payload.mail")
		}
	}
	if kind == "lane.ended" {
		if _, ok := p["prompt"]; ok {
			fields["prompt"] = exact(map[string]validator{"state": choice("written", "cut"), "bytes": integer(0, 1<<62), "length": integer(1, 1<<62)})
		}
	}
	if err := exact(fields)(p, "payload"); err != nil {
		return fmt.Errorf("%s %s", kind, err.Error())
	}
	return laneConsistency(kind, p)
}
func equalValue(a, b any) bool {
	x, err := Canonical(a)
	if err != nil {
		return false
	}
	y, err := Canonical(b)
	return err == nil && string(x) == string(y)
}
func laneConsistency(kind string, p map[string]any) error {
	fail := func(field string) error { return fmt.Errorf("%s payload.%s: fields are inconsistent", kind, field) }
	if kind == "lane.started" || kind == "lane.adopted" {
		chosen := Object(p["chosen_by"])
		if (p["effort"] == nil) != (chosen["effort"] == nil) {
			return fail("chosen_by.effort")
		}
		if (p["account"] == nil) != (chosen["account"] == nil) {
			return fail("chosen_by.account")
		}
		if (p["repository"] == nil) != (p["branch"] == nil) {
			return fail("branch")
		}
		if kind == "lane.started" {
			if (p["how"] == "start") != (Number(p["run"]) == 1) {
				return fail("run")
			}
			if mail, ok := p["mail"]; ok {
				if _, ok := p["session_id"]; !ok {
					return fail("session_id")
				}
				if p["how"] != "resume" && len(Array(mail)) > 0 {
					return fail("mail")
				}
			}
		} else {
			for _, part := range []string{"runner", "model"} {
				if chosen[part] != "supervisor" {
					return fail("chosen_by." + part)
				}
			}
			for _, part := range []string{"effort", "account"} {
				if chosen[part] != nil && chosen[part] != "supervisor" {
					return fail("chosen_by." + part)
				}
			}
			if p["difficulty"] != nil {
				return fail("difficulty")
			}
		}
	}
	if kind == "lane.ended" {
		if p["exit_code"] != nil && p["signal"] != nil {
			return fail("exit_code")
		}
		pattern := p["pattern"] != nil
		limited := p["reason"] == "limit" || p["reason"] == "dropped"
		if pattern != limited || pattern && !strings.HasPrefix(String(p["pattern"]), String(p["reason"])+"_") {
			return fail("pattern")
		}
		if pattern != (p["classification"] == "matched") {
			return fail("classification")
		}
		if (p["reason"] == "timeout" || p["reason"] == "stopped") && p["classification"] != nil {
			return fail("classification")
		}
		if fate, ok := p["prompt"]; ok {
			f := Object(fate)
			if (f["state"] == "written") != (Number(f["bytes"]) == Number(f["length"])) || Number(f["bytes"]) > Number(f["length"]) {
				return fail("prompt")
			}
		}
	}
	if kind == "lane.refusal" {
		if (p["format"] == "text") != (p["via"] == "log") {
			return fail("via")
		}
		if (p["via"] == "hook") != (p["hook"] != nil) {
			return fail("hook")
		}
		if p["format"] == "text" {
			if p["tool"] != nil || p["command"] != nil || p["call"] != nil || len(Array(p["targets"])) > 0 || p["workarounds_checked"] != false {
				return fail("format")
			}
		} else if p["call"] == nil {
			return fail("call")
		}
	}
	if kind == "lane.workaround_suspected" {
		reworded := false
		for _, x := range Array(p["how"]) {
			if x == "reworded" {
				reworded = true
			}
		}
		if (p["similarity"] != nil) != reworded {
			return fail("similarity")
		}
	}
	if kind == "lane.refusal_reviewed" && regexp.MustCompile(`^\([1-9][0-9]{0,8} more\)$`).MatchString(String(p["path"])) {
		return fail("path")
	}
	if kind == "lane.state" {
		for _, key := range []string{"not_covered", "held"} {
			if v, ok := p[key]; ok && (p["state"] != "accepted" && p["state"] != "merged" || len(Array(v)) == 0) {
				return fail(key)
			}
		}
	}
	return nil
}
func integral(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		x, _ := strconv.ParseInt(n.String(), 10, 64)
		return x
	case float64:
		if !math.IsNaN(n) {
			return int64(n)
		}
	}
	return 0
}
