package eventstore

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/lanesandbox"
	"laneboss.io/laneboss/internal/observation"
	"laneboss.io/laneboss/internal/rolepolicy"
	"laneboss.io/laneboss/internal/settings"
)

var kindGrammar = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){1,3}$`)
var idGrammar = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Actor labels may identify a human source while retaining the bounded ASCII
// identifier grammar and rejecting control characters.
var actorGrammar = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/+() -]{0,127}$`)
var protocolGrammar = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)
var timestampGrammar = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)

func checkTimestamp(v any, field string) error {
	s, ok := v.(string)
	if !ok || !timestampGrammar.MatchString(s) {
		return Refuse("%s: must be a timestamp such as 2026-10-08T09:00:00Z", field)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, s); err != nil || parsed.Year() < 1 {
		return Refuse("%s: is not a valid date and time", field)
	}
	if s[len(s)-1] != 'Z' {
		h, _ := strconv.Atoi(s[len(s)-5 : len(s)-3])
		m, _ := strconv.Atoi(s[len(s)-2:])
		if h > 23 || m > 59 {
			return Refuse("%s: is not a valid date and time", field)
		}
	}
	return nil
}
func envelopeGrammar(v any, re *regexp.Regexp, field string, optional bool) error {
	if v == nil && optional {
		return nil
	}
	if v == nil {
		return Refuse("%s: is required", field)
	}
	if s, ok := v.(string); !ok || !re.MatchString(s) {
		return Refuse("%s: must match %s", field, strings.TrimSuffix(strings.TrimPrefix(re.String(), "^"), "$"))
	}
	return nil
}
func Validate(value any) (Object, error) {
	m := object(value)
	if m == nil {
		return nil, Refuse("an event must be a JSON object")
	}
	if where, rule := credentialValue(m); rule != "" {
		return nil, Refuse("%s: looks like a credential (%s); nothing was stored", where, rule)
	}
	for _, field := range []string{"seq", "recorded_at", "sha256"} {
		if _, ok := m[field]; ok {
			return nil, Refuse("%s: is set by the store; a caller cannot supply it", field)
		}
	}
	for field := range m {
		if !contains(envelopeFields, field) {
			label := "a field"
			if regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(field) {
				label = field
			}
			return nil, Refuse("%s: unknown field; an event has %s", label, strings.Join(envelopeFields, ", "))
		}
	}
	for _, check := range []struct {
		field    string
		re       *regexp.Regexp
		optional bool
	}{{"id", idGrammar, true}, {"kind", kindGrammar, false}, {"lane", laneGrammar, true}, {"actor", actorGrammar, false}, {"protocol_version", protocolGrammar, false}} {
		if err := envelopeGrammar(m[check.field], check.re, check.field, check.optional); err != nil {
			return nil, err
		}
	}
	e := envelope(m)
	if e["id"] == nil {
		id, err := randomID()
		if err != nil {
			return nil, err
		}
		e["id"] = "ev-" + id
	}
	if e["occurred_at"] != nil {
		if err := checkTimestamp(e["occurred_at"], "occurred_at"); err != nil {
			return nil, err
		}
	}
	if e["payload"] == nil {
		return nil, Refuse("payload: is required (a JSON object)")
	}
	if object(e["payload"]) == nil {
		return nil, Refuse("payload: must be a JSON object")
	}
	if len(Canonical(e["payload"])) > 1024*1024 {
		return nil, Refuse("payload: must be at most 1 MiB in canonical form")
	}
	kind := text(e["kind"])
	if kind == "store.record" {
		if err := ValidateRecord(object(e["payload"])); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(kind, "lane.") {
		if err := checkLane(e); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(kind, "resource.") {
		if err := checkResource(e); err != nil {
			return nil, err
		}
	}
	return e, nil
}
func contains(options []string, value string) bool {
	for _, o := range options {
		if o == value {
			return true
		}
	}
	return false
}

type validator func(any, string) error

func nullable(check validator) validator {
	return func(v any, w string) error {
		if v == nil {
			return nil
		}
		return check(v, w)
	}
}
func grammar(pattern string) validator {
	re := regexp.MustCompile("^(?:" + pattern + ")$")
	return func(v any, w string) error {
		if s, ok := v.(string); !ok || !re.MatchString(s) {
			return Refuse("%s: must match %s", w, pattern)
		}
		return nil
	}
}
func whole(min, max int64) validator {
	return func(v any, w string) error {
		n, ok := integerValue(v)
		if !ok || n < min || n > max {
			return Refuse("%s: must be a whole number from %d to %d", w, min, max)
		}
		return nil
	}
}
func numeric(min, max float64, above bool) validator {
	return func(v any, w string) error {
		n, ok := integerValue(v)
		f := float64(n)
		if fv, yes := v.(floatValue); yes {
			f, ok = float64(fv), true
		}
		if fv, yes := v.(float64); yes {
			f, ok = fv, true
		}
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < min || f > max || above && f <= min {
			word := "from"
			if above {
				word = "above"
			}
			return Refuse("%s: must be a number %s %g and at most %g", w, word, min, max)
		}
		return nil
	}
}
func oneOf(options ...string) validator {
	return func(v any, w string) error {
		s, ok := v.(string)
		if !ok || !contains(options, s) {
			return Refuse("%s: must be one of %s", w, strings.Join(options, ", "))
		}
		return nil
	}
}
func absolute(v any, w string) error {
	if !validAbsolute(v) {
		return Refuse("%s: must be an absolute path on one line", w)
	}
	return nil
}
func boolean(v any, w string) error {
	if _, ok := v.(bool); !ok {
		return Refuse("%s: must be true or false", w)
	}
	return nil
}
func modelName(v any, w string) error {
	if err := grammar(`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`)(v, w); err != nil {
		return err
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(text(v)) {
		return Refuse("%s: must be a full model name that includes its version", w)
	}
	return nil
}
func fields(checks map[string]validator) validator {
	return func(v any, w string) error {
		m := object(v)
		keys := make([]string, 0, len(checks))
		for k := range checks {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if m == nil || len(m) != len(checks) {
			return Refuse("%s: must be an object with exactly: %s", w, strings.Join(keys, ", "))
		}
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				return Refuse("%s: must be an object with exactly: %s", w, strings.Join(keys, ", "))
			}
			if err := checks[k](m[k], w+"."+k); err != nil {
				return err
			}
		}
		return nil
	}
}
func array(item validator, max int) validator {
	return func(v any, w string) error {
		a, ok := v.([]any)
		if !ok || len(a) > max {
			return Refuse("%s: must be a list of at most %d items", w, max)
		}
		for i, x := range a {
			if err := item(x, fmt.Sprintf("%s[%d]", w, i)); err != nil {
				return err
			}
		}
		return nil
	}
}
func sortedList(item validator, min, max int) validator {
	return func(v any, w string) error {
		a, ok := v.([]any)
		if !ok || len(a) < min || len(a) > max {
			return Refuse("%s: must be a list of %d to %d items", w, min, max)
		}
		for i, x := range a {
			if err := item(x, fmt.Sprintf("%s[%d]", w, i)); err != nil {
				return err
			}
			if i > 0 {
				if sx, ok := x.(string); ok {
					if text(a[i-1]) >= sx {
						return Refuse("%s: must be sorted, without repeats", w)
					}
				} else if num(a[i-1]) >= num(x) {
					return Refuse("%s: must be sorted, without repeats", w)
				}
			}
		}
		return nil
	}
}
func touches(v any, w string) error {
	if err := sortedList(oneOf("billing", "deploy"), 0, 2)(v, w); err != nil {
		return Refuse("%s: must be a sorted list of billing and deploy", w)
	}
	return nil
}
func lineText(v any, w string) error {
	s, ok := v.(string)
	if !ok || s == "" || utf8.RuneCountInString(s) > 4096 || control(s) {
		return Refuse("%s: must be a text on one line", w)
	}
	return nil
}
func recordPath(v any, w string) error {
	s := text(v)
	if regexp.MustCompile(`^\((?:withheld [0-9a-f]{64}|[1-9][0-9]{0,8} more)\)$`).MatchString(s) {
		return nil
	}
	return absolute(v, w)
}
func suspectedPath(v any, w string) error {
	if v == "(command)" {
		return nil
	}
	return recordPath(v, w)
}
func excerpt(v any, w string) error {
	if err := fields(map[string]validator{"text": nullable(func(any, string) error { return nil }), "withheld": boolean, "length": whole(0, 1<<62), "sha256": grammar(`[0-9a-f]{64}`)})(v, w); err != nil {
		return err
	}
	m := object(v)
	if m["withheld"] == true {
		if m["text"] != nil {
			return Refuse("%s.text: is null when the excerpt is withheld", w)
		}
	} else {
		s, ok := m["text"].(string)
		if !ok || utf8.RuneCountInString(s) > 400 || int64(utf8.RuneCountInString(s)) > num(m["length"]) {
			return Refuse("%s.text: must be the start of the text, at most 400 characters", w)
		}
	}
	return nil
}
func note(v any, w string) error {
	if err := fields(map[string]validator{"text": func(any, string) error { return nil }, "sha256": grammar(`[0-9a-f]{64}`)})(v, w); err != nil {
		return err
	}
	s, ok := object(v)["text"].(string)
	if !ok || strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > 4000 {
		return Refuse("%s.text: must be a text of 1 to 4000 characters", w)
	}
	return nil
}
func heldList(v any, w string) error {
	check := fields(map[string]validator{"resource": grammar(`rs-[0-9a-f]{24}`), "state": oneOf("intent", "acquired")})
	if err := array(check, 256)(v, w); err != nil {
		return err
	}
	a := list(v)
	for i := 1; i < len(a); i++ {
		if text(object(a[i-1])["resource"]) >= text(object(a[i])["resource"]) {
			return Refuse("%s: must be sorted by resource, without repeats", w)
		}
	}
	return nil
}
func cleanItem(kept bool) validator {
	return func(v any, w string) error {
		m := object(v)
		if m == nil || m["item"] == nil {
			return Refuse("%s: must be an object with an item", w)
		}
		check := oneOf("worktree", "branch", "session", "lane-directory")
		if err := check(m["item"], w+".item"); err != nil {
			return err
		}
		c := map[string]validator{"item": check}
		if m["item"] == "branch" || m["item"] == "session" {
			c["name"] = grammar(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`)
		} else {
			c["path"] = absolute
		}
		if kept {
			c["why"] = oneOf("not-created", "missing", "not-this-lane", "abandoned", "not-merged", "record")
		}
		return fields(c)(v, w)
	}
}

var runCheck = whole(1, 1000000)
var fileCheck = fields(map[string]validator{"path": absolute, "sha256": grammar(`[0-9a-f]{64}`)})
var sequenceCheck = whole(1, 999999999)
var carriedCheck = sortedList(sequenceCheck, 0, 64)
var positionCheck = fields(map[string]validator{"path": recordPath, "line": whole(1, 1<<62), "offset": whole(0, 1<<62), "item": whole(0, 1000000)})
var reasonCheck = oneOf("exit", "timeout", "stopped", "limit", "dropped", "hook-config")
var returnCheck = oneOf("exit", "timeout", "stopped", "limit", "dropped", "hook-config", "lost", "gone", "cut")
var chosenCheck = fields(map[string]validator{"runner": oneOf("routing", "supervisor", "previous", "settings"), "model": oneOf("routing", "supervisor", "previous", "settings"), "effort": nullable(oneOf("routing", "supervisor", "previous", "settings")), "account": nullable(oneOf("supervisor", "default", "previous", "room", "settings"))})

func startFields() map[string]validator {
	return map[string]validator{
		"runner": grammar(`[a-z0-9][a-z0-9-]{0,31}`), "model": modelName, "effort": nullable(grammar(`[a-z0-9][a-z0-9-]{0,31}`)), "account": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`)), "chosen_by": chosenCheck, "difficulty": nullable(oneOf("mechanical", "standard", "hard", "review")), "project": nullable(grammar(`[a-z0-9][a-z0-9-]{0,31}`)), "worktree": absolute, "branch": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`)), "base": nullable(grammar(`[0-9a-f]{40}|[0-9a-f]{64}`)), "repository": nullable(absolute), "budget_minutes": numeric(0, 10080, true), "quiet_seconds": whole(1, 604800), "brief": fileCheck, "log": absolute, "session": fields(map[string]validator{"socket": absolute, "name": grammar(`[a-z0-9][a-z0-9_-]{0,63}`)}), "touches": touches, "claims": nullable(absolute),
	}
}
func laneFields(kind string, p Object) map[string]validator {
	switch kind {
	case "lane.planned", "lane.merged", "lane.deployed", "lane.landed":
		return map[string]validator{}
	case "lane.state":
		c := map[string]validator{"state": oneOf("queued", "running", "verifying", "accepted", "merged", "abandoned", "waiting")}
		if _, ok := p["not_covered"]; ok {
			c["not_covered"] = array(fields(map[string]validator{"run": runCheck, "reason": grammar(`[a-z][a-z-]{0,39}`), "path": nullable(lineText)}), 4096)
		}
		if _, ok := p["held"]; ok {
			c["held"] = heldList
		}
		return c
	case "lane.started", "lane.adopted":
		c := startFields()
		if _, exists := p["settings"]; exists {
			c["settings"] = settings.EventField(p)
		}
		if _, exists := p["runner_sandbox"]; exists {
			c["runner_sandbox"] = oneOf(lanesandbox.RunnerReplaced)
		}
		if _, exists := p["role_context"]; exists {
			c["role"] = rolepolicy.EventField(p, "role")
			c["role_context"] = rolepolicy.EventField(p, "role_context")
		}
		for _, key := range []string{"level", "level_source", "starter"} {
			if _, ok := p[key]; ok {
				c[key] = func(value any, path string) error {
					if err := records.Field(key, value); err != nil {
						return Refuse("%s: %s", path, err)
					}
					return nil
				}
			}
		}
		if kind == "lane.started" {
			c["run"] = runCheck
			c["how"] = oneOf("start", "resume", "reuse")
			c["launch"] = grammar(`[0-9a-f]{32}`)
			if _, ok := p["session_id"]; ok {
				c["session_id"] = grammar(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
			}
			if _, ok := p["mail"]; ok {
				c["mail"] = carriedCheck
				c["idle_seconds"] = nullable(whole(1, 604800))
			}
		} else {
			c["session_id"] = grammar(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
			c["idle_seconds"] = nullable(whole(1, 604800))
		}
		return c
	case "lane.resumed":
		return map[string]validator{"run": whole(2, 1000000), "after": nullable(oneOf("exit", "timeout", "stopped", "limit", "dropped", "hook-config", "lost")), "message": nullable(fileCheck)}
	case "lane.ended":
		c := map[string]validator{"run": runCheck, "reason": reasonCheck, "exit_code": nullable(whole(0, 255)), "signal": nullable(whole(1, 127)), "duration_seconds": numeric(0, 1e9, false), "pattern": nullable(grammar(`(limit|dropped)_patterns\[[0-9]{1,4}\]`)), "classification": nullable(oneOf("matched", "unmatched", "timed-out")), "survivors": whole(0, 1000000)}
		if _, ok := p["prompt"]; ok {
			c["prompt"] = fields(map[string]validator{"state": oneOf("written", "cut"), "bytes": whole(0, 1<<62), "length": whole(1, 1<<62)})
		}
		return c
	case "lane.timeout":
		return map[string]validator{"run": runCheck, "budget_minutes": numeric(0, 10080, true), "elapsed_seconds": numeric(0, 1e9, false)}
	case "lane.stuck":
		return map[string]validator{"run": runCheck, "quiet_seconds": whole(1, 604800), "output_bytes": whole(0, 1<<62)}
	case "lane.lost":
		return map[string]validator{"run": runCheck, "survivors": whole(0, 1000000)}
	case "lane.gone":
		return map[string]validator{"run": runCheck, "launch": grammar(`[0-9a-f]{32}`)}
	case "lane.cleaned":
		return map[string]validator{"removed": array(cleanItem(false), 64), "kept": array(cleanItem(true), 64)}
	case "lane.mailed":
		c := map[string]validator{"sequence": sequenceCheck, "sender": func(value any, path string) error {
			id, ok := value.(string)
			if !ok || !records.ValidSender(id) {
				return Refuse("%s: must be a sender label or principal node id", path)
			}
			return nil
		}, "sha256": grammar(`[0-9a-f]{64}`), "bytes": whole(1, 262144)}
		if _, ok := p["legacy_relationship"]; ok {
			c["legacy_relationship"] = func(value any, path string) error {
				if value != true {
					return Refuse("%s: must be true when present", path)
				}
				return nil
			}
		}
		return c
	case "lane.delivered":
		return map[string]validator{"run": whole(2, 1000000), "sequences": sortedList(sequenceCheck, 1, 64)}
	case "lane.returned":
		return map[string]validator{"run": whole(2, 1000000), "sequences": sortedList(sequenceCheck, 1, 64), "reason": returnCheck}
	case "lane.refusal":
		return map[string]validator{
			"run": runCheck, "refusal": grammar(`rf-[0-9a-f]{24}`), "guard": grammar(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`), "kind": nullable(oneOf("hook", "permission", "harness")), "format": oneOf("claude-code", "text"), "via": oneOf("tool-result", "hook", "log"), "hook": nullable(fields(map[string]validator{"event": nullable(grammar(`[A-Za-z][A-Za-z0-9_]{0,63}`)), "name": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}`))})), "tool": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`)), "at": nullable(checkTimestamp), "command": nullable(excerpt), "message": excerpt, "targets": sortedList(recordPath, 0, 1024), "call": nullable(fields(map[string]validator{"id": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`)), "record": nullable(positionCheck)})), "record": positionCheck, "workarounds_checked": boolean,
		}
	case "lane.workaround_suspected":
		return map[string]validator{
			"run": runCheck, "suspicion": grammar(`ws-[0-9a-f]{24}`), "refusal": nullable(grammar(`rf-[0-9a-f]{24}`)), "how": sortedList(oneOf("reworded", "shell-write", "shell-substitution-in-text"), 1, 2), "paths": sortedList(suspectedPath, 1, 1024), "tool": grammar(`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`), "at": nullable(checkTimestamp), "command": excerpt, "call": fields(map[string]validator{"id": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`)), "record": positionCheck}), "similarity": nullable(fields(map[string]validator{"containment": numeric(0, 1, false), "coverage": numeric(0, 1, false)})),
		}
	case "lane.refusal_reviewed":
		return map[string]validator{"refusal": grammar(`rf-[0-9a-f]{24}`), "path": suspectedPath, "verdict": oneOf("clean", "workaround"), "suspicions": sortedList(grammar(`ws-[0-9a-f]{24}`), 1, 4096), "note": nullable(note)}
	case "lane.ingested":
		return map[string]validator{"lane": grammar(`[a-z0-9][a-z0-9._-]{0,63}`), "rows_added": whole(0, 4096), "rows_existing": whole(0, 4096), "rows": array(fields(map[string]validator{"id": grammar(`[a-z0-9][a-z0-9-]{0,31}/[a-z0-9][a-z0-9._-]{0,63}/(?:report|events|attachment)/[0-9a-f]{16}`), "sha256": grammar(`[0-9a-f]{64}`)}), 4096)}
	}
	return nil
}
func checkLane(e Object) error {
	kind := text(e["kind"])
	p := object(e["payload"])
	checks := laneFields(kind, p)
	if checks == nil {
		return Refuse("kind: unknown lane event kind")
	}
	if e["lane"] == nil {
		return Refuse("lane: is required for lane events")
	}
	if kind == "lane.started" {
		if _, ok := p["idle_seconds"]; ok {
			if _, ok = p["mail"]; !ok {
				return Refuse("lane.started payload.idle_seconds: is there only together with payload.mail")
			}
		}
	}
	if err := fields(checks)(p, "payload"); err != nil {
		return Refuse("%s %s", kind, err.Error())
	}
	if err := consistent(kind, p); err != nil {
		return Refuse("%s %s", kind, err.Error())
	}
	return nil
}
func consistent(kind string, p Object) error {
	if kind == "lane.started" || kind == "lane.adopted" {
		if err := records.Validate(p); err != nil {
			return Refuse("payload report line: %s", err)
		}
		chosen := object(p["chosen_by"])
		for _, key := range []string{"effort", "account"} {
			if (p[key] == nil) != (chosen[key] == nil) {
				return Refuse("payload.chosen_by.%s: is null exactly when payload.%s is null", key, key)
			}
		}
		if (p["repository"] == nil) != (p["branch"] == nil) {
			return Refuse("payload.branch: is null exactly when payload.repository is null")
		}
		if kind == "lane.started" {
			if (p["how"] == "start") != (num(p["run"]) == 1) {
				return Refuse("payload.run: is 1 exactly when payload.how is start")
			}
			if _, ok := p["mail"]; ok {
				if p["session_id"] == nil {
					return Refuse("payload.session_id: is required when payload.mail is there")
				}
				if p["how"] != "resume" && len(list(p["mail"])) > 0 {
					return Refuse("payload.mail: must be empty when payload.how is start or reuse")
				}
			}
		} else {
			for _, k := range []string{"runner", "model"} {
				if chosen[k] != "supervisor" {
					return Refuse("payload.chosen_by.%s: is supervisor", k)
				}
			}
			for _, k := range []string{"effort", "account"} {
				if chosen[k] != nil && chosen[k] != "supervisor" {
					return Refuse("payload.chosen_by.%s: is null or supervisor", k)
				}
			}
			if p["difficulty"] != nil {
				return Refuse("payload.difficulty: is null for an adoption")
			}
		}
	}
	if kind == "lane.ended" {
		if p["exit_code"] != nil && p["signal"] != nil {
			return Refuse("payload.exit_code: at most one of exit_code and signal is set")
		}
		pattern := p["pattern"] != nil
		limited := p["reason"] == "limit" || p["reason"] == "dropped"
		if pattern != limited || pattern && !strings.HasPrefix(text(p["pattern"]), text(p["reason"])+"_") {
			return Refuse("payload.pattern: names the matching pattern exactly when the reason is limit or dropped")
		}
		if pattern != (p["classification"] == "matched") {
			return Refuse("payload.classification: is matched exactly when a pattern is named")
		}
		if (p["reason"] == "timeout" || p["reason"] == "stopped") && p["classification"] != nil {
			return Refuse("payload.classification: is null for a run that was stopped or timed out")
		}
		if fate := object(p["prompt"]); fate != nil {
			if (fate["state"] == "written") != (num(fate["bytes"]) == num(fate["length"])) || num(fate["bytes"]) > num(fate["length"]) {
				return Refuse("payload.prompt: is written exactly when every byte was written")
			}
		}
	}
	if kind == "lane.refusal" {
		if (p["format"] == "text") != (p["via"] == "log") {
			return Refuse("payload.via: is log exactly for a text record")
		}
		if (p["via"] == "hook") != (p["hook"] != nil) {
			return Refuse("payload.hook: is given exactly when the refusal came through a hook")
		}
		if p["format"] == "text" {
			if p["tool"] != nil || p["command"] != nil || p["call"] != nil || len(list(p["targets"])) != 0 || p["workarounds_checked"] != false {
				return Refuse("payload.format: a text record names no tool, command, call or target, so no workaround is checked")
			}
		} else if p["call"] == nil {
			return Refuse("payload.call: is required for a refusal in a claude-code record")
		}
	}
	if kind == "lane.workaround_suspected" {
		reworded := false
		for _, how := range list(p["how"]) {
			reworded = reworded || how == "reworded"
		}
		if err := observation.Check(p); err != nil {
			return Refuse("%s", err.Error())
		}
		if (p["similarity"] != nil) != reworded {
			return Refuse("payload.similarity: is given exactly when the way includes reworded")
		}
	}
	if kind == "lane.refusal_reviewed" && regexp.MustCompile(`^\([1-9][0-9]{0,8} more\)$`).MatchString(text(p["path"])) {
		return Refuse("payload.path: a verdict names one path")
	}
	if kind == "lane.state" {
		for _, key := range []string{"held", "not_covered"} {
			if v, ok := p[key]; ok {
				if p["state"] != "accepted" && p["state"] != "merged" || len(list(v)) == 0 {
					return Refuse("payload.%s: is given only when a lane is accepted or merged and the list is not empty", key)
				}
			}
		}
	}
	return nil
}
func checkLoop(e Object) error {
	kind := text(e["kind"])
	var checks map[string]validator
	switch kind {
	case "loop.started":
		checks = map[string]validator{"loop": grammar(`[0-9a-f]{32}`), "pid": whole(1, 1<<62), "start": grammar(`[0-9A-Za-z :.-]{1,64}`), "detached": boolean, "unrecorded_end": nullable(grammar(`[0-9a-f]{32}`))}
	case "loop.stopped":
		checks = map[string]validator{"loop": grammar(`[0-9a-f]{32}`), "reason": oneOf("stop", "error"), "turns": whole(0, 1<<62), "skips": whole(0, 1<<62)}
	case "loop.turn":
		checks = map[string]validator{"loop": grammar(`[0-9a-f]{32}`), "kind": oneOf("mail", "idle"), "sequences": carriedCheck, "run": whole(2, 1000000)}
	case "loop.skipped":
		checks = map[string]validator{"loop": grammar(`[0-9a-f]{32}`), "reason": oneOf("backoff", "refused", "no-room"), "until": nullable(checkTimestamp), "after": nullable(fields(map[string]validator{"run": runCheck, "reason": returnCheck})), "detail": nullable(func(v any, w string) error {
			if err := lineText(v, w); err != nil {
				return err
			}
			if utf8.RuneCountInString(text(v)) > 200 {
				return Refuse("%s: must be one line of 1 to 200 characters", w)
			}
			return nil
		})}
	default:
		return Refuse("kind: loop events are loop.started, loop.stopped, loop.turn, loop.skipped")
	}
	about := kind == "loop.turn" || kind == "loop.skipped"
	if about != (e["lane"] != nil) {
		return Refuse("lane: is required exactly for loop.turn and loop.skipped")
	}
	p := object(e["payload"])
	if err := fields(checks)(p, "payload"); err != nil {
		return Refuse("%s %s", kind, err.Error())
	}
	if kind == "loop.turn" && (p["kind"] == "idle") != (len(list(p["sequences"])) == 0) {
		return Refuse("loop.turn payload.sequences: is empty exactly when payload.kind is idle")
	}
	if kind == "loop.skipped" && (p["reason"] == "backoff") != (p["after"] != nil) {
		return Refuse("loop.skipped payload.after: is given exactly when payload.reason is backoff")
	}
	return nil
}
