package laneturns

import (
	"math"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

func fmtInt(n int) string { return strconv.Itoa(n) }

var eventTimestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)

func validEventTimestamp(v any) bool {
	if !eventTimestampPattern.MatchString(str(v)) {
		return false
	}
	_, err := moment(v)
	return err == nil
}
func normalizeEnvelope(e object) (object, error) {
	for key := range e {
		if !strings.Contains(" id kind lane actor occurred_at payload protocol_version ", " "+key+" ") {
			return nil, refused("an event contains an unknown or store-owned field")
		}
	}
	r := object{"id": e["id"], "kind": e["kind"], "lane": e["lane"], "actor": e["actor"], "occurred_at": e["occurred_at"], "payload": e["payload"], "protocol_version": e["protocol_version"]}
	if r["id"] == nil {
		id, err := randomID()
		if err != nil {
			return nil, err
		}
		r["id"] = "ev-" + id
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(str(r["id"])) || !regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){1,3}$`).MatchString(str(r["kind"])) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$`).MatchString(str(r["actor"])) || !regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`).MatchString(str(r["protocol_version"])) {
		return nil, refused("an event's id, kind, actor or protocol_version is invalid")
	}
	if r["lane"] != nil && !lanePattern.MatchString(str(r["lane"])) {
		return nil, refused("the event's lane is invalid")
	}
	if r["occurred_at"] != nil {
		if !validEventTimestamp(r["occurred_at"]) {
			return nil, refused("the event's occurred_at must be a valid timestamp")
		}
	}
	if obj(r["payload"]) == nil {
		return nil, refused("the event's payload must be an object")
	}
	data, err := canonical(r["payload"])
	if err != nil {
		return nil, err
	}
	if len(data) > 1048576 {
		return nil, refused("the event's payload must be at most 1 MiB in canonical form")
	}
	return r, nil
}

func isArray(v any) bool {
	if v == nil {
		return false
	}
	kind := reflect.TypeOf(v).Kind()
	return kind == reflect.Slice || kind == reflect.Array
}
func boundedInteger(v any, lo, hi float64) bool {
	n := number(v)
	return isWhole(v) && !math.IsInf(n, 0) && n >= lo && n <= hi
}
func validAbsolute(v any) bool {
	s, ok := v.(string)
	return ok && filepath.IsAbs(s) && len(s) <= 4096 && shown(s) == s
}
func validFile(v any) bool {
	m := obj(v)
	return exactKeys(m, "path sha256") && validAbsolute(m["path"]) && hashPattern.MatchString(str(m["sha256"]))
}
func validSortedSequences(v any, minLength, maxLength int) bool {
	return isArray(v) && len(array(v)) >= minLength && len(array(v)) <= maxLength && checkSequences(v) == nil
}
func validatePayloadFields(kind string, p object) error {
	fail := func(field string) error { return refused("%s: payload.%s is not in the documented form", kind, field) }
	for key, bounds := range map[string][2]float64{"run": {1, 1000000}, "sequence": {1, 999999999}, "bytes": {1, maxMessage}, "survivors": {0, 1000000}, "quiet_seconds": {1, 604800}, "output_bytes": {0, math.Exp2(62)}} {
		if v, ok := p[key]; ok && !boundedInteger(v, bounds[0], bounds[1]) {
			return fail(key)
		}
	}
	for _, key := range []string{"duration_seconds", "elapsed_seconds", "budget_minutes"} {
		if v, ok := p[key]; ok {
			switch v.(type) {
			case int, int64, float64:
			case interface{ Float64() (float64, error) }:
			default:
				return fail(key)
			}
			n := number(v)
			hi := 1e9
			lo := 0.0
			if key == "budget_minutes" {
				hi = 10080
				lo = math.SmallestNonzeroFloat64
			}
			if math.IsNaN(n) || math.IsInf(n, 0) || n < lo || n > hi {
				return fail(key)
			}
		}
	}
	if kind == "lane.started" || kind == "lane.adopted" {
		for _, key := range []string{"worktree", "log"} {
			if !validAbsolute(p[key]) {
				return fail(key)
			}
		}
		for _, key := range []string{"repository", "claims"} {
			if p[key] != nil && !validAbsolute(p[key]) {
				return fail(key)
			}
		}
		if p["project"] != nil && !namePattern.MatchString(str(p["project"])) {
			return fail("project")
		}
		if p["branch"] != nil && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}$`).MatchString(str(p["branch"])) {
			return fail("branch")
		}
		if p["base"] != nil && !regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`).MatchString(str(p["base"])) {
			return fail("base")
		}
		if p["difficulty"] != nil && !contains([]string{"mechanical", "standard", "hard", "review"}, str(p["difficulty"])) {
			return fail("difficulty")
		}
		if !validFile(p["brief"]) {
			return fail("brief")
		}
		session := obj(p["session"])
		if !validAbsolute(session["socket"]) || !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`).MatchString(str(session["name"])) {
			return fail("session")
		}
		if !isArray(p["touches"]) {
			return fail("touches")
		}
		last := ""
		for _, x := range array(p["touches"]) {
			s, ok := x.(string)
			if !ok || s != "billing" && s != "deploy" || s <= last {
				return fail("touches")
			}
			last = s
		}
		chosen := obj(p["chosen_by"])
		for _, key := range []string{"runner", "model", "effort", "account"} {
			v := chosen[key]
			if key == "effort" || key == "account" {
				if (p[key] == nil) != (v == nil) {
					return fail("chosen_by." + key)
				}
				if v == nil {
					continue
				}
			}
			allowed := []string{"routing", "supervisor", "previous"}
			if key == "account" {
				allowed = []string{"supervisor", "default", "previous", "room"}
			}
			if !contains(allowed, str(v)) {
				return fail("chosen_by." + key)
			}
		}
		if idle, ok := p["idle_seconds"]; ok && idle != nil && !boundedInteger(idle, 1, 604800) {
			return fail("idle_seconds")
		}
		if kind == "lane.adopted" {
			for _, key := range []string{"difficulty", "branch", "base", "repository"} {
				if p[key] != nil {
					return fail(key)
				}
			}
			if len(array(p["touches"])) != 0 {
				return fail("touches")
			}
			for _, key := range []string{"runner", "model", "effort", "account"} {
				if chosen[key] != nil && chosen[key] != "supervisor" {
					return fail("chosen_by." + key)
				}
			}
		}
		if kind == "lane.started" {
			if mail, ok := p["mail"]; ok {
				if !validSortedSequences(mail, 0, 64) || p["session_id"] == nil {
					return fail("mail")
				}
				if p["how"] != "resume" && len(array(mail)) > 0 {
					return fail("mail")
				}
			} else if _, ok := p["idle_seconds"]; ok {
				return fail("idle_seconds")
			}
		}
	}
	if kind == "lane.resumed" {
		if p["message"] != nil && !validFile(p["message"]) {
			return fail("message")
		}
	}
	if kind == "lane.ended" {
		if p["exit_code"] != nil && !boundedInteger(p["exit_code"], 0, 255) {
			return fail("exit_code")
		}
		if p["signal"] != nil && !boundedInteger(p["signal"], 1, 127) {
			return fail("signal")
		}
		if p["exit_code"] != nil && p["signal"] != nil {
			return fail("signal")
		}
		if p["classification"] != nil && !contains([]string{"matched", "unmatched", "timed-out"}, str(p["classification"])) {
			return fail("classification")
		}
		if p["pattern"] != nil && !regexp.MustCompile(`^(?:limit|dropped)_patterns\[[0-9]{1,4}\]$`).MatchString(str(p["pattern"])) {
			return fail("pattern")
		}
		if p["reason"] == "limit" || p["reason"] == "dropped" {
			if p["classification"] != "matched" || !strings.HasPrefix(str(p["pattern"]), str(p["reason"])+"_patterns[") {
				return fail("pattern")
			}
		} else if p["pattern"] != nil {
			return fail("pattern")
		}
		if fate := obj(p["prompt"]); p["prompt"] != nil {
			if !boundedInteger(fate["bytes"], 0, math.Exp2(62)) || !boundedInteger(fate["length"], 1, math.Exp2(62)) {
				return fail("prompt")
			}
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		if !validSortedSequences(p["sequences"], 1, 64) {
			return fail("sequences")
		}
		if kind == "lane.returned" && !contains([]string{"exit", "timeout", "stopped", "limit", "dropped", "lost", "gone", "cut"}, str(p["reason"])) {
			return fail("reason")
		}
	}
	if kind == "lane.gone" && !launchPattern.MatchString(str(p["launch"])) {
		return fail("launch")
	}
	return nil
}
func checkStringArray(v any, nonempty bool, pattern *regexp.Regexp) bool {
	if !isArray(v) || nonempty && len(array(v)) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, item := range array(v) {
		s, ok := item.(string)
		if !ok || s == "" || shown(s) != s || seen[s] || pattern != nil && !pattern.MatchString(s) {
			return false
		}
		seen[s] = true
	}
	return true
}
func validateConfigSafety(c *configuration) error {
	label := "configuration " + c.name + ": config.toml"
	m := c.data
	secretNames := regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	if !isWhole(m["schema_version"]) {
		return invalid("%s: schema_version: must be an integer", label)
	}
	for _, key := range []string{"rules", "organisation_rules", "secrets"} {
		if value, ok := m[key]; key == "secrets" && ok && !checkStringArray(value, false, secretNames) {
			return invalid("%s: secrets: must list environment variable names in capitals", label)
		}
		if v, ok := m[key]; ok && !checkStringArray(v, false, nil) {
			return invalid("%s: %s: must be an array of distinct strings", label, key)
		}
	}
	for name, value := range obj(m["runners"]) {
		r := obj(value)
		for _, key := range []string{"command", "resume", "room"} {
			if v, ok := r[key]; ok {
				if !isArray(v) || len(array(v)) == 0 {
					return invalid("%s: runners.%s.%s: must be a nonempty array", label, name, key)
				}
				for _, x := range array(v) {
					if s, ok := x.(string); !ok || s == "" || len(s) > 4096 || shown(s) != s {
						return invalid("%s: runners.%s.%s: must contain strings on one line", label, name, key)
					}
				}
			}
		}
		for _, key := range []string{"accounts", "secrets", "limit_patterns", "dropped_patterns"} {
			if value, ok := r[key]; key == "secrets" && ok && !checkStringArray(value, false, secretNames) {
				return invalid("%s: runners.%s.secrets: must list environment variable names in capitals", label, name)
			}
			if v, ok := r[key]; ok && !checkStringArray(v, key == "limit_patterns" || key == "dropped_patterns", nil) {
				return invalid("%s: runners.%s.%s: must be an array of distinct strings", label, name, key)
			}
		}
		if v, ok := r["quiet_seconds"]; ok && !boundedInteger(v, 1, 604800) {
			return invalid("%s: runners.%s.quiet_seconds: must be an integer from 1 to 604800", label, name)
		}
		if v, ok := r["records"]; ok {
			if !isArray(v) || len(array(v)) == 0 {
				return invalid("%s: runners.%s.records: must be a nonempty array", label, name)
			}
			for _, item := range array(v) {
				entry := obj(item)
				if !exactKeys(entry, "format paths") || !contains([]string{"claude-code", "text"}, str(entry["format"])) || !checkStringArray(entry["paths"], true, nil) {
					return invalid("%s: runners.%s.records: invalid records entry", label, name)
				}
				if entry["format"] == "text" && !equalJSON(entry["paths"], []string{"{log}"}) {
					return invalid("%s: runners.%s.records: text reads only {log}", label, name)
				}
				for _, path := range texts(entry["paths"]) {
					if _, err := expandTemplate(path, nil, "account effort lane log model project session worktree", true); err != nil {
						return invalid("%s: runners.%s.records: invalid path placeholder", label, name)
					}
				}
			}
		}
	}
	if guards, ok := m["guards"]; ok {
		if !isArray(guards) || len(array(guards)) == 0 {
			return invalid("%s: guards: must be a nonempty array", label)
		}
		names := map[string]bool{}
		for _, item := range array(guards) {
			guard := obj(item)
			keys := "name pattern"
			if _, ok := guard["kind"]; ok {
				keys += " kind"
			}
			if !exactKeys(guard, keys) || !senderPattern.MatchString(str(guard["name"])) || names[str(guard["name"])] {
				return invalid("%s: guards: invalid or repeated guard", label)
			}
			names[str(guard["name"])] = true
			if guard["kind"] != nil && !contains([]string{"hook", "permission", "harness"}, str(guard["kind"])) {
				return invalid("%s: guards: invalid guard kind", label)
			}
			rx, err := regexp.Compile(str(guard["pattern"]))
			if err != nil || rx.MatchString("") {
				return invalid("%s: guards: must have a valid nonempty pattern", label)
			}
		}
	}
	for name, p := range c.projects {
		if !isWhole(p["schema_version"]) {
			return invalid("projects/%s.toml: schema_version: must be an integer", name)
		}
		for _, key := range []string{"rules", "workers", "gates", "excluded_accounts", "reserved_paths"} {
			if v, ok := p[key]; ok && !checkStringArray(v, key == "gates", nil) {
				return invalid("projects/%s.toml: %s: must be an array of distinct strings", name, key)
			}
		}
	}
	return nil
}

func validMailRow(m, row object) bool {
	if !boundedInteger(m["last"], 0, 999999999) || !boundedInteger(m["delivered"], 0, 999999999) || number(m["delivered"]) > number(m["last"]) || !validSortedSequences(m["waiting"], 0, 1000) || !validSortedSequences(m["returned"], 0, 1000) || queued(m) > 1000 {
		return false
	}
	if m["idle_seconds"] != nil && !boundedInteger(m["idle_seconds"], 1, 604800) {
		return false
	}
	seen := map[int]bool{}
	for _, key := range []string{"waiting", "returned"} {
		for _, n := range array(m[key]) {
			seq := integer(n)
			if seen[seq] || seq > integer(m["last"]) {
				return false
			}
			seen[seq] = true
		}
	}
	if m["in_flight"] != nil {
		flight := obj(m["in_flight"])
		if !exactKeys(flight, "run sequences") || !boundedInteger(flight["run"], 1, 1000000) || !validSortedSequences(flight["sequences"], 1, 64) || !flag(row["running"]) || integer(flight["run"]) != integer(row["run"]) {
			return false
		}
		for _, n := range array(flight["sequences"]) {
			seq := integer(n)
			if seen[seq] || seq > integer(m["last"]) {
				return false
			}
			seen[seq] = true
		}
	}
	if m["settled"] != nil {
		settled := obj(m["settled"])
		if !exactKeys(settled, "run outcome reason sequences announced") || !boundedInteger(settled["run"], 1, 1000000) || !validSortedSequences(settled["sequences"], 1, 64) || !contains([]string{"delivered", "returned"}, str(settled["outcome"])) {
			return false
		}
		if _, ok := settled["announced"].(bool); !ok {
			return false
		}
		if settled["outcome"] == "delivered" && settled["reason"] != nil || settled["outcome"] == "returned" && !contains([]string{"exit", "timeout", "stopped", "limit", "dropped", "lost", "gone", "cut"}, str(settled["reason"])) {
			return false
		}
	}
	return true
}
