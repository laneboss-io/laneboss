package lane

import (
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/observation"
)

func validTimestamp(v any) bool {
	s, ok := v.(string)
	if !ok || !match(`[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})`, s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}
func nullableGrammar(v any, p string) bool { return v == nil || match(p, str(v)) }
func recordPath(v any, suspected bool) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	return absValue(v) || match(`\(withheld [0-9a-f]{64}\)|\([1-9][0-9]{0,8} more\)`, s) || (suspected && s == "(command)")
}
func validPosition(v any) bool {
	p := obj(v)
	return exactKeys(p, strings.Fields("path line offset item")) && recordPath(p["path"], false) && whole(p["line"], 1, 1<<62) && whole(p["offset"], 0, 1<<62) && whole(p["item"], 0, 1e6)
}
func validExcerpt(v any) bool {
	m := obj(v)
	if !exactKeys(m, strings.Fields("text withheld length sha256")) || !whole(m["length"], 0, 1<<62) || !match(`[0-9a-f]{64}`, str(m["sha256"])) {
		return false
	}
	if _, ok := m["withheld"].(bool); !ok {
		return false
	}
	if flag(m["withheld"]) {
		return m["text"] == nil
	}
	text, ok := m["text"].(string)
	return ok && utf8.ValidString(text) && len([]rune(text)) <= 400 && float64(len([]rune(text))) <= number(m["length"])
}
func sortedStrings(v any, min, max int, item func(string) bool) bool {
	a := list(v)
	if a == nil || len(a) < min || len(a) > max {
		return false
	}
	last := ""
	for i, value := range a {
		s, ok := value.(string)
		if !ok || !item(s) || (i > 0 && s <= last) {
			return false
		}
		last = s
	}
	return true
}
func sequences(v any, min, max int) bool {
	a := list(v)
	if a == nil || len(a) < min || len(a) > max {
		return false
	}
	last := 0
	for _, n := range a {
		if !whole(n, 1, 999999999) || integer(n) <= last {
			return false
		}
		last = integer(n)
	}
	return true
}
func validCallPosition(v any, required bool) bool {
	m := obj(v)
	if !exactKeys(m, []string{"id", "record"}) || !nullableGrammar(m["id"], `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`) {
		return false
	}
	return (!required && m["record"] == nil) || validPosition(m["record"])
}
func validateExtra(kind string, p object) error {
	fail := func(field string) error { return refuse("%s payload.%s: invalid field", kind, field) }
	if kind == "lane.started" || kind == "lane.adopted" {
		if err := records.Validate(p); err != nil {
			return refuse("%s payload report line: %s", kind, err)
		}
		if !match(`[a-z0-9][a-z0-9-]{0,31}`, str(p["runner"])) {
			return fail("runner")
		}
		if p["difficulty"] != nil && !contains(strings.Fields("mechanical standard hard review"), str(p["difficulty"])) {
			return fail("difficulty")
		}
		chosen := obj(p["chosen_by"])
		for _, k := range []string{"runner", "model"} {
			if !contains(strings.Fields("routing supervisor previous settings"), str(chosen[k])) {
				return fail("chosen_by." + k)
			}
		}
		if chosen["effort"] != nil && !contains(strings.Fields("routing supervisor previous settings"), str(chosen["effort"])) {
			return fail("chosen_by.effort")
		}
		if chosen["account"] != nil && !contains(strings.Fields("supervisor default previous room settings"), str(chosen["account"])) {
			return fail("chosen_by.account")
		}
		if _, ok := p["mail"]; ok && !sequences(p["mail"], 0, 64) {
			return fail("mail")
		}
		if kind == "lane.adopted" && (p["difficulty"] != nil || str(chosen["runner"]) != "supervisor" || str(chosen["model"]) != "supervisor" || (chosen["effort"] != nil && chosen["effort"] != "supervisor") || (chosen["account"] != nil && chosen["account"] != "supervisor") || (p["effort"] == nil) != (chosen["effort"] == nil) || (p["account"] == nil) != (chosen["account"] == nil) || (p["repository"] == nil) != (p["branch"] == nil)) {
			return fail("chosen_by")
		}
	}
	if kind == "lane.resumed" && !whole(p["run"], 2, 1000000) {
		return fail("run")
	}
	if kind == "lane.ended" {
		if !nullableGrammar(p["pattern"], `(?:limit|dropped)_patterns\[[0-9]{1,4}\]`) {
			return fail("pattern")
		}
		if p["classification"] != nil && !contains(strings.Fields("matched unmatched timed-out"), str(p["classification"])) {
			return fail("classification")
		}
		if v, ok := p["prompt"]; ok {
			m := obj(v)
			if !exactKeys(m, strings.Fields("state bytes length")) || !whole(m["bytes"], 0, 1<<62) || !whole(m["length"], 1, 1<<62) {
				return fail("prompt")
			}
		}
	}
	if kind == "lane.state" {
		if v, ok := p["not_covered"]; ok {
			a := list(v)
			if a == nil || len(a) == 0 || len(a) > 4096 || !contains([]string{"accepted", "merged"}, str(p["state"])) {
				return fail("not_covered")
			}
			for _, v := range a {
				m := obj(v)
				if !exactKeys(m, strings.Fields("run reason path")) || !whole(m["run"], 1, 1000000) || !match(`[a-z][a-z-]{0,39}`, str(m["reason"])) {
					return fail("not_covered")
				}
				if m["path"] != nil {
					s, ok := m["path"].(string)
					if !ok || s == "" || len([]rune(s)) > 4096 || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
						return fail("not_covered.path")
					}
				}
			}
		}
		if v, ok := p["held"]; ok {
			a := list(v)
			if a == nil || len(a) == 0 || len(a) > 256 || !contains([]string{"accepted", "merged"}, str(p["state"])) {
				return fail("held")
			}
			last := ""
			for _, v := range a {
				m := obj(v)
				id := str(m["resource"])
				if !exactKeys(m, strings.Fields("resource state")) || !match(`rs-[0-9a-f]{24}`, id) || id <= last || !contains([]string{"intent", "acquired"}, str(m["state"])) {
					return fail("held")
				}
				last = id
			}
		}
	}
	if kind == "lane.cleaned" {
		for _, field := range []string{"removed", "kept"} {
			a := list(p[field])
			if a == nil || len(a) > 64 {
				return fail(field)
			}
			for _, v := range a {
				m := obj(v)
				item := str(m["item"])
				if !contains(strings.Fields("worktree branch session lane-directory"), item) {
					return fail(field)
				}
				detail := "path"
				if item == "branch" || item == "session" {
					detail = "name"
				}
				keys := []string{"item", detail}
				if field == "kept" {
					keys = append(keys, "why")
				}
				if !exactKeys(m, keys) || (detail == "path" && !absValue(m[detail])) || (detail == "name" && !match(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`, str(m[detail]))) {
					return fail(field)
				}
				if field == "kept" && !contains(strings.Fields("not-created missing not-this-lane abandoned not-merged record"), str(m["why"])) {
					return fail(field + ".why")
				}
			}
		}
	}
	if kind == "lane.mailed" {
		if v, ok := p["legacy_relationship"]; ok && v != true {
			return fail("legacy_relationship")
		}
		if !whole(p["sequence"], 1, 999999999) || !records.ValidSender(str(p["sender"])) || !match(`[0-9a-f]{64}`, str(p["sha256"])) || !whole(p["bytes"], 1, 262144) {
			return fail("sequence")
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		if !whole(p["run"], 2, 1000000) || !sequences(p["sequences"], 1, 64) {
			return fail("sequences")
		}
		if kind == "lane.returned" && !contains(strings.Fields("exit timeout stopped limit dropped hook-config lost gone cut"), str(p["reason"])) {
			return fail("reason")
		}
	}
	if kind == "lane.refusal" {
		if !match(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, str(p["guard"])) || (p["kind"] != nil && !contains(strings.Fields("hook permission harness"), str(p["kind"]))) || !contains([]string{"claude-code", "text"}, str(p["format"])) || !contains(strings.Fields("tool-result hook log"), str(p["via"])) {
			return fail("guard")
		}
		if !nullableGrammar(p["tool"], `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`) || (p["at"] != nil && !validTimestamp(p["at"])) || !validPosition(p["record"]) || !validExcerpt(p["message"]) || (p["command"] != nil && !validExcerpt(p["command"])) {
			return fail("record")
		}
		if _, ok := p["workarounds_checked"].(bool); !ok {
			return fail("workarounds_checked")
		}
		if !sortedStrings(p["targets"], 0, 1024, func(s string) bool { return recordPath(s, false) }) {
			return fail("targets")
		}
		if p["call"] != nil && !validCallPosition(p["call"], false) {
			return fail("call")
		}
		if (str(p["format"]) == "text") != (str(p["via"]) == "log") || (str(p["via"]) == "hook") != (p["hook"] != nil) {
			return fail("via")
		}
		if p["hook"] != nil {
			m := obj(p["hook"])
			if !exactKeys(m, []string{"event", "name"}) || !nullableGrammar(m["event"], `[A-Za-z][A-Za-z0-9_]{0,63}`) || !nullableGrammar(m["name"], `[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}`) {
				return fail("hook")
			}
		}
		if str(p["format"]) == "text" {
			if p["tool"] != nil || p["command"] != nil || p["call"] != nil || len(list(p["targets"])) > 0 || flag(p["workarounds_checked"]) {
				return fail("format")
			}
		} else if p["call"] == nil {
			return fail("call")
		}
	}
	if kind == "lane.workaround_suspected" {
		if !sortedStrings(p["how"], 1, 2, func(s string) bool { return s == "shell-write" || s == "reworded" || s == "shell-substitution-in-text" }) || !sortedStrings(p["paths"], 1, 1024, func(s string) bool { return recordPath(s, true) }) || !match(`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`, str(p["tool"])) || !validExcerpt(p["command"]) || !validCallPosition(p["call"], true) || (p["at"] != nil && !validTimestamp(p["at"])) {
			return fail("paths")
		}
		if err := observation.Check(p); err != nil {
			return refuse("%s %s", kind, err.Error())
		}
		if contains(stringsOf(p["how"]), "reworded") != (p["similarity"] != nil) {
			return fail("similarity")
		}
		if p["similarity"] != nil {
			m := obj(p["similarity"])
			if !exactKeys(m, strings.Fields("containment coverage")) {
				return fail("similarity")
			}
			for _, v := range m {
				if !numeric(v) || number(v) < 0 || number(v) > 1 {
					return fail("similarity")
				}
			}
		}
	}
	if kind == "lane.refusal_reviewed" {
		if !recordPath(p["path"], true) || match(`\([1-9][0-9]{0,8} more\)`, str(p["path"])) || !contains([]string{"clean", "workaround"}, str(p["verdict"])) || !sortedStrings(p["suspicions"], 1, 4096, func(s string) bool { return match(`ws-[0-9a-f]{24}`, s) }) {
			return fail("path")
		}
		if p["note"] != nil {
			m := obj(p["note"])
			text, ok := m["text"].(string)
			if !exactKeys(m, []string{"text", "sha256"}) || !ok || strings.TrimSpace(text) == "" || len([]rune(text)) > 4000 || !match(`[0-9a-f]{64}`, str(m["sha256"])) {
				return fail("note")
			}
		}
	}
	if kind == "lane.ingested" {
		if !match(`[a-z0-9][a-z0-9._-]{0,63}`, str(p["lane"])) || !whole(p["rows_added"], 0, 4096) || !whole(p["rows_existing"], 0, 4096) || list(p["rows"]) == nil || len(list(p["rows"])) > 4096 {
			return fail("rows")
		}
		for _, v := range list(p["rows"]) {
			m := obj(v)
			if !exactKeys(m, []string{"id", "sha256"}) || !match(`[a-z0-9][a-z0-9-]{0,31}/[a-z0-9][a-z0-9._-]{0,63}/(?:report|events|attachment)/[0-9a-f]{16}`, str(m["id"])) || !match(`[0-9a-f]{64}`, str(m["sha256"])) {
				return fail("rows")
			}
		}
	}
	return nil
}

// ValidateEventPayload shares the CLI's additional per-kind payload checks with
// service-owned observations. The envelope/base schema is checked by eventstore.
func ValidateEventPayload(kind string, payload map[string]any) error {
	return validateExtra(kind, payload)
}
