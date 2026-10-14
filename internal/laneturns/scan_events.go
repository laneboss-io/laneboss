package laneturns

import (
	"regexp"
	"sort"
	"strings"
)

var refusalPattern = regexp.MustCompile(`^rf-[0-9a-f]{24}$`)
var suspicionPattern = regexp.MustCompile(`^ws-[0-9a-f]{24}$`)
var toolPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
var callPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validScanPath(v any, command bool) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	if command && s == "(command)" {
		return true
	}
	return validAbsolute(s) || regexp.MustCompile(`^\(withheld [0-9a-f]{64}\)$|^\([1-9][0-9]{0,8} more\)$`).MatchString(s)
}
func validExcerpt(v any) bool {
	p := obj(v)
	if !exactKeys(p, "text withheld length sha256") || !boundedInteger(p["length"], 0, 1e9) || !hashPattern.MatchString(str(p["sha256"])) {
		return false
	}
	b, ok := p["withheld"].(bool)
	if !ok {
		return false
	}
	if b {
		return p["text"] == nil
	}
	s, ok := p["text"].(string)
	return ok && len([]rune(s)) <= 400 && float64(len([]rune(s))) <= number(p["length"])
}
func validPosition(v any) bool {
	p := obj(v)
	return exactKeys(p, "path line offset item") && validScanPath(p["path"], false) && boundedInteger(p["line"], 1, 1<<62) && boundedInteger(p["offset"], 0, 1<<62) && boundedInteger(p["item"], 0, 1000000)
}
func sortedStrings(v any, minimum, maximum int, valid func(any) bool) bool {
	if !isArray(v) || len(array(v)) < minimum || len(array(v)) > maximum {
		return false
	}
	last := ""
	for _, item := range array(v) {
		s, ok := item.(string)
		if !ok || s <= last || !valid(item) {
			return false
		}
		last = s
	}
	return true
}
func checkRefusalPayload(kind string, p object) error {
	fail := func(field string) error { return refused("%s: payload.%s is not in the documented form", kind, field) }
	if !refusalPattern.MatchString(str(p["refusal"])) {
		return fail("refusal")
	}
	if kind == "lane.refusal_reviewed" {
		if !exactKeys(p, "refusal path verdict suspicions note") || !validScanPath(p["path"], true) || !contains([]string{"clean", "workaround"}, str(p["verdict"])) || !sortedStrings(p["suspicions"], 1, 4096, func(v any) bool { return suspicionPattern.MatchString(str(v)) }) {
			return fail("review")
		}
		if p["note"] != nil {
			note := obj(p["note"])
			if !exactKeys(note, "text sha256") || str(note["text"]) == "" || len([]rune(str(note["text"]))) > 4000 || !hashPattern.MatchString(str(note["sha256"])) {
				return fail("note")
			}
		}
		return nil
	}
	if !boundedInteger(p["run"], 1, 1000000) {
		return fail("run")
	}
	if p["at"] != nil {
		if !validEventTimestamp(p["at"]) {
			return fail("at")
		}
	}
	if kind == "lane.refusal" {
		if !exactKeys(p, "run refusal guard kind format via hook tool at command message targets call record workarounds_checked") {
			return fail("fields")
		}
		if !senderPattern.MatchString(str(p["guard"])) || p["kind"] != nil && !contains([]string{"hook", "permission", "harness"}, str(p["kind"])) || !contains([]string{"claude-code", "text"}, str(p["format"])) || !contains([]string{"tool-result", "hook", "log"}, str(p["via"])) || !validExcerpt(p["message"]) || !validPosition(p["record"]) || !sortedStrings(p["targets"], 0, 1024, func(v any) bool { return validScanPath(v, false) }) {
			return fail("refusal")
		}
		if p["tool"] != nil && !toolPattern.MatchString(str(p["tool"])) {
			return fail("tool")
		}
		if p["command"] != nil && !validExcerpt(p["command"]) {
			return fail("command")
		}
		if _, ok := p["workarounds_checked"].(bool); !ok {
			return fail("workarounds_checked")
		}
		if p["hook"] != nil {
			h := obj(p["hook"])
			if !exactKeys(h, "event name") || h["event"] != nil && !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`).MatchString(str(h["event"])) || h["name"] != nil && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}$`).MatchString(str(h["name"])) {
				return fail("hook")
			}
		}
	} else {
		if !exactKeys(p, "run suspicion refusal how paths tool at command call similarity") || !suspicionPattern.MatchString(str(p["suspicion"])) || !sortedStrings(p["how"], 1, 2, func(v any) bool { return v == "reworded" || v == "shell-write" }) || !sortedStrings(p["paths"], 1, 1024, func(v any) bool { return validScanPath(v, true) }) || !toolPattern.MatchString(str(p["tool"])) || !validExcerpt(p["command"]) {
			return fail("suspicion")
		}
		if p["similarity"] != nil {
			s := obj(p["similarity"])
			if !exactKeys(s, "containment coverage") || number(s["containment"]) < 0 || number(s["containment"]) > 1 || number(s["coverage"]) < 0 || number(s["coverage"]) > 1 {
				return fail("similarity")
			}
		}
	}
	if p["call"] != nil {
		call := obj(p["call"])
		if !exactKeys(call, "id record") || call["id"] != nil && !callPattern.MatchString(str(call["id"])) || call["record"] != nil && !validPosition(call["record"]) {
			return fail("call")
		}
		if kind == "lane.workaround_suspected" && !validPosition(call["record"]) {
			return fail("call.record")
		}
	} else if kind == "lane.workaround_suspected" {
		return fail("call")
	}
	return nil
}
func refusalState(row object) object {
	if v := obj(row["refusals"]); v != nil {
		return v
	}
	return object{"recorded": object{}, "suspected": object{}, "verdicts": []any{}, "unreviewed": []any{}}
}
func checkRefusalTransition(row, e object) error {
	p := obj(e["payload"])
	kind := str(e["kind"])
	state := refusalState(row)
	if kind != "lane.refusal_reviewed" && (integer(p["run"]) < 1 || integer(p["run"]) > integer(row["run"])) {
		return refused("%s: the refusal or suspicion names a run that has not started", kind)
	}
	if kind == "lane.refusal" {
		if obj(state["recorded"])[str(p["refusal"])] != nil {
			return refused("lane.refusal: it is already recorded")
		}
		return nil
	}
	r := obj(obj(state["recorded"])[str(p["refusal"])])
	if r == nil {
		return refused("%s: no recorded refusal has that identity", kind)
	}
	if kind == "lane.workaround_suspected" {
		if integer(p["run"]) < integer(r["run"]) {
			return refused("a suspected workaround must come after its refusal")
		}
		return nil
	}
	for _, id := range texts(p["suspicions"]) {
		s := obj(obj(state["suspected"])[id])
		if s == nil || s["refusal"] != p["refusal"] || !contains(s["paths"], str(p["path"])) {
			return refused("a review must name suspicions of this refusal that name its reviewed path")
		}
	}
	return nil
}
func applyRefusal(row, e object) {
	p := obj(e["payload"])
	state := refusalState(row)
	switch e["kind"] {
	case "lane.refusal":
		obj(state["recorded"])[str(p["refusal"])] = object{"run": p["run"], "seq": e["seq"], "guard": p["guard"], "tool": p["tool"]}
	case "lane.workaround_suspected":
		obj(state["suspected"])[str(p["suspicion"])] = object{"refusal": p["refusal"], "run": p["run"], "seq": e["seq"], "how": p["how"], "paths": p["paths"]}
	case "lane.refusal_reviewed":
		state["verdicts"] = append(array(state["verdicts"]), object{"refusal": p["refusal"], "path": p["path"], "verdict": p["verdict"], "suspicions": p["suspicions"], "seq": e["seq"]})
	}
	reviewed := map[string]bool{}
	for _, item := range array(state["verdicts"]) {
		v := obj(item)
		for _, id := range texts(v["suspicions"]) {
			reviewed[id+"\x00"+str(v["path"])] = true
		}
	}
	open := map[string][]string{}
	for id, item := range obj(state["suspected"]) {
		s := obj(item)
		for _, path := range texts(s["paths"]) {
			if !reviewed[id+"\x00"+path] {
				key := str(s["refusal"]) + "\x00" + path
				open[key] = append(open[key], id)
			}
		}
	}
	keys := []string{}
	for k := range open {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := []any{}
	for _, k := range keys {
		parts := strings.SplitN(k, "\x00", 2)
		sort.Strings(open[k])
		rows = append(rows, object{"refusal": parts[0], "path": parts[1], "suspicions": open[k]})
	}
	state["unreviewed"] = rows
	row["refusals"] = state
}
