package lane

import "strings"

func validateLoop(e object) error {
	kind, lane, p := str(e["kind"]), str(e["lane"]), obj(e["payload"])
	fields, ok := map[string]string{"loop.started": "loop pid start detached unrecorded_end", "loop.stopped": "loop reason turns skips", "loop.turn": "loop kind sequences run", "loop.skipped": "loop reason until after detail"}[kind]
	if !ok || !exactKeys(p, strings.Fields(fields)) || !match(`[0-9a-f]{32}`, str(p["loop"])) {
		return refuse("loop payload is not in this version's form")
	}
	about := kind == "loop.turn" || kind == "loop.skipped"
	if about != (lane != "") {
		return refuse("loop lane binding is invalid")
	}
	switch kind {
	case "loop.started":
		if !whole(p["pid"], 1, 1<<62) || !match(`[0-9A-Za-z :.-]{1,64}`, str(p["start"])) || !nullableGrammar(p["unrecorded_end"], `[0-9a-f]{32}`) {
			return refuse("loop.started payload is invalid")
		}
		if _, ok := p["detached"].(bool); !ok {
			return refuse("loop.started detached must be a boolean")
		}
	case "loop.stopped":
		if !contains([]string{"stop", "error"}, str(p["reason"])) || !whole(p["turns"], 0, 1<<62) || !whole(p["skips"], 0, 1<<62) {
			return refuse("loop.stopped payload is invalid")
		}
	case "loop.turn":
		if !contains([]string{"mail", "idle"}, str(p["kind"])) || !sequences(p["sequences"], 0, 64) || !whole(p["run"], 2, 1000000) || (str(p["kind"]) == "idle") != (len(list(p["sequences"])) == 0) {
			return refuse("loop.turn payload is invalid")
		}
	case "loop.skipped":
		if !contains(strings.Fields("backoff refused no-room"), str(p["reason"])) || (p["until"] != nil && !validTimestamp(p["until"])) || (str(p["reason"]) == "backoff") != (p["after"] != nil) {
			return refuse("loop.skipped payload is invalid")
		}
		if p["after"] != nil {
			m := obj(p["after"])
			if !exactKeys(m, []string{"run", "reason"}) || !whole(m["run"], 1, 1000000) || !contains(strings.Fields("exit timeout stopped limit dropped lost gone cut"), str(m["reason"])) {
				return refuse("loop.skipped after is invalid")
			}
		}
		if p["detail"] != nil {
			s, ok := p["detail"].(string)
			if !ok || s == "" || len([]rune(s)) > 200 || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
				return refuse("loop.skipped detail is invalid")
			}
		}
	}
	return nil
}
