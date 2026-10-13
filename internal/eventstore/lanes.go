package eventstore

import (
	"path/filepath"
	"sort"
	"strings"
)

var times = []string{"planned", "started", "ended", "timeout", "stuck", "resumed", "lost", "cleaned"}
var landing = []string{"merged", "deployed", "landed"}

func empty(lane string) Object {
	t, l := Object{}, Object{}
	for _, key := range times {
		t[key] = nil
	}
	for _, key := range landing {
		l[key] = nil
	}
	return Object{"lane": lane, "state": nil, "state_at": nil, "times": t, "landing": l, "run": 0, "running": false, "runner": nil, "model": nil, "effort": nil, "account": nil, "worktree": nil, "branch": nil, "reason": nil, "exit_code": nil, "resumes": 0, "lost": 0, "cleaned": false, "events": 0, "last_seq": nil}
}
func keysEqual(m Object, keys []string) bool {
	if m == nil || len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func currentForm(p Object) bool {
	if !keysEqual(object(p["times"]), times) {
		return false
	}
	base := empty("")
	for k := range base {
		if _, ok := p[k]; !ok {
			return false
		}
	}
	for k := range p {
		if _, ok := base[k]; !ok && k != "refusals" && k != "mail" {
			return false
		}
	}
	if r, ok := p["refusals"]; ok && !keysEqual(object(r), []string{"recorded", "suspected", "verdicts", "unreviewed"}) {
		return false
	}
	if m, ok := p["mail"]; ok {
		if !keysEqual(object(m), []string{"turn_based", "idle_seconds", "last", "waiting", "returned", "in_flight", "delivered", "settled"}) {
			return false
		}
		if _, ok = object(m)["turn_based"].(bool); !ok {
			return false
		}
	}
	return projectionValues(p) == nil
}

// Check values before changing a row: a malformed queue must never become an empty queue.
func projectionValues(p Object) error {
	const maximumCount int64 = 1<<63 - 1
	timeFields, landingFields := map[string]validator{}, map[string]validator{}
	for _, key := range times {
		timeFields[key] = nullable(checkTimestamp)
	}
	for _, key := range landing {
		landingFields[key] = nullable(checkTimestamp)
	}
	checks := map[string]validator{
		"lane": grammar(`[a-z0-9][a-z0-9._-]{0,63}`), "state": nullable(oneOf("queued", "running", "verifying", "accepted", "merged", "abandoned", "waiting")), "state_at": nullable(checkTimestamp),
		"times": fields(timeFields), "landing": fields(landingFields), "run": whole(0, 1000000), "running": boolean,
		"runner": nullable(grammar(`[a-z0-9][a-z0-9-]{0,31}`)), "model": nullable(modelName), "effort": nullable(grammar(`[a-z0-9][a-z0-9-]{0,31}`)), "account": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`)), "worktree": nullable(absolute), "branch": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}`)),
		"reason": nullable(oneOf("exit", "timeout", "stopped", "limit", "dropped", "lost")), "exit_code": nullable(whole(0, 255)), "resumes": whole(0, maximumCount), "lost": whole(0, maximumCount), "cleaned": boolean, "events": whole(0, maximumCount), "last_seq": nullable(whole(1, maximumCount)),
	}
	if _, ok := p["mail"]; ok {
		checks["mail"] = fields(map[string]validator{
			"turn_based": boolean, "idle_seconds": nullable(whole(1, 604800)), "last": whole(0, 999999999), "waiting": sortedList(sequenceCheck, 0, 1000), "returned": sortedList(sequenceCheck, 0, 1000), "delivered": whole(0, 999999999),
			"in_flight": nullable(fields(map[string]validator{"run": runCheck, "sequences": carriedCheck})),
			"settled":   nullable(fields(map[string]validator{"run": runCheck, "outcome": oneOf("delivered", "returned"), "reason": nullable(returnCheck), "sequences": carriedCheck, "announced": boolean})),
		})
	}
	if _, ok := p["refusals"]; ok {
		mapOf := func(keyCheck, item validator) validator {
			return func(v any, w string) error {
				m := object(v)
				if m == nil {
					return Refuse("%s: must be an object", w)
				}
				for key, value := range m {
					if err := keyCheck(key, w); err != nil {
						return err
					}
					if err := item(value, w); err != nil {
						return err
					}
				}
				return nil
			}
		}
		seq := whole(1, maximumCount)
		checks["refusals"] = fields(map[string]validator{
			"recorded":   mapOf(grammar(`rf-[0-9a-f]{24}`), fields(map[string]validator{"run": runCheck, "seq": seq, "guard": grammar(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`), "tool": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`))})),
			"suspected":  mapOf(grammar(`ws-[0-9a-f]{24}`), fields(map[string]validator{"refusal": grammar(`rf-[0-9a-f]{24}`), "run": runCheck, "seq": seq, "how": sortedList(oneOf("reworded", "shell-write"), 1, 2), "paths": sortedList(suspectedPath, 1, 1024)})),
			"verdicts":   array(fields(map[string]validator{"refusal": grammar(`rf-[0-9a-f]{24}`), "path": suspectedPath, "verdict": oneOf("clean", "workaround"), "suspicions": sortedList(grammar(`ws-[0-9a-f]{24}`), 1, 4096), "seq": seq}), int(^uint(0)>>1)),
			"unreviewed": array(fields(map[string]validator{"refusal": grammar(`rf-[0-9a-f]{24}`), "path": suspectedPath, "suspicions": sortedList(grammar(`ws-[0-9a-f]{24}`), 1, int(^uint(0)>>1))}), int(^uint(0)>>1)),
		})
	}
	return fields(checks)(p, "projection")
}
func checkBinding(e Object, d *Directory) error {
	kind, lane := text(e["kind"]), text(e["lane"])
	p := object(e["payload"])
	directory := filepath.Join(d.Path, "lanes", lane)
	rendered := func(v any, label string) error {
		m := object(v)
		if m != nil && m["path"] != filepath.Join(directory, "rendered", text(m["sha256"])+".md") {
			return Refuse("%s: %s is not this lane's rendered file in this configuration", kind, label)
		}
		return nil
	}
	if kind == "lane.started" || kind == "lane.adopted" {
		session := object(p["session"])
		if session["socket"] != d.Config.Socket(d.Path) || session["name"] != strings.ReplaceAll(lane, ".", "_") {
			return Refuse("%s: payload.session is not this configuration's session for lane %s", kind, lane)
		}
		if p["log"] != filepath.Join(directory, "output.log") {
			return Refuse("%s: payload.log is not this lane's log in this configuration", kind)
		}
		return rendered(p["brief"], "payload.brief")
	}
	if kind == "lane.resumed" {
		return rendered(p["message"], "payload.message")
	}
	return nil
}
func checkTransition(p, e Object) error {
	kind, lane := text(e["kind"]), text(e["lane"])
	payload := object(e["payload"])
	if p == nil {
		p = empty(lane)
	}
	running := p["running"] == true
	if kind == "lane.started" || kind == "lane.resumed" {
		if running {
			return Refuse("%s: lane %s is running run %d; a new run starts only after it ends", kind, lane, num(p["run"]))
		}
		if num(payload["run"]) != num(p["run"])+1 {
			return Refuse("%s: payload.run must be %d, the run after the lane's last", kind, num(p["run"])+1)
		}
		if kind == "lane.started" && payload["how"] == "reuse" && p["state"] != "merged" && p["state"] != "abandoned" {
			return Refuse("lane.started: lane %s can be started again only when it is merged or abandoned", lane)
		}
	}
	if kind == "lane.adopted" && num(p["events"]) != 0 {
		return Refuse("lane.adopted: lane %s already has events; an adoption is only for a lane that has no event yet", lane)
	}
	if contains([]string{"lane.ended", "lane.timeout", "lane.stuck", "lane.lost"}, kind) && (!running || num(payload["run"]) != num(p["run"])) {
		return Refuse("%s: lane %s has no run %d going on", kind, lane, num(payload["run"]))
	}
	if kind == "lane.cleaned" && (running || p["state"] != "merged" && p["state"] != "abandoned") {
		return Refuse("lane.cleaned: lane %s must be merged or abandoned and not running", lane)
	}
	if kind == "lane.gone" && num(payload["run"]) != num(p["run"]) {
		return Refuse("lane.gone: lane %s's latest run is run %d", lane, num(p["run"]))
	}
	if contains([]string{"lane.mailed", "lane.delivered", "lane.returned", "lane.state", "lane.started", "lane.resumed"}, kind) {
		if err := checkMail(p, e); err != nil {
			return err
		}
	}
	if contains([]string{"lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed"}, kind) {
		return checkRefusal(p, e)
	}
	return nil
}
func checkMail(current, e Object) error {
	kind, lane := text(e["kind"]), text(e["lane"])
	p := object(e["payload"])
	mail := object(current["mail"])
	based := mail["turn_based"] == true
	if kind == "lane.mailed" {
		if !based {
			return Refuse("lane.mailed: lane %s is not turn-based", lane)
		}
		if current["cleaned"] == true {
			return Refuse("lane.mailed: lane %s was cleaned", lane)
		}
		if current["state"] == "abandoned" {
			return Refuse("lane.mailed: lane %s is abandoned", lane)
		}
		if num(p["sequence"]) != num(mail["last"])+1 {
			return Refuse("lane.mailed: payload.sequence must be %d, the one after the lane's last", num(mail["last"])+1)
		}
		if len(list(mail["waiting"]))+len(list(mail["returned"])) >= 1000 {
			return Refuse("lane.mailed: lane %s already has 1000 messages that wait or have returned", lane)
		}
	}
	if (kind == "lane.resumed" || kind == "lane.started") && based && current["state"] == "abandoned" && (kind == "lane.resumed" || p["how"] == "resume") {
		return Refuse("%s: lane %s is abandoned, so no turn starts; its messages stay waiting", kind, lane)
	}
	if kind == "lane.started" {
		if p["how"] == "reuse" && mail != nil && (len(list(mail["waiting"])) > 0 || len(list(mail["returned"])) > 0) {
			return Refuse("lane.started: lane %s has messages that wait or have returned; a new life is never sent mail written for the old one", lane)
		}
		carried, hasMail := p["mail"]
		if hasMail && p["how"] == "resume" {
			if !based {
				return Refuse("lane.started: a turn resumes a turn-based lane, and lane %s is not one", lane)
			}
			queue := append(append([]any{}, list(mail["returned"])...), list(mail["waiting"])...)
			n := len(list(carried))
			if n > len(queue) || !equal(carried, queue[:n]) {
				return Refuse("lane.started: payload.mail must be the head of the queue, the returned messages and then the waiting ones, in order")
			}
		} else if !hasMail && p["how"] == "resume" && based {
			return Refuse("lane.started: lane %s is turn-based, so a resume carries payload.mail", lane)
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		if current["running"] == true {
			return Refuse("%s: lane %s is running, so no announcement is due", kind, lane)
		}
		settled := object(mail["settled"])
		if settled == nil {
			return Refuse("%s: lane %s has no settled messages to announce", kind, lane)
		}
		if num(settled["run"]) != num(current["run"]) {
			return Refuse("%s: the settled messages are no longer those of the lane's latest run", kind)
		}
		if settled["announced"] == true {
			return Refuse("%s: the messages of this run are already announced", kind)
		}
		wanted := strings.TrimPrefix(kind, "lane.")
		if settled["outcome"] != wanted {
			return Refuse("%s: the messages were settled as %s, not %s", kind, text(settled["outcome"]), wanted)
		}
		if num(p["run"]) != num(settled["run"]) || !equal(p["sequences"], settled["sequences"]) {
			return Refuse("%s: payload.run and payload.sequences must be those of the settled messages", kind)
		}
		if kind == "lane.returned" && p["reason"] != settled["reason"] {
			return Refuse("lane.returned: payload.reason must be the reason the messages were settled with")
		}
	}
	if kind == "lane.state" {
		if p["state"] == "waiting" {
			return Refuse("lane.state: waiting is never set by lane.state; the end of a run sets it")
		}
		if based && p["state"] != "abandoned" {
			return Refuse("lane.state: lane %s is turn-based, so only abandoned can be recorded", lane)
		}
	}
	return nil
}
func refusalState(p Object) Object {
	if r := object(p["refusals"]); r != nil {
		return r
	}
	return Object{"recorded": Object{}, "suspected": Object{}, "verdicts": []any{}, "unreviewed": []any{}}
}
func recordedSeq(p, e Object) any {
	r := refusalState(p)
	body := object(e["payload"])
	switch e["kind"] {
	case "lane.refusal":
		return object(object(r["recorded"])[text(body["refusal"])])["seq"]
	case "lane.workaround_suspected":
		return object(object(r["suspected"])[text(body["suspicion"])])["seq"]
	}
	return nil
}
func checkRefusal(current, e Object) error {
	kind, lane := text(e["kind"]), text(e["lane"])
	p := object(e["payload"])
	found := refusalState(current)
	recorded, suspected := object(found["recorded"]), object(found["suspected"])
	if (kind == "lane.refusal" || kind == "lane.workaround_suspected") && (num(p["run"]) < 1 || num(p["run"]) > num(current["run"])) {
		return Refuse("%s: lane %s has no run %d", kind, lane, num(p["run"]))
	}
	if kind == "lane.refusal" && recorded[text(p["refusal"])] != nil {
		return Refuse("lane.refusal: this refusal is recorded already")
	}
	if kind == "lane.workaround_suspected" || kind == "lane.refusal_reviewed" {
		if recorded[text(p["refusal"])] == nil {
			return Refuse("%s: lane %s has no recorded refusal", kind, lane)
		}
	}
	if kind == "lane.workaround_suspected" {
		if suspected[text(p["suspicion"])] != nil {
			return Refuse("lane.workaround_suspected: this suspicion is recorded already")
		}
		if num(p["run"]) < num(object(recorded[text(p["refusal"])])["run"]) {
			return Refuse("lane.workaround_suspected: a suspected workaround comes after its refusal, in its run or a later one")
		}
	}
	if kind == "lane.refusal_reviewed" {
		for _, suspicion := range list(p["suspicions"]) {
			item := object(suspected[text(suspicion)])
			hasPath := false
			for _, path := range list(item["paths"]) {
				hasPath = hasPath || equal(path, p["path"])
			}
			if item == nil || item["refusal"] != p["refusal"] || !hasPath {
				return Refuse("lane.refusal_reviewed: a suspicion is not a recorded suspicion of this refusal that names the reviewed path")
			}
		}
	}
	return nil
}
func unreviewed(found Object) []any {
	type pair struct{ refusal, path string }
	reviewed := map[pair]bool{}
	for _, v := range list(found["verdicts"]) {
		verdict := object(v)
		for _, s := range list(verdict["suspicions"]) {
			reviewed[pair{text(s), text(verdict["path"])}] = true
		}
	}
	paths := map[pair][]string{}
	for suspicion, v := range object(found["suspected"]) {
		item := object(v)
		for _, path := range list(item["paths"]) {
			if !reviewed[pair{suspicion, text(path)}] {
				key := pair{text(item["refusal"]), text(path)}
				paths[key] = append(paths[key], suspicion)
			}
		}
	}
	keys := []pair{}
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].refusal != keys[j].refusal {
			return keys[i].refusal < keys[j].refusal
		}
		return keys[i].path < keys[j].path
	})
	result := []any{}
	for _, key := range keys {
		sort.Strings(paths[key])
		suspicions := []any{}
		for _, s := range paths[key] {
			suspicions = append(suspicions, s)
		}
		result = append(result, Object{"refusal": key.refusal, "path": key.path, "suspicions": suspicions})
	}
	return result
}
func applyRefusal(projection, e Object) {
	found := refusalState(projection)
	p := object(e["payload"])
	switch e["kind"] {
	case "lane.refusal":
		object(found["recorded"])[text(p["refusal"])] = Object{"run": p["run"], "seq": e["seq"], "guard": p["guard"], "tool": p["tool"]}
	case "lane.workaround_suspected":
		object(found["suspected"])[text(p["suspicion"])] = Object{"refusal": p["refusal"], "run": p["run"], "seq": e["seq"], "how": p["how"], "paths": p["paths"]}
	case "lane.refusal_reviewed":
		found["verdicts"] = append(list(found["verdicts"]), Object{"refusal": p["refusal"], "path": p["path"], "verdict": p["verdict"], "suspicions": p["suspicions"], "seq": e["seq"]})
	}
	found["unreviewed"] = unreviewed(found)
	projection["refusals"] = found
}
func freshMail() Object {
	return Object{"turn_based": false, "idle_seconds": nil, "last": 0, "waiting": []any{}, "returned": []any{}, "in_flight": nil, "delivered": 0, "settled": nil}
}
func startTurn(p, body Object) {
	mail := object(p["mail"])
	if mail == nil {
		mail = freshMail()
		p["mail"] = mail
	}
	mail["turn_based"] = true
	mail["idle_seconds"] = body["idle_seconds"]
	carried := list(body["mail"])
	for _, key := range []string{"waiting", "returned"} {
		remaining := []any{}
		for _, n := range list(mail[key]) {
			held := false
			for _, c := range carried {
				held = held || num(c) == num(n)
			}
			if !held {
				remaining = append(remaining, n)
			}
		}
		mail[key] = remaining
	}
	mail["in_flight"] = nil
	if len(carried) > 0 {
		mail["in_flight"] = Object{"run": body["run"], "sequences": append([]any{}, carried...)}
	}
}
func settle(mail Object, name string, p Object) {
	flight := object(mail["in_flight"])
	if flight == nil || num(flight["run"]) != num(p["run"]) {
		return
	}
	outcome := "returned"
	var reason any = p["reason"]
	if name == "lost" || name == "gone" {
		reason = name
	} else if p["reason"] == "exit" && p["exit_code"] != nil && num(p["exit_code"]) == 0 {
		if object(p["prompt"])["state"] == "written" {
			outcome, reason = "delivered", nil
		} else {
			reason = "cut"
		}
	}
	mail["in_flight"] = nil
	if outcome == "delivered" {
		mail["delivered"] = num(mail["delivered"]) + int64(len(list(flight["sequences"])))
	} else {
		set := map[int64]bool{}
		for _, n := range append(append([]any{}, list(mail["returned"])...), list(flight["sequences"])...) {
			set[num(n)] = true
		}
		numbers := []int64{}
		for n := range set {
			numbers = append(numbers, n)
		}
		sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
		returned := []any{}
		for _, n := range numbers {
			returned = append(returned, n)
		}
		mail["returned"] = returned
	}
	mail["settled"] = Object{"run": flight["run"], "outcome": outcome, "reason": reason, "sequences": append([]any{}, list(flight["sequences"])...), "announced": false}
}
func apply(p, e Object) {
	at := e["occurred_at"]
	if at == nil {
		at = e["recorded_at"]
	}
	name := strings.TrimPrefix(text(e["kind"]), "lane.")
	body := object(e["payload"])
	if contains(times, name) {
		object(p["times"])[name] = at
	}
	if contains(landing, name) {
		object(p["landing"])[name] = at
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
		state = body["state"]
	case "adopted":
		state = "waiting"
	}
	mail := object(p["mail"])
	closing := name == "ended" || name == "lost" || name == "gone"
	if closing && mail != nil {
		if p["state"] == "abandoned" {
			state = nil
		} else if mail["turn_based"] == true {
			state = "waiting"
		}
	}
	if state != nil {
		p["state"], p["state_at"] = state, at
	}
	if name == "started" || name == "adopted" {
		p["run"], p["running"] = body["run"], true
		p["reason"], p["exit_code"], p["cleaned"] = nil, nil, false
		for _, key := range []string{"runner", "model", "effort", "account", "worktree", "branch"} {
			p[key] = body[key]
		}
		if name == "adopted" {
			p["run"], p["running"] = 1, false
			m := freshMail()
			m["turn_based"], m["idle_seconds"] = true, body["idle_seconds"]
			p["mail"] = m
		} else if _, ok := body["mail"]; ok {
			startTurn(p, body)
		} else if mail != nil {
			mail["turn_based"] = false
		}
	}
	switch name {
	case "resumed":
		p["resumes"] = num(p["resumes"]) + 1
	case "ended":
		p["running"], p["reason"], p["exit_code"] = false, body["reason"], body["exit_code"]
	case "lost":
		p["running"], p["reason"], p["exit_code"], p["lost"] = false, "lost", nil, num(p["lost"])+1
	case "gone":
		p["running"] = false
	case "cleaned":
		p["cleaned"] = true
	case "mailed":
		mail["last"] = body["sequence"]
		mail["waiting"] = append(list(mail["waiting"]), body["sequence"])
	case "delivered", "returned":
		object(object(p["mail"])["settled"])["announced"] = true
	}
	if closing && mail != nil {
		settle(mail, name, body)
	}
	if contains([]string{"refusal", "workaround_suspected", "refusal_reviewed"}, name) {
		applyRefusal(p, e)
	}
	p["events"] = num(p["events"]) + 1
	p["last_seq"] = e["seq"]
}
