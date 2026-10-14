package laneturns

import (
	"path/filepath"
	"sort"
	"strings"
)

func emptyRow(lane string) object {
	times := object{}
	for _, key := range []string{"planned", "started", "ended", "timeout", "stuck", "resumed", "lost", "cleaned"} {
		times[key] = nil
	}
	return object{"lane": lane, "state": nil, "state_at": nil, "times": times, "landing": object{"merged": nil, "deployed": nil, "landed": nil}, "run": 0, "running": false, "runner": nil, "model": nil, "effort": nil, "account": nil, "worktree": nil, "branch": nil, "reason": nil, "exit_code": nil, "resumes": 0, "lost": 0, "cleaned": false, "events": 0, "last_seq": nil}
}
func emptyMail(idle any) object {
	return object{"turn_based": true, "idle_seconds": idle, "last": 0, "waiting": []any{}, "returned": []any{}, "in_flight": nil, "delivered": 0, "settled": nil}
}
func equalJSON(a, b any) bool {
	x, e := canonical(a)
	y, f := canonical(b)
	return e == nil && f == nil && string(x) == string(y)
}
func exactKeys(p object, keys string) bool {
	names := strings.Fields(keys)
	if p == nil || len(names) != len(p) {
		return false
	}
	for _, key := range names {
		if _, ok := p[key]; !ok {
			return false
		}
	}
	return true
}

const startedKeys = "run how launch runner model effort account chosen_by difficulty project worktree branch base repository budget_minutes quiet_seconds brief log session touches claims"
const adoptedKeys = "runner model effort account chosen_by difficulty project worktree branch base repository budget_minutes quiet_seconds brief log session touches claims session_id idle_seconds"

func checkPayload(kind string, p object) error {
	if contains([]string{"lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed"}, kind) {
		return checkRefusalPayload(kind, p)
	}
	keys := ""
	switch kind {
	case "lane.adopted":
		keys = adoptedKeys
	case "lane.started":
		keys = startedKeys
		if _, ok := p["session_id"]; ok {
			keys += " session_id"
		}
		if _, ok := p["mail"]; ok {
			keys += " mail idle_seconds"
		}
	case "lane.resumed":
		keys = "run after message"
	case "lane.ended":
		keys = "run reason exit_code signal duration_seconds pattern classification survivors"
		if _, ok := p["prompt"]; ok {
			keys += " prompt"
		}
	case "lane.mailed":
		keys = "sequence sender sha256 bytes"
	case "lane.delivered":
		keys = "run sequences"
	case "lane.returned":
		keys = "run sequences reason"
	case "lane.timeout":
		keys = "run budget_minutes elapsed_seconds"
	case "lane.stuck":
		keys = "run quiet_seconds output_bytes"
	case "lane.lost":
		keys = "run survivors"
	case "lane.gone":
		keys = "run launch"
	case "lane.planned", "lane.merged", "lane.deployed", "lane.landed":
		keys = ""
	case "lane.state":
		keys = "state"
	default:
		if contains([]string{"lane.cleaned", "lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed", "lane.ingested"}, kind) {
			return &unsupportedEventError{&problem{2, "refused", kind + ": this event's integration is not yet available; it remains pending"}}
		}
		return refused("%s: this turn implementation cannot append that event kind", kind)
	}
	if !exactKeys(p, keys) {
		if kind == "lane.state" && (p["held"] != nil || p["not_covered"] != nil) {
			return &unsupportedEventError{&problem{2, "refused", "lane.state: its resource or coverage extension remains pending for the owning command group"}}
		}
		return refused("%s: payload must hold exactly %s", kind, keys)
	}
	if err := validatePayloadFields(kind, p); err != nil {
		return err
	}
	if v, ok := p["run"]; ok {
		n := number(v)
		if n < 1 || n > 1000000 || n != float64(integer(v)) {
			return refused("%s: payload.run is invalid", kind)
		}
	}
	if kind == "lane.mailed" {
		if n := number(p["sequence"]); n < 1 || n > 999999999 || n != float64(integer(p["sequence"])) {
			return refused("lane.mailed: payload.sequence is invalid")
		}
		if !senderPattern.MatchString(str(p["sender"])) || !hashPattern.MatchString(str(p["sha256"])) || integer(p["bytes"]) < 1 || integer(p["bytes"]) > maxMessage {
			return refused("lane.mailed: payload sender, sha256 or bytes is invalid")
		}
	}
	if kind == "lane.started" || kind == "lane.adopted" {
		if !namePattern.MatchString(str(p["runner"])) || !modelPattern.MatchString(str(p["model"])) || !hasDigit.MatchString(str(p["model"])) {
			return refused("%s: payload.runner or model is invalid", kind)
		}
		for _, key := range []string{"worktree", "log"} {
			if !filepath.IsAbs(str(p[key])) || shown(str(p[key])) != str(p[key]) {
				return refused("%s: payload.%s must be an absolute path on one line", kind, key)
			}
		}
		if p["effort"] != nil && !namePattern.MatchString(str(p["effort"])) {
			return refused("%s: payload.effort is invalid", kind)
		}
		if p["account"] != nil && !senderPattern.MatchString(str(p["account"])) {
			return refused("%s: payload.account is invalid", kind)
		}
		if number(p["budget_minutes"]) <= 0 || number(p["budget_minutes"]) > 10080 || integer(p["quiet_seconds"]) < 1 || integer(p["quiet_seconds"]) > 604800 {
			return refused("%s: payload budget or quiet seconds is invalid", kind)
		}
		if !exactKeys(obj(p["brief"]), "path sha256") || !hashPattern.MatchString(str(obj(p["brief"])["sha256"])) || !filepath.IsAbs(str(obj(p["brief"])["path"])) {
			return refused("%s: payload.brief is invalid", kind)
		}
		if !exactKeys(obj(p["session"]), "socket name") || !filepath.IsAbs(str(obj(p["session"])["socket"])) {
			return refused("%s: payload.session is invalid", kind)
		}
		if !exactKeys(obj(p["chosen_by"]), "runner model effort account") {
			return refused("%s: payload.chosen_by is invalid", kind)
		}
		if kind == "lane.adopted" || p["session_id"] != nil {
			if !uuidPattern.MatchString(str(p["session_id"])) {
				return refused("%s: payload.session_id must be a lower-case UUID", kind)
			}
		}
		if p["idle_seconds"] != nil && (integer(p["idle_seconds"]) < 1 || integer(p["idle_seconds"]) > 604800) {
			return refused("%s: payload.idle_seconds is invalid", kind)
		}
		if kind == "lane.started" {
			if !launchPattern.MatchString(str(p["launch"])) || !contains([]string{"start", "resume", "reuse"}, str(p["how"])) {
				return refused("lane.started: payload launch or how is invalid")
			}
			if mail, ok := p["mail"]; ok {
				if len(array(mail)) > 64 {
					return refused("lane.started: payload.mail holds more than 64 messages")
				}
				if err := checkSequences(mail); err != nil {
					return err
				}
			}
		}
	}
	if kind == "lane.ended" {
		if !contains([]string{"exit", "timeout", "stopped", "limit", "dropped", "hook-config"}, str(p["reason"])) || integer(p["survivors"]) < 0 || number(p["duration_seconds"]) < 0 {
			return refused("lane.ended: reason, survivors or duration is invalid")
		}
		if p["exit_code"] != nil && (number(p["exit_code"]) < 0 || number(p["exit_code"]) > 255) {
			return refused("lane.ended: payload.exit_code is invalid")
		}
		if p["prompt"] != nil {
			f := obj(p["prompt"])
			if !exactKeys(f, "state bytes length") || !contains([]string{"written", "cut"}, str(f["state"])) || number(f["bytes"]) < 0 || number(f["length"]) < 1 || number(f["bytes"]) > number(f["length"]) || f["state"] == "written" && number(f["bytes"]) != number(f["length"]) {
				return refused("lane.ended: payload.prompt is invalid")
			}
		}
	}
	if kind == "lane.resumed" {
		if integer(p["run"]) < 2 {
			return refused("lane.resumed: payload.run must be at least 2")
		}
		if p["after"] != nil && !contains([]string{"exit", "timeout", "stopped", "limit", "dropped", "hook-config", "lost"}, str(p["after"])) {
			return refused("lane.resumed: payload.after is invalid")
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		if integer(p["run"]) < 2 || len(array(p["sequences"])) < 1 || len(array(p["sequences"])) > 64 {
			return refused("%s: announcement is invalid", kind)
		}
		if err := checkSequences(p["sequences"]); err != nil {
			return err
		}
	}
	if kind == "lane.state" && !contains([]string{"queued", "running", "verifying", "accepted", "merged", "abandoned", "waiting"}, str(p["state"])) {
		return refused("lane.state: payload.state is invalid")
	}
	return nil
}
func checkSequences(v any) error {
	if !isArray(v) {
		return refused("message sequences must be a list")
	}
	seen := map[int]bool{}
	last := 0
	for _, x := range array(v) {
		n := integer(x)
		if !isWhole(x) || n < 1 || n > 999999999 || seen[n] || n < last || number(x) != float64(n) {
			return refused("message sequences must be distinct, sorted whole numbers")
		}
		seen[n] = true
		last = n
	}
	return nil
}
func checkBinding(s *stateDir, lane, kind string, p object) error {
	if kind == "lane.resumed" {
		if p["message"] == nil {
			return nil
		}
		m := obj(p["message"])
		if str(m["path"]) != s.lanePath(lane, "rendered", str(m["sha256"])+".md") {
			return refused("lane.resumed: payload.message is not bound to the lane's rendered directory")
		}
		return nil
	}
	if str(p["log"]) != s.lanePath(lane, "output.log") || str(obj(p["session"])["socket"]) != socketPath(s.c.name, s.path) || str(obj(p["session"])["name"]) != sessionName(lane) {
		return refused("%s: payload log or session is not bound to this lane and configuration", kind)
	}
	b := obj(p["brief"])
	if str(b["path"]) != s.lanePath(lane, "rendered", str(b["sha256"])+".md") {
		return refused("%s: payload.brief is not bound to the lane's rendered directory", kind)
	}
	return nil
}
func checkTransition(row object, e object) error {
	if row == nil {
		row = emptyRow(str(e["lane"]))
	}
	if contains([]string{"lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed"}, str(e["kind"])) {
		return checkRefusalTransition(row, e)
	}
	kind := str(e["kind"])
	p := obj(e["payload"])
	lane := str(e["lane"])
	mail := obj(row["mail"])
	based := flag(mail["turn_based"])
	if kind == "lane.adopted" && integer(row["events"]) > 0 {
		return refused("lane.adopted: lane %s already has events; adoption is only for a lane that has no event yet", lane)
	}
	if kind == "lane.started" || kind == "lane.resumed" {
		if flag(row["running"]) {
			return refused("%s: lane %s is running run %d", kind, lane, integer(row["run"]))
		}
		if integer(p["run"]) != integer(row["run"])+1 {
			return refused("%s: payload.run must be the run after the lane's last", kind)
		}
		if based && row["state"] == "abandoned" {
			return refused("%s: lane %s is abandoned, so no turn starts", kind, lane)
		}
	}
	if contains([]string{"lane.ended", "lane.timeout", "lane.stuck", "lane.lost"}, kind) && (!flag(row["running"]) || integer(p["run"]) != integer(row["run"])) {
		return refused("%s: lane %s has no run %d going on", kind, lane, integer(p["run"]))
	}
	if kind == "lane.gone" && integer(p["run"]) != integer(row["run"]) {
		return refused("lane.gone: payload.run must be the latest run")
	}
	if kind == "lane.mailed" {
		if !based {
			return refused("lane %s is not turn-based", lane)
		}
		if flag(row["cleaned"]) || row["state"] == "abandoned" {
			return refused("lane %s was cleaned or abandoned", lane)
		}
		if integer(p["sequence"]) != integer(mail["last"])+1 {
			return refused("lane.mailed: payload.sequence must be the one after the lane's last")
		}
		if queued(mail) >= 1000 {
			return refused("lane %s already has 1000 messages that wait or have returned", lane)
		}
	}
	if kind == "lane.started" {
		if p["how"] == "resume" {
			if !based || p["mail"] == nil {
				return refused("a turn resumes a turn-based lane and carries payload.mail")
			}
			queue := append(append([]any{}, array(mail["returned"])...), array(mail["waiting"])...)
			carried := array(p["mail"])
			if len(carried) > len(queue) || !equalJSON(carried, queue[:len(carried)]) {
				return refused("lane.started: payload.mail must be the head of the queue, the returned messages and then the waiting ones, in order")
			}
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		settled := obj(mail["settled"])
		if flag(row["running"]) || settled == nil || flag(settled["announced"]) || integer(settled["run"]) != integer(row["run"]) || integer(p["run"]) != integer(settled["run"]) || !equalJSON(p["sequences"], settled["sequences"]) || settled["outcome"] != strings.TrimPrefix(kind, "lane.") || kind == "lane.returned" && p["reason"] != settled["reason"] {
			return refused("%s: no matching settled messages are due to be announced", kind)
		}
	}
	if kind == "lane.state" {
		if p["state"] == "waiting" {
			return refused("waiting is set only by the end of a turn")
		}
		if based && p["state"] != "abandoned" {
			return refused("a turn-based lane can only be marked abandoned")
		}
	}
	return nil
}
func settlement(kind string, p object) (string, any) {
	if kind == "lane.lost" || kind == "lane.gone" {
		return "returned", strings.TrimPrefix(kind, "lane.")
	}
	if p["reason"] == "exit" && p["exit_code"] != nil && integer(p["exit_code"]) == 0 {
		if obj(p["prompt"])["state"] == "written" {
			return "delivered", nil
		}
		return "returned", "cut"
	}
	return "returned", p["reason"]
}
func queued(mail object) int { return len(array(mail["waiting"])) + len(array(mail["returned"])) }
func applyEvent(row, e object) object {
	p := obj(e["payload"])
	name := strings.TrimPrefix(str(e["kind"]), "lane.")
	at := eventTime(e)
	times := obj(row["times"])
	if _, ok := times[name]; ok {
		times[name] = at
	}
	if _, ok := obj(row["landing"])[name]; ok {
		obj(row["landing"])[name] = at
	}
	state := any(nil)
	switch name {
	case "planned":
		state = "queued"
	case "started":
		state = "running"
	case "ended", "lost", "gone":
		state = "verifying"
	case "adopted":
		state = "waiting"
	case "state":
		state = p["state"]
	}
	mail := obj(row["mail"])
	closing := name == "ended" || name == "lost" || name == "gone"
	if closing && mail != nil {
		if row["state"] == "abandoned" {
			state = nil
		} else if flag(mail["turn_based"]) {
			state = "waiting"
		}
	}
	if state != nil {
		row["state"] = state
		row["state_at"] = at
	}
	if name == "started" || name == "adopted" {
		for _, key := range []string{"runner", "model", "effort", "account", "worktree", "branch"} {
			row[key] = p[key]
		}
		row["reason"] = nil
		row["exit_code"] = nil
		row["cleaned"] = false
		if name == "adopted" {
			row["run"] = 1
			row["running"] = false
			row["mail"] = emptyMail(p["idle_seconds"])
		} else {
			row["run"] = p["run"]
			row["running"] = true
			if carried, ok := p["mail"]; ok {
				if mail == nil {
					mail = emptyMail(p["idle_seconds"])
					row["mail"] = mail
				}
				mail["turn_based"] = true
				mail["idle_seconds"] = p["idle_seconds"]
				taken := map[int]bool{}
				for _, x := range array(carried) {
					taken[integer(x)] = true
				}
				for _, key := range []string{"waiting", "returned"} {
					kept := []any{}
					for _, x := range array(mail[key]) {
						if !taken[integer(x)] {
							kept = append(kept, x)
						}
					}
					mail[key] = kept
				}
				mail["in_flight"] = nil
				if len(taken) > 0 {
					mail["in_flight"] = object{"run": p["run"], "sequences": array(carried)}
				}
			} else if mail != nil {
				mail["turn_based"] = false
			}
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
	case "mailed":
		mail["last"] = p["sequence"]
		mail["waiting"] = append(array(mail["waiting"]), p["sequence"])
	case "delivered", "returned":
		obj(mail["settled"])["announced"] = true
	}
	if closing && mail != nil {
		flight := obj(mail["in_flight"])
		if flight != nil && integer(flight["run"]) == integer(p["run"]) {
			outcome, reason := settlement(str(e["kind"]), p)
			mail["in_flight"] = nil
			if outcome == "delivered" {
				mail["delivered"] = integer(mail["delivered"]) + len(array(flight["sequences"]))
			} else {
				set := map[int]bool{}
				for _, x := range append(array(mail["returned"]), array(flight["sequences"])...) {
					set[integer(x)] = true
				}
				numbers := []int{}
				for n := range set {
					numbers = append(numbers, n)
				}
				sort.Ints(numbers)
				mail["returned"] = numbers
			}
			mail["settled"] = object{"run": flight["run"], "outcome": outcome, "reason": reason, "sequences": flight["sequences"], "announced": false}
		}
	}
	row["events"] = integer(row["events"]) + 1
	if contains([]string{"lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed"}, str(e["kind"])) {
		applyRefusal(row, e)
	}
	row["last_seq"] = e["seq"]
	return row
}
