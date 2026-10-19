package doctorbase

import (
	"fmt"
	"sort"
	"strings"
)

var laneTimes = strings.Fields("planned started ended timeout stuck resumed lost cleaned")
var laneLanding = strings.Fields("merged deployed landed")

func emptyLane(lane string) map[string]any {
	times, landing := map[string]any{}, map[string]any{}
	for _, k := range laneTimes {
		times[k] = nil
	}
	for _, k := range laneLanding {
		landing[k] = nil
	}
	return map[string]any{"lane": lane, "state": nil, "state_at": nil, "times": times, "landing": landing, "run": int64(0), "running": false, "runner": nil, "model": nil, "effort": nil, "account": nil, "worktree": nil, "branch": nil, "reason": nil, "exit_code": nil, "resumes": int64(0), "lost": int64(0), "cleaned": false, "events": int64(0), "last_seq": nil}
}
func emptyMail(turns bool, idle any) map[string]any {
	return map[string]any{"turn_based": turns, "idle_seconds": idle, "last": int64(0), "waiting": []any{}, "returned": []any{}, "in_flight": nil, "delivered": int64(0), "settled": nil}
}
func refusals(row map[string]any) map[string]any {
	if f, ok := row["refusals"].(map[string]any); ok {
		return f
	}
	return map[string]any{"recorded": map[string]any{}, "suspected": map[string]any{}, "verdicts": []any{}, "unreviewed": []any{}}
}
func member(a []any, v any) bool {
	for _, x := range a {
		if equalValue(x, v) {
			return true
		}
	}
	return false
}
func finished(v any) bool { return v == "merged" || v == "abandoned" }
func checkTransition(row, event map[string]any) error {
	kind := String(event["kind"])
	p := Object(event["payload"])
	running := row["running"] == true
	run := integral(row["run"])
	n := integral(p["run"])
	fail := func(message string) error { return fmt.Errorf("%s: %s", kind, message) }
	if kind == "lane.started" || kind == "lane.resumed" {
		if running {
			return fail("a new run starts only after the running run ends")
		}
		if n != run+1 {
			return fail("payload.run must follow the lane's last run")
		}
		if kind == "lane.started" && p["how"] == "reuse" && !finished(row["state"]) {
			return fail("a lane can be started again only when merged or abandoned")
		}
	}
	if kind == "lane.adopted" && integral(row["events"]) != 0 {
		return fail("an adoption is only for a lane that has no event yet")
	}
	if kind == "lane.ended" || kind == "lane.timeout" || kind == "lane.stuck" || kind == "lane.lost" {
		if !running || n != run {
			return fail("the lane has no such run going on")
		}
	}
	if kind == "lane.cleaned" && (running || !finished(row["state"])) {
		return fail("the lane must be merged or abandoned and not running")
	}
	if kind == "lane.gone" && n != run {
		return fail("payload.run must be the lane's latest run")
	}
	mail, hasMail := row["mail"].(map[string]any)
	based := hasMail && mail["turn_based"] == true
	if kind == "lane.mailed" {
		if !based {
			return fail("the lane is not turn-based")
		}
		if row["cleaned"] == true {
			return fail("the lane was cleaned")
		}
		if row["state"] == "abandoned" {
			return fail("the lane is abandoned")
		}
		if integral(p["sequence"]) != integral(mail["last"])+1 {
			return fail("payload.sequence must follow the lane's last")
		}
		if len(Array(mail["waiting"]))+len(Array(mail["returned"])) >= 1000 {
			return fail("the lane already holds the maximum number of queued messages")
		}
	}
	if (kind == "lane.resumed" || kind == "lane.started") && based && row["state"] == "abandoned" && (kind == "lane.resumed" || p["how"] == "resume") {
		return fail("the lane is abandoned, so no turn starts")
	}
	if kind == "lane.started" {
		if p["how"] == "reuse" && hasMail && (len(Array(mail["waiting"])) > 0 || len(Array(mail["returned"])) > 0) {
			return fail("a new life of the lane is never sent mail written for the old one")
		}
		carried, hasCarried := p["mail"]
		if hasCarried && p["how"] == "resume" {
			if !based {
				return fail("a turn resumes a turn-based lane")
			}
			queue := append(append([]any{}, Array(mail["returned"])...), Array(mail["waiting"])...)
			a := Array(carried)
			if len(a) > len(queue) || !equalValue(a, queue[:len(a)]) {
				return fail("payload.mail must be the head of the queue, returned messages then waiting ones")
			}
		} else if !hasCarried && p["how"] == "resume" && based {
			return fail("a turn-based resume must carry payload.mail")
		}
	}
	if kind == "lane.delivered" || kind == "lane.returned" {
		if running {
			return fail("no announcement is due while the lane is running")
		}
		settled := Object(mail["settled"])
		if len(settled) == 0 {
			return fail("the lane has no settled messages to announce")
		}
		if integral(settled["run"]) != run {
			return fail("the settled messages are no longer those of the latest run")
		}
		if settled["announced"] == true {
			return fail("the settled messages are already announced")
		}
		outcome := strings.TrimPrefix(kind, "lane.")
		if settled["outcome"] != outcome {
			return fail("the announcement does not match the settlement")
		}
		if integral(p["run"]) != integral(settled["run"]) || !equalValue(p["sequences"], settled["sequences"]) {
			return fail("payload.run and payload.sequences must be those of the settlement")
		}
		if kind == "lane.returned" && p["reason"] != settled["reason"] {
			return fail("payload.reason must be the settlement's reason")
		}
	}
	if kind == "lane.state" {
		if p["state"] == "waiting" {
			return fail("waiting is set only by the end of a run")
		}
		if based && p["state"] != "abandoned" {
			return fail("a turn-based lane records only abandoned with lane.state")
		}
	}
	if kind == "lane.refusal" || kind == "lane.workaround_suspected" || kind == "lane.refusal_reviewed" {
		f := refusals(row)
		recorded, suspected := Object(f["recorded"]), Object(f["suspected"])
		rid := String(p["refusal"])
		if kind != "lane.refusal_reviewed" && (n < 1 || n > run) {
			return fail("the lane has no such run")
		}
		if kind == "lane.refusal" {
			if _, ok := recorded[rid]; ok {
				return fail("the refusal is recorded already")
			}
		} else if kind == "lane.workaround_suspected" && p["refusal"] == nil {
			if _, ok := suspected[String(p["suspicion"])]; ok {
				return fail("the suspicion is recorded already")
			}
		} else {
			r, ok := recorded[rid]
			if !ok {
				return fail("the lane has no recorded refusal")
			}
			if kind == "lane.workaround_suspected" {
				if _, ok := suspected[String(p["suspicion"])]; ok {
					return fail("the suspicion is recorded already")
				}
				if n < integral(Object(r)["run"]) {
					return fail("a suspected workaround comes after its refusal")
				}
			} else {
				for _, id := range Array(p["suspicions"]) {
					item, ok := suspected[String(id)]
					m := Object(item)
					if !ok || m["refusal"] != p["refusal"] || !member(Array(m["paths"]), p["path"]) {
						return fail("a verdict must name recorded suspicions of the refusal and reviewed path")
					}
				}
			}
		}
	}
	return nil
}
func applyRefusal(row, event map[string]any) {
	f := refusals(row)
	p := Object(event["payload"])
	switch event["kind"] {
	case "lane.refusal":
		Object(f["recorded"])[String(p["refusal"])] = map[string]any{"run": p["run"], "seq": event["seq"], "guard": p["guard"], "tool": p["tool"]}
	case "lane.workaround_suspected":
		Object(f["suspected"])[String(p["suspicion"])] = map[string]any{"refusal": p["refusal"], "run": p["run"], "seq": event["seq"], "how": p["how"], "paths": p["paths"]}
	default:
		f["verdicts"] = append(Array(f["verdicts"]), map[string]any{"refusal": p["refusal"], "path": p["path"], "verdict": p["verdict"], "suspicions": p["suspicions"], "seq": event["seq"]})
	}
	type pair struct{ Refusal, Path string }
	reviewed := map[pair]bool{}
	for _, v := range Array(f["verdicts"]) {
		m := Object(v)
		for _, id := range Array(m["suspicions"]) {
			reviewed[pair{String(id), String(m["path"])}] = true
		}
	}
	open := map[pair][]string{}
	for id, v := range Object(f["suspected"]) {
		m := Object(v)
		if m["refusal"] == nil {
			continue
		}
		for _, path := range Array(m["paths"]) {
			if !reviewed[pair{id, String(path)}] {
				key := pair{String(m["refusal"]), String(path)}
				open[key] = append(open[key], id)
			}
		}
	}
	pairs := []pair{}
	for key := range open {
		pairs = append(pairs, key)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Refusal == pairs[j].Refusal {
			return pairs[i].Path < pairs[j].Path
		}
		return pairs[i].Refusal < pairs[j].Refusal
	})
	unreviewed := []any{}
	for _, key := range pairs {
		ids := open[key]
		sort.Strings(ids)
		a := []any{}
		for _, id := range ids {
			a = append(a, id)
		}
		unreviewed = append(unreviewed, map[string]any{"refusal": key.Refusal, "path": key.Path, "suspicions": a})
	}
	f["unreviewed"] = unreviewed
	row["refusals"] = f
}
func applyLane(row, event map[string]any) {
	at := event["occurred_at"]
	if at == nil {
		at = event["recorded_at"]
	}
	name := strings.TrimPrefix(String(event["kind"]), "lane.")
	p := Object(event["payload"])
	for _, key := range laneTimes {
		if name == key {
			Object(row["times"])[name] = at
		}
	}
	for _, key := range laneLanding {
		if name == key {
			Object(row["landing"])[name] = at
		}
	}
	var state any
	switch name {
	case "state":
		state = p["state"]
	case "planned":
		state = "queued"
	case "started":
		state = "running"
	case "ended", "lost", "gone":
		state = "verifying"
	case "adopted":
		state = "waiting"
	}
	mail, hasMail := row["mail"].(map[string]any)
	closing := name == "ended" || name == "lost" || name == "gone"
	if closing && hasMail {
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
		if name == "adopted" {
			row["run"] = int64(1)
		}
		row["running"] = name == "started"
		row["reason"] = nil
		row["exit_code"] = nil
		row["cleaned"] = false
		for _, k := range []string{"runner", "model", "effort", "account", "worktree", "branch"} {
			row[k] = p[k]
		}
		if name == "adopted" {
			row["mail"] = emptyMail(true, p["idle_seconds"])
		} else if carried, ok := p["mail"]; ok {
			if !hasMail {
				mail = emptyMail(false, nil)
				row["mail"] = mail
			}
			mail["turn_based"] = true
			mail["idle_seconds"] = p["idle_seconds"]
			a := Array(carried)
			for _, key := range []string{"waiting", "returned"} {
				remaining := []any{}
				for _, n := range Array(mail[key]) {
					if !member(a, n) {
						remaining = append(remaining, n)
					}
				}
				mail[key] = remaining
			}
			if len(a) > 0 {
				mail["in_flight"] = map[string]any{"run": p["run"], "sequences": append([]any{}, a...)}
			} else {
				mail["in_flight"] = nil
			}
		} else if hasMail {
			mail["turn_based"] = false
		}
	}
	if name == "resumed" {
		row["resumes"] = integral(row["resumes"]) + 1
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
		row["lost"] = integral(row["lost"]) + 1
	}
	if name == "gone" {
		row["running"] = false
	}
	if name == "cleaned" {
		row["cleaned"] = true
	}
	if name == "mailed" {
		mail["last"] = p["sequence"]
		mail["waiting"] = append(Array(mail["waiting"]), p["sequence"])
	}
	if closing && hasMail {
		flight := Object(mail["in_flight"])
		if len(flight) > 0 && integral(flight["run"]) == integral(p["run"]) {
			outcome := "returned"
			var reason any
			reason = name
			if name == "ended" {
				if p["reason"] == "exit" && integral(p["exit_code"]) == 0 && p["exit_code"] != nil {
					if Object(p["prompt"])["state"] == "written" {
						outcome = "delivered"
						reason = nil
					} else {
						reason = "cut"
					}
				} else {
					reason = p["reason"]
				}
			}
			mail["in_flight"] = nil
			sequences := Array(flight["sequences"])
			if outcome == "delivered" {
				mail["delivered"] = integral(mail["delivered"]) + int64(len(sequences))
			} else {
				all := append(append([]any{}, Array(mail["returned"])...), sequences...)
				sort.Slice(all, func(i, j int) bool { return integral(all[i]) < integral(all[j]) })
				unique := []any{}
				for _, n := range all {
					if len(unique) == 0 || integral(n) != integral(unique[len(unique)-1]) {
						unique = append(unique, n)
					}
				}
				mail["returned"] = unique
			}
			mail["settled"] = map[string]any{"run": flight["run"], "outcome": outcome, "reason": reason, "sequences": append([]any{}, sequences...), "announced": false}
		}
	}
	if name == "delivered" || name == "returned" {
		Object(mail["settled"])["announced"] = true
	}
	if name == "refusal" || name == "workaround_suspected" || name == "refusal_reviewed" {
		applyRefusal(row, event)
	}
	row["events"] = integral(row["events"]) + 1
	row["last_seq"] = event["seq"]
}
func verifyProjections(q sqlReader, events []map[string]any) error {
	computed := map[string]any{}
	resources := map[string]*resourceRecord{}
	for _, event := range events {
		kind := String(event["kind"])
		lane := String(event["lane"])
		row := Object(computed[lane])
		if strings.HasPrefix(kind, "resource.") {
			if err := replayResource(row, resources, event); err != nil {
				return Integrity("event seq %d: %s", integral(event["seq"]), err.Error())
			}
			continue
		}
		if !strings.HasPrefix(kind, "lane.") {
			continue
		}
		if len(row) == 0 {
			row = emptyLane(lane)
			computed[lane] = row
		}
		if err := checkTransition(row, event); err != nil {
			return Integrity("event seq %d: %s", integral(event["seq"]), err.Error())
		}
		if kind == "lane.state" && versionAtLeast(String(event["protocol_version"]), 1, 3, 0) {
			p := Object(event["payload"])
			if p["state"] == "accepted" || p["state"] == "merged" {
				held := holding(resources, lane)
				given := p["held"]
				if given == nil {
					given = []any{}
				}
				if !equalValue(given, held) {
					return Integrity("event seq %d: lane.state payload.held must list exactly the resources the lane holds", integral(event["seq"]))
				}
			}
		}
		applyLane(row, event)
	}
	rows, err := q.Query("SELECT lane, projection FROM lanes ORDER BY lane")
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var lane, projection string
		if err := rows.Scan(&lane, &projection); err != nil {
			return err
		}
		expected, ok := computed[lane]
		if !ok {
			return Integrity("the stored lane projection does not match the events; run state rebuild")
		}
		canonical, err := Canonical(expected)
		if err != nil {
			return err
		}
		if string(canonical) != projection {
			return Integrity("the stored lane projection does not match the events; run state rebuild")
		}
		seen[lane] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(computed) {
		return Integrity("the stored lane projection does not match the events; run state rebuild")
	}
	return nil
}
