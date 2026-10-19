package lane

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

func validCoverage(m object, launch string) bool {
	if m == nil || integer(m["format"]) != 1 || str(m["launch"]) != launch || str(m["lane"]) == "" || !whole(m["run"], 1, 1000000) {
		return false
	}
	for _, k := range []string{"complete", "configured", "covered"} {
		if _, ok := m[k].(bool); !ok {
			return false
		}
	}
	if flag(m["covered"]) && (!flag(m["complete"]) || !flag(m["configured"]) || len(list(m["not_covered"])) != 0) {
		return false
	}
	for _, key := range []string{"scanned_at", "by"} {
		if value := m[key]; value != nil {
			if _, ok := value.(string); !ok {
				return false
			}
		}
	}
	if skipped := obj(m["skipped"]); skipped == nil {
		return false
	} else {
		for _, value := range skipped {
			if !whole(value, 0, 1<<62) {
				return false
			}
		}
	}
	for _, k := range []string{"not_covered", "records", "inventory"} {
		if list(m[k]) == nil {
			return false
		}
		for _, v := range list(m[k]) {
			row := obj(v)
			if row == nil {
				return false
			}
			if k == "not_covered" {
				if str(row["reason"]) == "" {
					return false
				}
				if value := row["path"]; value != nil {
					if _, ok := value.(string); !ok {
						return false
					}
				}
			} else {
				state := str(row["state"])
				if str(row["path"]) == "" || !contains(strings.Fields("covered unreadable unrecognised partly-read missing replaced refused-zone truncated outside"), state) || k == "inventory" && state == "outside" {
					return false
				}
				if flag(m["covered"]) && state != "covered" && state != "outside" {
					return false
				}
			}
			if k == "inventory" && !whole(row["seen"], 0, 1<<62) {
				return false
			}
			if k == "inventory" {
				for _, field := range []string{"shown", "format", "first", "tail"} {
					if value := row[field]; value != nil {
						if _, ok := value.(string); !ok {
							return false
						}
					}
				}
			}
		}
	}
	inventoryStates := map[string]string{}
	for _, value := range list(m["inventory"]) {
		entry := obj(value)
		shown := str(entry["shown"])
		if shown == "" {
			shown = safePath(str(entry["path"]))
		}
		inventoryStates[shown] = str(entry["state"])
	}
	for _, value := range list(m["records"]) {
		entry := obj(value)
		if str(entry["state"]) != "outside" && inventoryStates[str(entry["path"])] != str(entry["state"]) {
			return false
		}
	}
	return obj(m["skipped"]) != nil
}
func (s *session) readCoverage(lane, launch string) (object, bool, error) {
	r, err := s.laneRoot(lane, false)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	b, err := rootRead(r, "scans/"+launch+".json", 16*1024*1024)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, nil
	}
	v, err := parseJSON(b)
	if err != nil || !validCoverage(obj(v), launch) {
		return nil, true, nil
	}
	return obj(v), false, nil
}
func (scan *refusalScan) coverage(run *scanRun) object {
	complete := run.ended
	result := object{"format": 1, "lane": scan.lane, "run": run.number, "launch": run.launch, "scanned_at": utcNow(), "by": scan.by, "complete": complete, "configured": configured(scan.s.c, run.runner), "covered": false, "records": []any{}, "skipped": object{"other_directory": 0, "before_run": 0}, "not_covered": []any{}, "inventory": []any{}}
	if !flag(result["configured"]) {
		return result
	}
	reasons := append([]any{}, scan.problems[run.number]...)
	records, inventory := []any{}, []any{}
	belongs := map[string]bool{}
	for _, record := range scan.records {
		if record.format == "text" && record.run != run.number {
			continue
		}
		counts := record.counts[run.number]
		if record.foreign || (counts == nil && record.otherDirectory[run.number]) {
			if record.otherDirectory[run.number] {
				obj(result["skipped"])["other_directory"] = integer(obj(result["skipped"])["other_directory"]) + 1
			}
			continue
		}
		state := record.state
		if state == "covered" && record.partial {
			state = "partly-read"
		}
		if state == "covered" && complete && record.finished && record.format != "text" && (record.incomplete || !record.recognised || record.cwd == "") {
			if record.incomplete {
				state = "partly-read"
			} else {
				state = "unrecognised"
			}
		}
		owned := record.run
		if owned == 0 {
			if owner := scan.runOf(record.mtime, true); owner != nil {
				owned = owner.number
			}
		}
		priorLaunch := scan.inventoryByRun[run.number][record.path] != nil
		if counts == nil && !priorLaunch && (state == "covered" || owned != run.number) {
			continue
		}
		if counts == nil {
			counts = object{}
			for _, k := range recordCountNames {
				counts[k] = 0
			}
		}
		outside := integer(counts["outside_runs"]) > 0 && integer(counts["lines"]) == 0 && integer(counts["oversized"]) == 0 && record.state == "covered" && !priorLaunch
		row := clone(counts)
		row["path"] = safePath(record.shown)
		row["format"] = record.format
		row["state"] = state
		if outside {
			row["state"] = "outside"
		}
		records = append(records, row)
		if outside {
			continue
		}
		if integer(counts["oversized"]) > 0 {
			reasons = append(reasons, object{"reason": "oversized-line", "path": safePath(record.shown)})
		}
		if integer(counts["timed_out"]) > 0 {
			reasons = append(reasons, object{"reason": "timed-out", "path": safePath(record.shown)})
		}
		inventory = append(inventory, object{"path": record.path, "shown": safePath(record.shown), "format": record.format, "first": record.first, "seen": record.seen, "tail": record.tail, "state": state})
		for _, template := range record.templates[run.number] {
			if record.format == "text" && record.run == run.number || record.format != "text" && integer(counts["lines"]) > 0 {
				belongs[template] = true
			}
		}
	}
	listed := map[string]bool{}
	for _, v := range records {
		listed[str(obj(v)["path"])] = true
	}
	for path := range scan.foundPaths[run.number] {
		if !listed[safePath(path)] && scan.before[path] {
			obj(result["skipped"])["before_run"] = integer(obj(result["skipped"])["before_run"]) + 1
		}
	}
	if run.ran {
		runner := obj(obj(scan.s.c.data["runners"])[run.runner])
		for _, entry := range list(runner["records"]) {
			for _, template := range stringsOf(obj(entry)["paths"]) {
				problem := false
				for _, why := range reasons {
					if str(obj(why)["path"]) == template {
						problem = true
						break
					}
				}
				if !problem && !belongs[template] {
					reasons = append(reasons, object{"reason": "no-record", "path": template})
				}
			}
		}
	}
	if !complete {
		reason := "running"
		if run.ended {
			reason = "not-scanned-to-its-end"
		}
		reasons = append(reasons, object{"reason": reason})
	}
	sort.Slice(records, func(i, j int) bool { return str(obj(records[i])["path"]) < str(obj(records[j])["path"]) })
	result["records"] = records
	result["inventory"] = inventory
	result["not_covered"] = reasons
	return result
}
func mergeCoverage(old, next object) object {
	entries := map[string]object{}
	for _, v := range list(old["inventory"]) {
		m := obj(v)
		entries[str(m["path"])] = clone(m)
	}
	for _, v := range list(next["inventory"]) {
		entry := obj(v)
		path := str(entry["path"])
		before := entries[path]
		state := "covered"
		if before != nil {
			state = str(before["state"])
			if state == "covered" && ((before["first"] != nil && entry["first"] != nil && before["first"] != entry["first"]) || (number(before["seen"]) == number(entry["seen"]) && before["tail"] != nil && entry["tail"] != nil && before["tail"] != entry["tail"])) {
				state = "replaced"
			}
		}
		later := entry
		if before != nil && number(before["seen"]) > number(entry["seen"]) {
			later = before
		}
		kept := clone(entry)
		kept["seen"] = later["seen"]
		kept["tail"] = later["tail"]
		if state != "covered" {
			kept["state"] = state
		}
		entries[path] = kept
	}
	states := map[string]string{}
	reasons := append([]any{}, list(next["not_covered"])...)
	paths := []string{}
	for path, entry := range entries {
		if str(entry["state"]) == "covered" && str(entry["format"]) != "text" {
			info, err := os.Stat(path)
			if os.IsNotExist(err) {
				entry["state"] = "missing"
			} else if err != nil {
				entry["state"] = "unreadable"
			} else if info.Size() < int64(number(entry["seen"])) {
				entry["state"] = "replaced"
			}
		}
		if str(entry["state"]) != "covered" {
			shown := str(entry["shown"])
			if shown == "" {
				shown = safePath(path)
			}
			states[shown] = str(entry["state"])
			reasons = append(reasons, object{"reason": entry["state"], "path": shown})
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	inventory := []any{}
	for _, path := range paths {
		inventory = append(inventory, entries[path])
	}
	reasonMap := map[string]any{}
	for _, v := range reasons {
		reasonMap[string(canonical(v))] = v
	}
	reasons = []any{}
	for _, v := range reasonMap {
		reasons = append(reasons, v)
	}
	for _, v := range list(next["records"]) {
		m := obj(v)
		if state := states[str(m["path"])]; state != "" {
			m["state"] = state
		}
		// A row's bad state is itself evidence of an incomplete scan, even if
		// its inventory was omitted. Never derive success from empty reasons.
		state := str(m["state"])
		if state != "covered" && state != "outside" {
			if state == "" {
				state = "coverage-unreadable"
			}
			why := object{"reason": state, "path": m["path"]}
			key := string(canonical(why))
			if reasonMap[key] == nil {
				reasons = append(reasons, why)
				reasonMap[key] = why
			}
		}
	}
	sort.Slice(reasons, func(i, j int) bool {
		a, b := obj(reasons[i]), obj(reasons[j])
		if a["reason"] != b["reason"] {
			return str(a["reason"]) < str(b["reason"])
		}
		return str(a["path"]) < str(b["path"])
	})
	next["inventory"] = inventory
	next["not_covered"] = reasons
	next["covered"] = flag(next["configured"]) && flag(next["complete"]) && len(reasons) == 0
	return next
}
func (s *session) writeCoverage(lane string, coverage object) (object, error) {
	root, unlock, err := s.laneLock(lane, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	old, bad, err := s.readCoverage(lane, str(coverage["launch"]))
	if err != nil {
		return nil, err
	}
	merged := mergeCoverage(old, coverage)
	if bad {
		merged["covered"] = false
		merged["not_covered"] = append(list(merged["not_covered"]), object{"reason": "coverage-unreadable", "path": safePath(s.lanePath(lane, "scans", str(coverage["launch"])+".json"))})
		return merged, nil
	}
	if err = rootWrite(root, "scans/"+str(coverage["launch"])+".json", append(canonical(merged), '\n'), true, 0600); err != nil {
		return nil, err
	}
	return merged, nil
}
func shownCoverage(m object) object { m = clone(m); delete(m, "inventory"); return m }
func flattenCoverage(coverages []any) []any {
	found := []any{}
	for _, v := range coverages {
		coverage := obj(v)
		for _, item := range list(coverage["not_covered"]) {
			why := obj(item)
			found = append(found, object{"run": coverage["run"], "reason": why["reason"], "path": why["path"]})
		}
	}
	return found
}
func (s *session) scanLane(lane, by string, final bool, emit func(object) error) (object, error) {
	scan, err := newScan(s, lane, by, final, emit)
	if err != nil {
		return nil, err
	}
	if err = scan.read(); err != nil {
		return nil, err
	}
	coverages := []any{}
	for _, run := range scan.runs {
		kept, err := s.writeCoverage(lane, scan.coverage(run))
		if err != nil {
			return nil, err
		}
		coverages = append(coverages, shownCoverage(kept))
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	row, err := s.row(lane)
	if err != nil {
		return nil, err
	}
	found := refusalState(row)
	pending, err := s.pendingCount(lane)
	if err != nil {
		return nil, err
	}
	return object{"lane": lane, "appended": scan.appended, "refused_events": scan.refusedEvents, "recorded": object{"refusals": len(obj(found["recorded"])), "suspicions": len(obj(found["suspected"]))}, "unreviewed": found["unreviewed"], "runs": coverages, "not_covered": flattenCoverage(coverages), "pending_events": pending}, nil
}
func (s *session) scan(a arguments) (any, error) {
	lane := a.get("lane")
	if _, err := s.known(lane); err != nil {
		return nil, err
	}
	if err := s.drain(lane); err != nil {
		return nil, err
	}
	return s.scanLane(lane, "lane scan", true, nil)
}
func (s *session) gate(lane string, acceptUncovered bool) (any, error) {
	if !configured(s.c, "") {
		if acceptUncovered {
			return nil, refuse("--accept-uncovered: configuration has no guards, so nothing is scanned")
		}
		return nil, nil
	}
	if err := s.refuseScanSurvivors(lane); err != nil {
		return nil, err
	}
	scanned, err := s.scanLane(lane, "lane mark", true, nil)
	if err != nil {
		return nil, err
	}
	if integer(scanned["refused_events"]) > 0 {
		return nil, refuse("the store refused refusal or suspicion events (kept in refused.jsonl), so its refusals cannot be checked; nothing was recorded")
	}
	if integer(scanned["pending_events"]) > 0 {
		return nil, refuse("lane has events waiting to be recorded; lane check records them first")
	}
	if len(list(scanned["unreviewed"])) > 0 {
		lines := []string{}
		for _, v := range list(scanned["unreviewed"]) {
			m := obj(v)
			lines = append(lines, fmt.Sprintf("refusal %s path %s (suspicion %s)", str(m["refusal"]), str(m["path"]), strings.Join(stringsOf(m["suspicions"]), ", ")))
		}
		return nil, refuse("lane %s has suspected workarounds without a verdict; review each path with lane review --refusal ID --path PATH --verdict clean|workaround:\n%s", lane, strings.Join(lines, "\n"))
	}
	// Absence of a reason is not proof of coverage. Require the completed
	// result for every configured launch, using the run registry rather than
	// trusting a missing or partial scan result to describe its own omissions.
	runs, err := s.scanRuns(lane)
	if err != nil {
		return nil, err
	}
	byLaunch := map[string]object{}
	for _, value := range list(scanned["runs"]) {
		coverage := obj(value)
		byLaunch[str(coverage["launch"])] = coverage
	}
	for _, run := range runs {
		if !configured(s.c, run.runner) {
			continue
		}
		coverage := byLaunch[run.launch]
		if coverage != nil && flag(coverage["complete"]) && flag(coverage["configured"]) && flag(coverage["covered"]) {
			continue
		}
		if len(list(coverage["not_covered"])) == 0 {
			scanned["not_covered"] = append(list(scanned["not_covered"]), object{"run": run.number, "reason": "coverage-incomplete", "path": nil})
		}
	}
	if len(list(scanned["not_covered"])) > 0 && !acceptUncovered {
		lines := []string{}
		for _, v := range list(scanned["not_covered"]) {
			m := obj(v)
			lines = append(lines, fmt.Sprintf("run %d %s %s", integer(m["run"]), str(m["reason"]), str(m["path"])))
		}
		return nil, refuse("lane %s's session records were not all scanned, so a refusal may be missing; make them readable and mark again, or pass --accept-uncovered:\n%s", lane, strings.Join(lines, "\n"))
	}
	return object{"appended": scanned["appended"], "not_covered": scanned["not_covered"]}, nil
}
func (s *session) refuseScanSurvivors(lane string) error {
	p, record, err := s.latest(lane)
	if err != nil {
		return err
	}
	if p != nil && p["launch"] != nil && record == nil {
		ended, e := s.last(lane, "lane.ended")
		if e != nil {
			return e
		}
		gone, e := s.last(lane, "lane.gone")
		if e != nil {
			return e
		}
		if !(ended != nil && integer(obj(ended["payload"])["run"]) == integer(p["run"]) && integer(obj(ended["payload"])["survivors"]) == 0 || gone != nil && integer(obj(gone["payload"])["run"]) == integer(p["run"])) {
			return refuse("the run has no record and no end showing its processes are gone, so its records cannot be scanned to their end; restore the record, or lane mark --gone")
		}
	}
	records, err := s.everyRecord(lane)
	if err != nil {
		return err
	}
	events, err := s.laneEvents(lane, "lane.ended", "lane.lost", "lane.gone")
	if err != nil {
		return err
	}
	closed := map[int]bool{}
	for _, e := range events {
		closed[integer(obj(e["payload"])["run"])] = true
	}
	table, err := processSnapshot()
	if err != nil {
		return err
	}
	for _, r := range records {
		alive, e := recordAlive(r, table)
		if e != nil {
			return e
		}
		if alive && !closed[integer(r["run"])] {
			return refuse("a run of lane %s is alive, so its records are not complete", lane)
		}
		survivors, e := recordSurvivors(r, table)
		if e != nil {
			return e
		}
		if len(survivors) > 0 {
			return refuse("%d processes of lane %s's run survive, so its records may still grow; lane stop removes them", len(survivors), lane)
		}
	}
	return nil
}
func (s *session) refusalListing(lane string) (object, error) {
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	found := refusalState(row)
	events, err := s.laneEvents(lane, "lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed")
	if err != nil {
		return nil, err
	}
	refusals, suspicions, observations, verdicts := []any{}, []any{}, []any{}, []any{}
	for _, e := range events {
		p := clone(obj(e["payload"]))
		p["seq"] = e["seq"]
		switch str(e["kind"]) {
		case "lane.refusal":
			refusals = append(refusals, p)
		case "lane.workaround_suspected":
			if p["refusal"] == nil {
				observations = append(observations, p)
			} else {
				suspicions = append(suspicions, p)
			}
		case "lane.refusal_reviewed":
			p["actor"] = e["actor"]
			p["occurred_at"] = e["occurred_at"]
			verdicts = append(verdicts, p)
		}
	}
	latest := map[string]any{}
	for _, v := range verdicts {
		m := obj(v)
		for _, id := range stringsOf(m["suspicions"]) {
			latest[id+"\x00"+str(m["path"])] = m["verdict"]
		}
	}
	for _, v := range suspicions {
		m := obj(v)
		reviewed := object{}
		for _, path := range stringsOf(m["paths"]) {
			reviewed[path] = latest[str(m["suspicion"])+"\x00"+path]
		}
		m["reviewed"] = reviewed
	}
	for _, v := range refusals {
		m := obj(v)
		ids := []string{}
		for _, entry := range suspicions {
			if obj(entry)["refusal"] == m["refusal"] {
				ids = append(ids, str(obj(entry)["suspicion"]))
			}
		}
		m["suspicions"] = ids
	}
	runs, err := s.scanRuns(lane)
	if err != nil {
		return nil, err
	}
	coverages := []any{}
	for _, run := range runs {
		coverage, bad, e := s.readCoverage(lane, run.launch)
		if e != nil {
			return nil, e
		}
		if coverage == nil {
			configuredRun := configured(s.c, run.runner)
			coverage = object{"format": 1, "lane": lane, "run": run.number, "launch": run.launch, "scanned_at": nil, "by": nil, "complete": false, "configured": configuredRun, "covered": false, "records": []any{}, "skipped": object{"other_directory": 0, "before_run": 0}, "not_covered": []any{}}
			if bad {
				coverage["not_covered"] = []any{object{"reason": "coverage-unreadable", "path": safePath(s.lanePath(lane, "scans", run.launch+".json"))}}
			} else if configuredRun {
				coverage["not_covered"] = []any{object{"reason": "not-scanned"}}
			}
		}
		coverages = append(coverages, shownCoverage(coverage))
	}
	pending, err := s.pendingCount(lane)
	if err != nil {
		return nil, err
	}
	return object{"lane": lane, "guards": len(list(s.c.data["guards"])), "refusals": refusals, "suspicions": suspicions, "observations": observations, "observation_count": len(observations), "verdicts": verdicts, "unreviewed": found["unreviewed"], "coverage": coverages, "not_covered": flattenCoverage(coverages), "pending_events": pending}, nil
}
func (s *session) refusals(a arguments) (any, error) {
	if a.get("lane") != "" {
		return s.refusalListing(a.get("lane"))
	}
	rows, err := s.rows()
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, row := range rows {
		listing, err := s.refusalListing(str(row["lane"]))
		if err != nil {
			return nil, err
		}
		result = append(result, listing)
	}
	return result, nil
}
