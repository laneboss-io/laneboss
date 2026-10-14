package laneturns

import (
	"os"
	"sort"
	"time"
)

func validScanCoverage(v object, launch string) bool {
	if v == nil || integer(v["format"]) != 1 || v["launch"] != launch || str(v["lane"]) == "" || !isWhole(v["run"]) {
		return false
	}
	for _, key := range []string{"complete", "configured", "covered"} {
		if _, ok := v[key].(bool); !ok {
			return false
		}
	}
	for _, key := range []string{"scanned_at", "by"} {
		if v[key] != nil {
			if _, ok := v[key].(string); !ok {
				return false
			}
		}
	}
	if obj(v["skipped"]) == nil {
		return false
	}
	for _, value := range obj(v["skipped"]) {
		if !isWhole(value) {
			return false
		}
	}
	for _, key := range []string{"not_covered", "records", "inventory"} {
		if !isArray(v[key]) {
			return false
		}
		for _, value := range array(v[key]) {
			p := obj(value)
			if p == nil {
				return false
			}
			if key == "not_covered" {
				if str(p["reason"]) == "" {
					return false
				}
				if p["path"] != nil {
					if _, ok := p["path"].(string); !ok {
						return false
					}
				}
			} else {
				if str(p["path"]) == "" || str(p["state"]) == "" {
					return false
				}
				if key == "inventory" {
					if !boundedInteger(p["seen"], 0, 1<<62) {
						return false
					}
					for _, field := range []string{"shown", "format", "first", "tail"} {
						if p[field] != nil {
							if _, ok := p[field].(string); !ok {
								return false
							}
						}
					}
				}
			}
		}
	}
	return true
}
func (s *laneScan) coverage(run *scanRun, complete bool) object {
	runner := obj(obj(s.s.c.data["runners"])[run.runner])
	configured := len(s.guards) > 0 && len(array(runner["records"])) > 0
	result := object{"format": 1, "lane": s.lane, "run": run.run, "launch": run.launch, "scanned_at": nowStamp(), "by": "supervising process", "complete": complete, "configured": configured, "covered": false, "records": []any{}, "skipped": object{"other_directory": 0, "before_run": 0}, "not_covered": []any{}, "inventory": []any{}}
	if !configured {
		return result
	}
	reasons := append([]object{}, s.problems[run.run]...)
	records, inventory := []any{}, []any{}
	listed := map[string]bool{}
	for _, r := range s.recordOrder {
		counts := r.counts[run.run]
		if r.foreign || counts == nil && r.other[run.run] {
			if r.other[run.run] {
				obj(result["skipped"])["other_directory"] = integer(obj(result["skipped"])["other_directory"]) + 1
			}
			continue
		}
		state := r.state
		if state == "covered" && r.partly {
			state = "partly-read"
		}
		if state == "covered" && complete && r.finished && r.format == "claude-code" && (r.incomplete || !r.recognised || r.cwd == "") {
			state = "unrecognised"
			if r.incomplete {
				state = "partly-read"
			}
		}
		owned := r.run
		if owned == 0 {
			owned = s.runNumber(r.mtime)
		}
		if counts == nil && !r.launches[run.launch] && (state == "covered" || owned != run.run) {
			continue
		}
		if counts == nil {
			counts = object{}
			for _, key := range scanCountKeys {
				counts[key] = 0
			}
		}
		outside := integer(counts["outside_runs"]) > 0 && integer(counts["lines"]) == 0 && integer(counts["oversized"]) == 0 && r.state == "covered" && !r.launches[run.launch]
		row := copyObject(counts)
		row["path"] = safeScanPath(r.shown)
		row["format"] = r.format
		row["state"] = state
		if outside {
			row["state"] = "outside"
		}
		records = append(records, row)
		listed[str(row["path"])] = true
		if outside {
			continue
		}
		if integer(counts["oversized"]) > 0 {
			reasons = append(reasons, object{"reason": "oversized-line", "path": safeScanPath(r.shown)})
		}
		if integer(counts["timed_out"]) > 0 {
			reasons = append(reasons, object{"reason": "timed-out", "path": safeScanPath(r.shown)})
		}
		inventory = append(inventory, object{"path": r.path, "shown": safeScanPath(r.shown), "format": r.format, "first": nilIfEmpty(r.first), "seen": r.seen, "tail": nilIfEmpty(r.tail), "state": state})
	}
	for path := range s.found[run.run] {
		if listed[safeScanPath(path)] {
			continue
		}
		_, old := s.before[path]
		r := s.records[path]
		if old || r != nil && r.mtime.Before(run.start.Add(-2*time.Second)) {
			obj(result["skipped"])["before_run"] = integer(obj(result["skipped"])["before_run"]) + 1
		}
	}
	for _, entry := range array(runner["records"]) {
		for _, template := range texts(obj(entry)["paths"]) {
			failed := false
			for _, why := range reasons {
				if why["path"] == template {
					failed = true
				}
			}
			if failed {
				continue
			}
			belongs := false
			for _, r := range s.recordOrder {
				if !contains(r.templates[run.run], template) {
					continue
				}
				if r.format == "text" && r.run == run.run || r.format != "text" && integer(r.counts[run.run]["lines"]) > 0 {
					belongs = true
					break
				}
			}
			if !belongs {
				reasons = append(reasons, object{"reason": "no-record", "path": template})
			}
		}
	}
	if !complete {
		why := "running"
		if run.ended {
			why = "not-scanned-to-its-end"
		}
		reasons = append(reasons, object{"reason": why})
	}
	sort.Slice(records, func(i, j int) bool { return str(obj(records[i])["path"]) < str(obj(records[j])["path"]) })
	result["records"] = records
	result["inventory"] = inventory
	result["not_covered"] = reasons
	return result
}
func mergeScanCoverage(old, new object) object {
	entries := map[string]object{}
	for _, value := range array(old["inventory"]) {
		entry := copyObject(obj(value))
		entries[str(entry["path"])] = entry
	}
	for _, value := range array(new["inventory"]) {
		entry := obj(value)
		before := entries[str(entry["path"])]
		state := str(before["state"])
		if state == "" {
			state = "covered"
		}
		if state == "covered" && (before["first"] != nil && entry["first"] != nil && before["first"] != entry["first"] || number(before["seen"]) == number(entry["seen"]) && before["tail"] != nil && entry["tail"] != nil && before["tail"] != entry["tail"]) {
			state = "replaced"
		}
		latest := entry
		if number(before["seen"]) > number(entry["seen"]) {
			latest = before
		}
		combined := copyObject(entry)
		combined["seen"] = latest["seen"]
		combined["tail"] = latest["tail"]
		if state != "covered" {
			combined["state"] = state
		}
		entries[str(entry["path"])] = combined
	}
	states := map[string]string{}
	for _, entry := range entries {
		if entry["state"] == "covered" && entry["format"] != "text" {
			info, err := os.Stat(str(entry["path"]))
			if os.IsNotExist(err) {
				entry["state"] = "missing"
			} else if err != nil {
				entry["state"] = "unreadable"
			} else if info.Size() < int64(number(entry["seen"])) {
				entry["state"] = "replaced"
			}
		}
		if entry["state"] != "covered" {
			states[str(entry["shown"])] = str(entry["state"])
		}
	}
	reasons := []any{}
	keys := map[string]bool{}
	for _, value := range array(new["not_covered"]) {
		p := obj(value)
		data, _ := canonical(p)
		key := string(data)
		if !keys[key] {
			keys[key] = true
			reasons = append(reasons, p)
		}
	}
	for path, state := range states {
		p := object{"reason": state, "path": path}
		data, _ := canonical(p)
		key := string(data)
		if !keys[key] {
			keys[key] = true
			reasons = append(reasons, p)
		}
	}
	sort.Slice(reasons, func(i, j int) bool {
		a, b := obj(reasons[i]), obj(reasons[j])
		if a["reason"] != b["reason"] {
			return str(a["reason"]) < str(b["reason"])
		}
		return str(a["path"]) < str(b["path"])
	})
	inventory := []any{}
	paths := []string{}
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		inventory = append(inventory, entries[path])
	}
	records := []any{}
	for _, value := range array(new["records"]) {
		r := copyObject(obj(value))
		if state, ok := states[str(r["path"])]; ok {
			r["state"] = state
		}
		records = append(records, r)
	}
	result := copyObject(new)
	result["inventory"] = inventory
	result["records"] = records
	result["not_covered"] = reasons
	result["covered"] = flag(new["configured"]) && flag(new["complete"]) && len(reasons) == 0
	return result
}
func (s *laneScan) save(complete bool) error {
	dir, err := s.s.state.dir("lanes/"+s.lane, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := lockRoot(dir, ".", 60, "lane directory lock", false, false)
	if err != nil {
		return err
	}
	defer lock.close()
	scans, err := s.s.state.dir("lanes/"+s.lane+"/scans", true)
	if err != nil {
		return err
	}
	defer scans.Close()
	for _, run := range s.runs {
		coverage := s.coverage(run, run.ended && (complete || run.run != s.runs[len(s.runs)-1].run))
		data, err := readAt(scans, run.launch+".json", "the scan record", 16*1024*1024)
		var old object
		if err == nil {
			old, err = decodeJSON(data)
			if err != nil || !validScanCoverage(old, run.launch) {
				return integrity("the kept scan coverage is unreadable; it was not overwritten")
			}
		} else if !os.IsNotExist(err) {
			return integrity("the kept scan coverage cannot be read; it was not overwritten")
		}
		coverage = mergeScanCoverage(old, coverage)
		encoded, err := canonical(coverage)
		if err != nil {
			return err
		}
		if err = writeAtomic(scans, run.launch+".json", append(encoded, '\n'), 0600, true); err != nil {
			return err
		}
	}
	return nil
}
