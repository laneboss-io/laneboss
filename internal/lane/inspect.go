package lane

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
)

func (s *session) selectedRows(lane string) ([]object, error) {
	if lane != "" {
		row, err := s.known(lane)
		if err != nil {
			return nil, err
		}
		return []object{row}, nil
	}
	return s.rows()
}
func (s *session) status(a arguments) (any, error) {
	rows, err := s.selectedRows(a.get("lane"))
	if err != nil {
		return nil, err
	}
	table, err := processSnapshot()
	if err != nil {
		return nil, err
	}
	sessions := map[string][]string{}
	result := []any{}
	for _, row := range rows {
		lane := str(row["lane"])
		pending, err := s.pendingCount(lane)
		if err != nil {
			return nil, err
		}
		refused, err := s.refusedCount(lane)
		if err != nil {
			return nil, err
		}
		live := object{"launch": nil, "session": nil, "session_alive": nil, "supervisor": nil, "survivors": nil, "stopping": nil, "pending_events": pending, "refused_events": refused, "running_seconds": nil, "budget_left_seconds": nil, "quiet_seconds": nil, "log_bytes": nil}
		event, err := s.last(lane, "lane.started")
		if err != nil {
			return nil, err
		}
		if event != nil {
			p := obj(event["payload"])
			record, err := s.readRecord(lane, str(p["launch"]))
			if err != nil {
				return nil, err
			}
			socket := str(obj(p["session"])["socket"])
			listed, ok := sessions[socket]
			if !ok {
				listed, err = tmuxSessions(socket)
				if err != nil {
					return nil, err
				}
				sessions[socket] = listed
			}
			live["launch"] = p["launch"]
			live["session"] = p["session"]
			live["session_alive"] = contains(listed, str(obj(p["session"])["name"]))
			left, err := recordSurvivors(record, table)
			if err != nil {
				return nil, err
			}
			live["survivors"] = len(left)
			if record != nil && validIdentity(record["supervisor"]) {
				alive, e := recordAlive(record, table)
				if e != nil {
					return nil, e
				}
				live["supervisor"] = object{"pid": obj(record["supervisor"])["pid"], "alive": alive}
				if alive {
					live["survivors"] = 0
					live["stopping"] = record["stopping"]
				}
			}
			var info os.FileInfo
			root, err := s.laneRoot(lane, false)
			if err == nil {
				info, err = root.Lstat("output.log")
				root.Close()
				if err != nil && !os.IsNotExist(err) {
					return nil, err
				}
				if info != nil {
					if !info.Mode().IsRegular() {
						return nil, refuse("the lane's output log is a symbolic link or not a regular file")
					}
					live["log_bytes"] = info.Size()
				}
			} else if !os.IsNotExist(err) {
				return nil, err
			}
			if flag(row["running"]) {
				at := str(event["occurred_at"])
				if at == "" {
					at = str(event["recorded_at"])
				}
				began, e := time.Parse(time.RFC3339Nano, at)
				if e != nil {
					return nil, integrity("the run's start time is invalid")
				}
				elapsed := time.Since(began).Seconds()
				running := elapsed
				if running < 0 {
					running = 0
				}
				live["running_seconds"] = rounded(running)
				live["budget_left_seconds"] = rounded(number(p["budget_minutes"])*60 - elapsed)
				growth := began
				if info != nil && info.ModTime().After(growth) {
					growth = info.ModTime()
				}
				quiet := time.Since(growth).Seconds()
				if quiet < 0 {
					quiet = 0
				}
				live["quiet_seconds"] = rounded(quiet)
			}
		}
		previous, _, err := s.latest(lane)
		if err != nil {
			return nil, err
		}
		ended, err := s.last(lane, "lane.ended")
		if err != nil {
			return nil, err
		}
		var fate any
		if ended != nil && event != nil && integer(obj(ended["payload"])["run"]) == integer(obj(event["payload"])["run"]) {
			fate = obj(ended["payload"])["prompt"]
		}
		entry := clone(row)
		origin := event
		if origin == nil {
			origin, err = s.lastObservation(lane, "lane.adopted")
			if err != nil {
				return nil, err
			}
		}
		entry["externally_appended"] = eventstore.ExternallyAppended(origin)
		entry["live"] = live
		entry["session_id"] = previous["session_id"]
		entry["runner_sandbox"] = previous["runner_sandbox"]
		entry["prompt"] = fate
		entry["idle"] = str(row["state"]) == "waiting" && !flag(row["running"])
		result = append(result, entry)
	}
	if a.get("lane") != "" {
		return result[0], nil
	}
	return result, nil
}
func (s *session) announce(lane string) (any, error) {
	if err := s.refresh(); err != nil {
		return nil, err
	}
	row, err := s.row(lane)
	if err != nil {
		return nil, err
	}
	mail := obj(row["mail"])
	settled := obj(mail["settled"])
	if settled == nil || flag(settled["announced"]) || flag(row["running"]) || integer(settled["run"]) != integer(row["run"]) {
		return nil, nil
	}
	kind := "lane." + str(settled["outcome"])
	p := object{"run": settled["run"], "sequences": settled["sequences"]}
	if kind == "lane.returned" {
		p["reason"] = settled["reason"]
	}
	e, err := s.append(envelope(lane, kind, p, "laneboss"), 10)
	return eventPointer(e), err
}
func (s *session) check(a arguments) (any, error) {
	rows, err := s.selectedRows(a.get("lane"))
	if err != nil {
		return nil, err
	}
	result := object{}
	for _, k := range strings.Fields("checked alive lost recorded refused pending") {
		result[k] = []any{}
	}
	for _, row := range rows {
		lane := str(row["lane"])
		count, err := s.pendingCount(lane)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			done, rejected, left, e := s.flush(lane, 10)
			if e != nil {
				return nil, e
			}
			for k, n := range map[string]int{"recorded": done, "refused": rejected, "pending": left} {
				if n > 0 {
					result[k] = append(list(result[k]), object{"lane": lane, "events": n})
				}
			}
		}
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	rows, err = s.selectedRows(a.get("lane"))
	if err != nil {
		return nil, err
	}
	type candidate struct{ row, p, record object }
	running := []candidate{}
	for _, row := range rows {
		if flag(row["running"]) {
			p, r, e := s.latest(str(row["lane"]))
			if e != nil {
				return nil, e
			}
			if p == nil {
				return nil, integrity("a running lane has no run start")
			}
			if e = checkSocket(str(obj(p["session"])["socket"])); e != nil {
				return nil, e
			}
			running = append(running, candidate{row, p, r})
		}
	}
	table, err := processSnapshot()
	if err != nil {
		return nil, err
	}
	for _, c := range running {
		lane := str(c.row["lane"])
		result["checked"] = append(list(result["checked"]), lane)
		if c.record == nil || !validIdentity(c.record["supervisor"]) {
			continue
		}
		alive, e := recordAlive(c.record, table)
		if e != nil {
			return nil, e
		}
		if alive {
			result["alive"] = append(list(result["alive"]), lane)
			continue
		}
		pending, e := s.pendingCount(lane)
		if e != nil {
			return nil, e
		}
		if pending > 0 {
			continue
		}
		survivors, e := recordSurvivors(c.record, table)
		if e != nil {
			return nil, e
		}
		event, e := s.append(envelope(lane, "lane.lost", object{"run": c.row["run"], "survivors": len(survivors)}, "laneboss"), 10)
		if e != nil {
			if refreshError := s.refresh(); refreshError != nil {
				return nil, refreshError
			}
			row, er := s.row(lane)
			if er != nil {
				return nil, er
			}
			if row != nil && (!flag(row["running"]) || integer(row["run"]) != integer(c.row["run"])) {
				continue
			}
			return nil, e
		}
		returned, e := s.announce(lane)
		entry := object{"lane": lane, "run": c.row["run"], "survivors": len(survivors), "event": eventPointer(event), "returned": returned}
		if e != nil {
			entry["returned_error"] = safeMessage(e.Error())
		}
		result["lost"] = append(list(result["lost"]), entry)
	}
	return result, nil
}
func (s *session) mark(a arguments) (any, error) {
	principal, callerErr := s.c.caller()
	if callerErr != nil {
		return nil, callerErr
	}
	lane := a.get("lane")
	count := 0
	for _, b := range []bool{a.get("state") != "", a.get("landing") != "", a.has("gone")} {
		if b {
			count++
		}
	}
	if count != 1 {
		return nil, refuse("lane mark records one decision: give --state, --landing or --gone")
	}
	state, landing := a.get("state"), a.get("landing")
	if state != "" && !contains(strings.Fields("verifying accepted merged abandoned"), state) {
		return nil, refuse("--state must be verifying, accepted, merged or abandoned")
	}
	if landing != "" && !contains(landingKinds, landing) {
		return nil, refuse("--landing must be merged, deployed or landed")
	}
	if a.has("accept-uncovered") && !contains([]string{"accepted", "merged"}, state) {
		return nil, refuse("--accept-uncovered goes with --state accepted or --state merged")
	}
	if _, err := s.known(lane); err != nil {
		return nil, err
	}
	if contains([]string{"accepted", "merged"}, state) {
		unlock, err := s.lanesLock()
		if err != nil {
			return nil, err
		}
		defer unlock()
		if err = s.refresh(); err != nil {
			return nil, err
		}
	}
	if err := s.drain(lane); err != nil {
		return nil, err
	}
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	kind := "lane." + landing
	payload := object{}
	var scanned any
	if a.has("gone") {
		event, e := s.last(lane, "lane.started")
		if e != nil {
			return nil, e
		}
		if event == nil {
			return nil, refuse("lane %s has not run; nothing was declared", lane)
		}
		p := obj(event["payload"])
		for _, k := range []string{"lane.ended", "lane.gone"} {
			event, e := s.last(lane, k)
			if e != nil {
				return nil, e
			}
			if event != nil && integer(obj(event["payload"])["run"]) == integer(p["run"]) {
				return nil, refuse("the lane's run is not open: its end or declaration is recorded")
			}
		}
		r, e := s.readRecord(lane, str(p["launch"]))
		if e != nil {
			if problem, ok := e.(*problem); !ok || problem.code != 3 {
				return nil, e
			}
			r = nil
		}
		if r != nil {
			return nil, refuse("the lane's run has a readable run record: lane stop removes what survives; nothing was declared")
		}
		alive, e := tmuxAlive(str(obj(p["session"])["socket"]), str(obj(p["session"])["name"]))
		if e != nil {
			return nil, e
		}
		if alive {
			return nil, refuse("the lane's tmux session is open, so its supervising process may be alive; nothing was declared")
		}
		kind = "lane.gone"
		payload = object{"run": p["run"], "launch": p["launch"]}
	} else if state != "" {
		if flag(row["running"]) {
			return nil, refuse("lane %s is running; stop it before deciding its state", lane)
		}
		kind = "lane.state"
		payload["state"] = state
		if contains([]string{"accepted", "merged"}, state) {
			scanned, err = s.gate(lane, a.has("accept-uncovered"))
			if err != nil {
				return nil, err
			}
			if m := obj(scanned); m != nil && len(list(m["not_covered"])) > 0 {
				payload["not_covered"] = m["not_covered"]
			}
		}
	}
	event, err := s.append(envelope(lane, kind, payload, caller.LifecycleActor(principal.ID)), 10)
	if err != nil {
		return nil, err
	}
	result := object{"lane": lane, "kind": kind, "event": eventPointer(event)}
	for k, v := range payload {
		result[k] = v
	}
	if len(payload) == 0 {
		result["landing"] = landing
	}
	if scanned != nil {
		result["scan"] = scanned
	}
	if a.has("gone") {
		returned, e := s.announce(lane)
		result["returned"] = returned
		if e != nil {
			result["returned_error"] = safeMessage(e.Error())
		}
	}
	return result, nil
}
func directoryListing(root string) ([]string, error) {
	found := []string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			found = append(found, relative)
		}
		return nil
	})
	sort.Strings(found)
	return found, err
}
func (s *session) clean(a arguments) (any, error) {
	if faults.Get("clean-without-archive").Point != "" {
		if err := faults.Reach("clean-without-archive"); err != nil {
			return nil, err
		}
		unlock, err := s.lanesLock()
		if err != nil {
			return nil, err
		}
		defer unlock()
		return s.cleanLocked(a, nil)
	}
	value, err := s.archive(a)
	if err != nil {
		return nil, err
	}
	archived := obj(value)
	result := clone(obj(archived["clean"]))
	if len(result) == 0 {
		result = object{"lane": a.get("lane"), "pending": false, "removed": []any{}, "kept": []any{object{"item": "lane-directory", "path": s.lanePath(a.get("lane")), "why": "record"}}}
	}
	if flag(archived["pending"]) {
		result["pending"] = true
	}
	for _, key := range []string{"archive", "manifest", "receipt", "sha256", "verified", "reused", "remove_paths", "keep_paths", "status"} {
		if value, ok := archived[key]; ok {
			result[key] = value
		}
	}
	return result, nil
}

// cleanLocked is shared with archive, which holds this same lock from planning
// through read-back and collection. No force option is introduced.
func (s *session) cleanLocked(a arguments, plan *archivePlan) (any, error) {
	s.authority = true
	principal, callerErr := s.c.caller()
	if callerErr != nil {
		return nil, callerErr
	}
	if err := caller.RequireIdentity(principal); err != nil {
		return nil, refuse("%s", err)
	}
	if err := s.c.archivePermission(principal, a.get("lane")); err != nil {
		return nil, err
	}
	lane := a.get("lane")
	var err error
	if err = s.refresh(); err != nil {
		return nil, err
	}
	if plan != nil && len(plan.pending) > 0 {
		if err = s.checkArchivePending(lane, plan.pending); err != nil {
			return nil, err
		}
	} else if err = s.drain(lane); err != nil {
		return nil, err
	}
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	if flag(row["running"]) || !contains([]string{"merged", "abandoned"}, str(row["state"])) {
		return nil, refuse("lane clean takes a lane marked merged or abandoned that is not running; lane %s is %s", lane, str(row["state"]))
	}
	if flag(row["cleaned"]) {
		return nil, refuse("lane %s was already cleaned", lane)
	}
	event, err := s.last(lane, "lane.started")
	if err != nil {
		return nil, err
	}
	if err = s.refuseLive(lane); err != nil {
		return nil, err
	}
	removed, kept := []any{}, []any{}
	if event != nil {
		p := obj(event["payload"])
		socket, name := str(obj(p["session"])["socket"]), str(obj(p["session"])["name"])
		if err = checkSocket(socket); err != nil {
			return nil, err
		}
		mine := s.claimOwner(lane, str(p["launch"]), "")
		path, repository, branch := str(p["worktree"]), str(p["repository"]), str(p["branch"])
		worktree, e := s.worktreeForCollection(lane, p)
		if e != nil {
			return nil, e
		}
		if !worktree.owned && worktree.why == "not-this-lane" && faults.Get("clean-refuse-unowned-worktree").Point != "" {
			if err = faults.Reach("clean-refuse-unowned-worktree"); err != nil {
				return nil, err
			}
			return nil, refuse("the working directory has no valid lane claim; nothing was removed")
		}
		if plan != nil && repository != "" && worktree.why == "" && plan.worktree != path {
			return nil, refuse("the worktree became eligible after archive planning; nothing was removed")
		}
		release := false
		if repository != "" {
			didRemove := false
			if worktree.why != "" {
				kept = append(kept, object{"item": "worktree", "path": path, "why": worktree.why})
			} else {
				code, changes, _, e := gitRun(path, "status", "--porcelain")
				if e != nil {
					return nil, e
				}
				if code != 0 || changes != "" {
					return nil, refuse("lane %s's worktree has uncommitted or untracked work, so nothing was removed", lane)
				}
				before, e := directoryListing(path)
				if e != nil {
					return nil, e
				}
				code, _, errors, e := gitRun(repository, "worktree", "remove", path)
				if e != nil {
					return nil, e
				}
				if code != 0 {
					after := []string{}
					if info, e := os.Stat(path); e == nil && info.IsDir() {
						after, e = directoryListing(path)
						if e != nil {
							return nil, e
						}
					}
					if strings.Join(before, "\x00") == strings.Join(after, "\x00") {
						return nil, refuse("Git refused to remove lane %s's worktree without force and the worktree is unchanged; nothing was removed: %s", lane, safeMessage(errors))
					}
					left := map[string]bool{}
					for _, n := range after {
						left[n] = true
					}
					gone := 0
					for _, n := range before {
						if !left[n] {
							gone++
						}
					}
					return nil, refuse("Git failed while removing lane %s's worktree and it is partly removed: %d of %d entries are gone; the branch and claim were left alone: %s", lane, gone, len(before), safeMessage(errors))
				}
				didRemove = true
				removed = append(removed, object{"item": "worktree", "path": path})
			}
			release = !didRemove && worktree.owned
			if branch != "" {
				if str(row["state"]) == "abandoned" {
					kept = append(kept, object{"item": "branch", "name": branch, "why": "abandoned"})
				} else {
					code, _, _, e := gitRun(repository, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch)
					if e != nil {
						return nil, e
					}
					if code != 0 {
						kept = append(kept, object{"item": "branch", "name": branch, "why": "missing"})
					} else {
						code, _, _, e = gitRun(repository, "branch", "-d", branch)
						if e != nil {
							return nil, e
						}
						if code == 0 {
							removed = append(removed, object{"item": "branch", "name": branch})
						} else {
							kept = append(kept, object{"item": "branch", "name": branch, "why": "not-merged"})
						}
					}
				}
			}
		} else {
			why := worktree.why
			if why == "" {
				why = "not-created"
			}
			kept = append(kept, object{"item": "worktree", "path": path, "why": why})
			release = worktree.owned
			keep := ""
			if worktree.claim != nil {
				keep = worktree.claim.name
			}
			if err = releaseStale(p["claims"], mine, path, keep); err != nil {
				return nil, err
			}
		}
		alive, e := tmuxAlive(socket, name)
		if e != nil {
			return nil, e
		}
		if alive {
			kept = append(kept, object{"item": "session", "name": name, "why": "not-this-lane"})
		}
		if release {
			if _, err = releaseClaim(worktree.claim, mine); err != nil {
				return nil, err
			}
		}
	}
	kept = append(kept, object{"item": "lane-directory", "path": s.lanePath(lane), "why": "record"})
	cleanedEvent := envelope(lane, "lane.cleaned", object{"removed": removed, "kept": kept}, caller.LifecycleActor(principal.ID))
	var stored bool
	if plan != nil && plan.deferReadOnly {
		_, stored, err = s.recordArchive(cleanedEvent, plan)
	} else {
		stored, err = s.record(cleanedEvent, 10)
	}
	if err != nil {
		return nil, err
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	var pointer any
	if stored {
		event, err := s.last(lane, "lane.cleaned")
		if err != nil {
			return nil, err
		}
		pointer = eventPointer(event)
	}
	return object{"lane": lane, "event": pointer, "pending": !stored, "removed": removed, "kept": kept}, nil
}
func (s *session) review(a arguments) (any, error) {
	lane, refusal, path := a.get("lane"), a.get("refusal"), a.get("path")
	if !match(`rf-[0-9a-f]{24}`, refusal) {
		return nil, refuse("--refusal must be a refusal id (rf-[0-9a-f]{24})")
	}
	if !contains([]string{"clean", "workaround"}, a.get("verdict")) {
		return nil, refuse("--verdict must be clean or workaround")
	}
	var note any
	if source := a.get("note"); source != "" {
		for _, candidate := range append([]string{source, realPath(source)}, strings.Split(source, "/")...) {
			if rule, _ := credential(candidate); rule != "" {
				return nil, refuse("--note: the path looks like a credential (%s); nothing was read", rule)
			}
		}
		b, err := s.c.external(source, "--note", 16*1024)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, refuse("--note: the note must be UTF-8 text")
		}
		text := string(b)
		if strings.TrimSpace(text) == "" || len([]rune(text)) > 4000 {
			return nil, refuse("--note: the note must hold 1 to 4000 characters")
		}
		if rule, line := credential(text); rule != "" {
			return nil, refuse("--note line %d: looks like a credential (%s); nothing was recorded", line, rule)
		}
		note = object{"text": text, "sha256": digest(b)}
	}
	if _, err := s.known(lane); err != nil {
		return nil, err
	}
	if err := s.drain(lane); err != nil {
		return nil, err
	}
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	if match(`\([1-9][0-9]{0,8} more\)`, path) {
		return nil, refuse("--path stands for paths an event could not hold, so it cannot be reviewed; read the suspected call and abandon the lane if it cannot be accepted")
	}
	if path != "(command)" && !match(`\(withheld [0-9a-f]{64}\)`, path) && !filepath.IsAbs(path) {
		if str(row["worktree"]) == "" {
			return nil, refuse("--path is relative, but the lane has no working directory")
		}
		path = filepath.Clean(filepath.Join(str(row["worktree"]), path))
	}
	if rule, _ := credential(path); rule != "" {
		return nil, refuse("--path looks like a credential")
	}
	found := refusalState(row)
	if obj(found["recorded"])[refusal] == nil {
		return nil, refuse("lane %s has no recorded refusal %s", lane, refusal)
	}
	suspicions := []string{}
	for id, v := range obj(found["suspected"]) {
		m := obj(v)
		if str(m["refusal"]) == refusal && contains(stringsOf(m["paths"]), path) {
			suspicions = append(suspicions, id)
		}
	}
	sort.Strings(suspicions)
	if len(suspicions) == 0 {
		return nil, refuse("no suspected workaround of refusal %s names %s; lane refusals lists the paths", refusal, path)
	}
	payload := object{"refusal": refusal, "path": path, "verdict": a.get("verdict"), "suspicions": suspicions, "note": note}
	event, err := s.append(envelope(lane, "lane.refusal_reviewed", payload, "supervisor"), 10)
	if err != nil {
		return nil, err
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	current, err := s.row(lane)
	if err != nil {
		return nil, err
	}
	result := clone(payload)
	result["lane"] = lane
	result["event"] = eventPointer(event)
	result["unreviewed"] = refusalState(current)["unreviewed"]
	return result, nil
}
