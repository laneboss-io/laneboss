package start

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

//go:embed protocol.md
var protocolBytes []byte

func protocolSection() (map[string]any, error) {
	match := rx(`(?m)^Protocol version: ([0-9]+\.[0-9]+\.[0-9]+)$`).FindSubmatch(protocolBytes)
	if match == nil {
		return nil, integrity("the shipped protocol has no 'Protocol version: X.Y.Z' line")
	}
	return map[string]any{"version": string(match[1]), "sha256": digest(protocolBytes), "text": string(protocolBytes)}, nil
}
func roleSection(c *configuration, selected *string) (map[string]any, error) {
	supervisors := object(c.data["supervisors"])
	defined := []any{}
	for _, name := range sortedKeys(supervisors) {
		defined = append(defined, name)
	}
	section := map[string]any{"selected": nil, "defined": defined, "entry": nil}
	if selected == nil {
		return section, nil
	}
	if err := checkName(*selected, "role"); err != nil {
		return nil, err
	}
	v, ok := supervisors[*selected]
	if !ok {
		detail := "this configuration defines no role"
		if len(defined) > 0 {
			detail = "the defined roles are: " + strings.Join(stringsOf(defined), ", ")
		}
		return nil, refused("role " + shown(*selected) + " is not defined; " + detail)
	}
	entry := object(v)
	level := integer(entry["level"])
	levelName := map[int64]string{4: "mini-supervisor", 5: "top supervisor", 6: "super top"}[level]
	section["selected"] = *selected
	section["entry"] = map[string]any{"level": level, "level_name": levelName, "runner": entry["runner"], "projects": append([]any{}, array(entry["projects"])...), "owner_channel": entry["owner_channel"], "description": shownValue(entry["description"])}
	return section, nil
}
func rulesSection(c *configuration, role map[string]any) []any {
	rules := []any{}
	known := map[string]bool{}
	add := func(path string, bytes []byte) {
		if known[path] {
			return
		}
		known[path] = true
		text := any(string(bytes))
		if findCredential(string(bytes)) != nil {
			text = withheld
		}
		rules = append(rules, map[string]any{"path": path, "sha256": digest(bytes), "text": text})
	}
	organisation := str(c.data["organisation"])
	for _, relative := range stringsOf(c.data["organisation_rules"]) {
		add("orgs/"+organisation+"/"+relative, c.organisationRules[relative])
	}
	for _, relative := range stringsOf(c.data["rules"]) {
		add(relative, c.rules[relative])
	}
	for _, project := range stringsOf(object(role["entry"])["projects"]) {
		for _, relative := range stringsOf(object(c.projects[project])["rules"]) {
			add(relative, c.rules[relative])
		}
	}
	return rules
}
func findCommand(command string) string {
	if filepath.IsAbs(command) {
		info, err := os.Stat(command)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return command
		}
		return ""
	}
	found, err := exec.LookPath(command)
	if err != nil {
		return ""
	}
	return found
}
func checksSection(c *configuration, s *storeSnapshot, storeErr error) (map[string]any, []any, error) {
	read := []any{}
	record := func(name string, ok bool, detail string) {
		read = append(read, map[string]any{"check": name, "ok": ok, "detail": scrub(detail)})
	}
	record("config", true, "configuration "+c.name+" is valid")
	isolated, detail, ownProblem := c.isolation()
	record("state.isolated", isolated, detail)
	storeDetail := "no store has been created yet"
	if storeErr != nil {
		storeDetail = storeErr.Error()
	} else if s != nil {
		storeDetail = fmt.Sprintf("the recorded store verifies (%d event(s))", len(s.events))
	}
	record("store.recorded", storeErr == nil, storeDetail)
	warnings := []any{}
	if ownProblem {
		return nil, nil, integrity("the state.isolated check failed (" + strings.Join(strings.Fields(scrub(detail)), " ") + "), so no briefing is printed from this state directory; run laneboss doctor --config " + c.name)
	}
	if storeErr != nil {
		return nil, nil, integrity("the store.recorded check failed (" + strings.Join(strings.Fields(scrub(storeDetail)), " ") + "), so no briefing is printed from this store; run laneboss state verify --config " + c.name)
	}
	if !isolated && len(c.unreadable) > 0 {
		names := []string{}
		for _, other := range c.unreadable {
			names = append(names, shown(other.name))
		}
		plural, pronoun := "", "it"
		if len(names) > 1 {
			plural, pronoun = "s", "them"
		}
		warnings = append(warnings, "Warning: configuration"+plural+" "+strings.Join(names, ", ")+" cannot be read, so isolation from "+pronoun+" cannot be shown; run laneboss doctor --config "+c.name+".")
	}
	for _, tool := range []string{"git", "tmux"} {
		found := findCommand(tool)
		detail := tool + " is not on PATH"
		if found != "" {
			detail = "found at " + found
		}
		record("tool."+tool, found != "", detail)
	}
	turns := []string{}
	runners := object(c.data["runners"])
	for _, name := range sortedKeys(runners) {
		runner := object(runners[name])
		programs := []string{stringsOf(runner["command"])[0]}
		if resume := stringsOf(runner["resume"]); len(resume) > 0 {
			programs = append(programs, resume[0])
		}
		missing := []string{}
		found := map[string]string{}
		for _, program := range programs {
			path := findCommand(program)
			found[program] = path
			if path == "" {
				missing = append(missing, program)
			}
		}
		details := []string{}
		if len(missing) > 0 {
			for _, program := range missing {
				details = append(details, program+" is not found on PATH")
			}
		} else {
			unique := []string{}
			for program := range found {
				unique = append(unique, program)
			}
			sort.Strings(unique)
			for _, program := range unique {
				details = append(details, program+" found at "+found[program])
			}
		}
		record("runner."+name, len(missing) == 0, strings.Join(details, "; "))
		if runner["prompt"] == "stdin" && uses(runner["command"], "session") && uses(runner["resume"], "session") && len(array(runner["limit_patterns"])) == 0 {
			turns = append(turns, name)
		}
	}
	if len(turns) > 0 {
		subject := "runner " + turns[0] + " can take turns and has"
		if len(turns) > 1 {
			subject = "runners " + strings.Join(turns, ", ") + " can take turns and have"
		}
		record("turns.limit_patterns", true, "warning: "+subject+" no limit_patterns, so a turn that ends at a usage limit with exit code 0 is counted as delivered; give each of them limit_patterns")
	}
	return map[string]any{"read": read, "not_run": map[string]any{"checks": []any{"state.writable", "store.round_trip"}, "note": "state.writable and store.round_trip write to the state directory, so this command does not run them; laneboss doctor runs them."}}, warnings, nil
}
func storeSections(s *storeSnapshot) (map[string]any, map[string]any, error) {
	present := s != nil
	var note any
	if !present {
		note = noStore
	}
	lanes := map[string]any{"store": present, "note": note, "running": []any{}, "ended": []any{}, "accepted": []any{}, "lost": []any{}, "idle": []any{}, "others": 0, "pending_events": 0, "refused_events": 0, "pending_lanes": []any{}}
	events := map[string]any{"store": present, "note": note, "total": 0, "recent": []any{}}
	if !present {
		return lanes, events, nil
	}
	last := map[string]map[string]any{}
	for _, event := range s.events {
		if contains([]string{"lane.ended", "lane.lost", "lane.gone"}, str(event["kind"])) {
			key := str(event["lane"]) + "\x00" + str(event["kind"]) + "\x00" + str(object(event["payload"])["run"])
			last[key] = event
		}
	}
	for _, row := range s.lanes {
		lane, run := str(row["lane"]), str(row["run"])
		base := lane + "\x00"
		suffix := "\x00" + run
		kind := ""
		if row["reason"] == "lost" {
			kind = "lane.lost"
		} else if row["reason"] != nil {
			kind = "lane.ended"
		}
		var survivors any
		if e := last[base+kind+suffix]; e != nil {
			survivors = object(e["payload"])["survivors"]
		}
		gone := row["running"] != true && last[base+"lane.gone"+suffix] != nil && last[base+"lane.ended"+suffix] == nil
		item := map[string]any{"lane": row["lane"], "run": row["run"], "runner": row["runner"], "model": row["model"], "account": row["account"], "state": row["state"], "state_at": row["state_at"], "reason": row["reason"], "exit_code": row["exit_code"], "survivors": survivors, "gone": gone, "times": row["times"], "landing": row["landing"]}
		group := ""
		if row["running"] == true {
			group = "running"
		} else if row["cleaned"] != true {
			switch row["state"] {
			case "accepted", "merged":
				group = "accepted"
			case "verifying":
				group = "ended"
				if row["reason"] == "lost" || gone {
					group = "lost"
				}
			case "waiting":
				group = "idle"
			}
		}
		if group == "" {
			lanes["others"] = lanes["others"].(int) + 1
		} else {
			if group == "idle" {
				mail := object(row["mail"])
				item["waiting"] = len(array(mail["waiting"])) + len(array(mail["returned"]))
			}
			lanes[group] = append(array(lanes[group]), item)
		}
		waiting, refused, err := pendingCounts(s.root, lane)
		if err != nil {
			return nil, nil, err
		}
		lanes["pending_events"] = lanes["pending_events"].(int) + waiting
		lanes["refused_events"] = lanes["refused_events"].(int) + refused
		if waiting > 0 || refused > 0 {
			lanes["pending_lanes"] = append(array(lanes["pending_lanes"]), map[string]any{"lane": lane, "waiting": waiting, "refused": refused})
		}
	}
	start := len(s.events) - 20
	if start < 0 {
		start = 0
	}
	recent := []any{}
	for _, e := range s.events[start:] {
		at := e["occurred_at"]
		if at == nil || at == "" {
			at = e["recorded_at"]
		}
		recent = append(recent, map[string]any{"seq": e["seq"], "time": at, "lane": e["lane"], "kind": e["kind"]})
	}
	events["total"] = len(s.events)
	events["recent"] = recent
	return lanes, events, nil
}
func briefing(c *configuration, selected *string) (map[string]any, error) {
	role, err := roleSection(c, selected)
	if err != nil {
		return nil, err
	}
	s, storeErr := openSnapshot(c)
	if s != nil {
		defer s.close()
	}
	checks, warnings, err := checksSection(c, s, storeErr)
	if err != nil {
		return nil, err
	}
	if s != nil {
		if err := s.pauseSnapshotForTest(); err != nil {
			return nil, err
		}
	}
	lanes, events, err := storeSections(s)
	if err != nil {
		return nil, err
	}
	protocol, err := protocolSection()
	if err != nil {
		return nil, err
	}
	var organisation any
	if name := str(c.data["organisation"]); name != "" {
		tools := filepath.Join(c.home, "orgs", name, "tools")
		info, err := os.Stat(tools)
		organisation = map[string]any{"name": name, "tools": scrub(tools), "tools_present": err == nil && info.IsDir()}
	}
	return map[string]any{"configuration": map[string]any{"name": c.name, "description": shownValue(c.data["description"]), "organisation": organisation, "binding": "Keep this session bound to configuration " + c.name + ": pass --config " + c.name + " on every command, or export LANEBOSS_CONFIG=" + c.name + ".", "warnings": warnings}, "protocol": protocol, "rules": rulesSection(c, role), "role": role, "checks": checks, "lanes": lanes, "events": events, "unknown": unknown}, nil
}
func splitLines(text string) []string {
	out := []string{}
	start := 0
	for i, r := range text {
		if !strings.ContainsRune("\n\r\v\f\x1c\x1d\x1e\u0085\u2028\u2029", r) {
			continue
		}
		if r == '\n' && i > 0 && text[i-1] == '\r' {
			start = i + 1
			continue
		}
		out = append(out, text[start:i])
		start = i + len(string(r))
	}
	if start < len(text) {
		out = append(out, text[start:])
	}
	return out
}
func indented(text string) []string {
	out := []string{}
	for _, line := range splitLines(text) {
		if strings.TrimFunc(line, unicode.IsSpace) == "" {
			out = append(out, "")
		} else {
			out = append(out, "    "+line)
		}
	}
	return out
}
func word(v any) string {
	if v == nil {
		return "none"
	}
	return str(v)
}
func listingText(doc map[string]any) []string {
	lines := []string{"# Laneboss: no configuration chosen", ""}
	items := array(doc["configurations"])
	if len(items) == 0 {
		lines = append(lines, "No configuration exists under "+str(doc["directory"])+".")
	} else {
		lines = append(lines, "Configurations under "+str(doc["directory"])+":", "")
		for _, v := range items {
			item := object(v)
			detail := str(item["description"])
			if item["readable"] != true {
				detail = "unreadable (" + str(item["problem"]) + ")"
			} else if detail == "" {
				detail = "no description"
			}
			if item["name_withheld"] == true {
				detail = "its name looks like a credential, so it is not shown; " + detail
			}
			lines = append(lines, "- "+str(item["name"])+": "+detail)
		}
	}
	return append(lines, "", str(doc["choose"]))
}
func laneLine(item map[string]any, always bool) string {
	t, l := []string{}, []string{}
	for _, key := range times {
		if v := object(item["times"])[key]; v != nil && v != "" {
			t = append(t, key+" "+str(v))
		}
	}
	for _, key := range landings {
		if v := object(item["landing"])[key]; v != nil && v != "" {
			l = append(l, key+" "+str(v))
		}
	}
	timeText := strings.Join(t, ", ")
	if timeText == "" {
		timeText = "none"
	}
	end := "reason " + word(item["reason"]) + ", exit code " + word(item["exit_code"]) + ", survivors " + word(item["survivors"])
	if item["gone"] == true {
		end = "declared gone, no end recorded"
	}
	line := fmt.Sprintf("- %s: run %s, runner %s, model %s, account %s; last end: %s; state %s since %s; times: %s", str(item["lane"]), str(item["run"]), word(item["runner"]), word(item["model"]), word(item["account"]), end, word(item["state"]), word(item["state_at"]), timeText)
	if len(l) > 0 || always {
		landing := strings.Join(l, ", ")
		if landing == "" {
			landing = "none"
		}
		line += "; landing: " + landing
	}
	return line
}
func briefingText(doc map[string]any) []string {
	c, p, role := object(doc["configuration"]), object(doc["protocol"]), object(doc["role"])
	lines := []string{"# Laneboss session briefing", "", "## Configuration"}
	lines = append(lines, stringsOf(c["warnings"])...)
	lines = append(lines, "", "- Name: "+str(c["name"]), "- Description: "+word(c["description"]))
	if c["organisation"] == nil {
		lines = append(lines, "- Organisation: none")
	} else {
		o := object(c["organisation"])
		present := "missing"
		if o["tools_present"] == true {
			present = "present"
		}
		lines = append(lines, "- Organisation: "+str(o["name"]), "- Organisation tools: "+str(o["tools"])+" ("+present+")")
	}
	lines = append(lines, "- Binding: "+str(c["binding"]), "", "## Protocol", "", "- Version: "+str(p["version"]), "- SHA-256: "+str(p["sha256"]), "", "The protocol text follows, indented by four spaces so that its own headings stay out of this briefing.", "")
	lines = append(lines, indented(str(p["text"]))...)
	lines = append(lines, "", "## Standing rules", "")
	rules := array(doc["rules"])
	if len(rules) == 0 {
		lines = append(lines, "No standing rules file is listed.")
	} else {
		lines = append(lines, "The text of each file follows its line, indented by four spaces so that its own headings stay out of this briefing.", "")
		for i, v := range rules {
			rule := object(v)
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, "- "+str(rule["path"])+": sha256 "+str(rule["sha256"]))
			lines = append(lines, indented(str(rule["text"]))...)
		}
	}
	lines = append(lines, "", "## Role", "")
	if role["entry"] == nil {
		detail := "No role is defined in this configuration."
		if defined := stringsOf(role["defined"]); len(defined) > 0 {
			detail = "Defined roles: " + strings.Join(defined, ", ") + "."
		}
		lines = append(lines, "No role was chosen. "+detail+" Pass --role ROLE to see one.")
	} else {
		entry := object(role["entry"])
		projects := strings.Join(stringsOf(entry["projects"]), ", ")
		if projects == "" {
			projects = "none"
		}
		lines = append(lines, "- Role: "+str(role["selected"]), fmt.Sprintf("- Level: L%d (%s)", integer(entry["level"]), str(entry["level_name"])), "- Runner: "+str(entry["runner"]), "- Projects: "+projects, "- Owner channel: "+word(entry["owner_channel"]), "- Description: "+word(entry["description"]))
	}
	lines = append(lines, "", "## Checks", "")
	checks := object(doc["checks"])
	for _, v := range array(checks["read"]) {
		check := object(v)
		status := "FAILED"
		if check["ok"] == true {
			status = "ok"
		}
		lines = append(lines, "- "+str(check["check"])+" ["+status+"] "+strings.Join(strings.Fields(str(check["detail"])), " "))
	}
	lines = append(lines, "", "Not run: "+str(object(checks["not_run"])["note"]), "", "## Lanes", "")
	lanes := object(doc["lanes"])
	if lanes["store"] != true {
		lines = append(lines, "There are no lanes: "+str(lanes["note"])+".")
	} else {
		for _, group := range [][2]string{{"running", "Running"}, {"ended", "Ended, waiting for the supervisor"}, {"accepted", "Accepted or merged, not yet cleaned"}, {"lost", "Lost or declared gone"}} {
			items := array(lanes[group[0]])
			lines = append(lines, fmt.Sprintf("%s (%d):", group[1], len(items)))
			for _, v := range items {
				lines = append(lines, laneLine(object(v), group[0] == "accepted"))
			}
		}
		if idle := array(lanes["idle"]); len(idle) > 0 {
			lines = append(lines, fmt.Sprintf("Idle, waiting for a turn (%d):", len(idle)))
			for _, v := range idle {
				item := object(v)
				lines = append(lines, laneLine(item, false)+"; messages waiting: "+str(item["waiting"]))
			}
		}
		lines = append(lines, "", "Events waiting to be recorded: "+str(lanes["pending_events"]), "Events the store refused for good: "+str(lanes["refused_events"]), "Lanes in none of these groups (queued, merged or abandoned): "+str(lanes["others"]))
		if pending := array(lanes["pending_lanes"]); len(pending) > 0 {
			items := []string{}
			for _, v := range pending {
				item := object(v)
				items = append(items, fmt.Sprintf("%s (waiting %s, refused %s)", str(item["lane"]), str(item["waiting"]), str(item["refused"])))
			}
			lines = append(lines, "", "Lanes are shown as the store records them; these lanes have events waiting to be recorded or refused by the store: "+strings.Join(items, ", ")+".")
		}
	}
	lines = append(lines, "", "## Recent events", "")
	events := object(doc["events"])
	if events["store"] != true {
		lines = append(lines, "There are no events: "+str(events["note"])+".")
	} else if events["total"] == 0 {
		lines = append(lines, "There are no events yet.")
	} else {
		recent := array(events["recent"])
		lines = append(lines, fmt.Sprintf("Showing the last %d of %s events, oldest first.", len(recent), str(events["total"])))
		for _, v := range recent {
			e := object(v)
			lines = append(lines, fmt.Sprintf("- seq %s, %s, lane %s, %s", str(e["seq"]), str(e["time"]), word(e["lane"]), str(e["kind"])))
		}
	}
	return append(lines, "", "## Not known to the launcher", "", str(doc["unknown"]))
}
