package laneturns

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/lane"
	"laneboss.io/laneboss/internal/observation"
	"laneboss.io/laneboss/internal/textcontext"
)

type scanGuard struct {
	name string
	kind any
	rx   *regexp.Regexp
}
type scanRefusal struct {
	id, path string
	run      int
	offset   int64
	when     time.Time
	targets  map[string]bool
	shingles map[string]bool
	checked  bool
}
type laneScan struct {
	s           *laneSession
	lane        string
	runs        []*scanRun
	guards      []scanGuard
	textTools   []textcontext.Tool
	records     map[string]*scanRecord
	recordOrder []*scanRecord
	known       map[string]bool
	open        map[string]*scanItem
	order       []string
	deadlines   map[string]time.Time
	refusals    []*scanRefusal
	problems    map[int][]object
	found       map[int]map[string]bool
	before      map[string]time.Time
	blocked     map[string]bool
	inventories map[string]object
	earlier     map[string]object
	emit        func(string, object, any) error
	live        bool
}

func newLaneScan(s *laneSession, lane string, through int, logStart int64, emit func(string, object, any) error) (*laneScan, error) {
	scan := &laneScan{s: s, lane: lane, records: map[string]*scanRecord{}, known: map[string]bool{}, open: map[string]*scanItem{}, deadlines: map[string]time.Time{}, problems: map[int][]object{}, found: map[int]map[string]bool{}, before: map[string]time.Time{}, blocked: map[string]bool{}, inventories: map[string]object{}, earlier: map[string]object{}, emit: emit, live: true}
	var err error
	scan.textTools, err = textcontext.Load(s.c.home, s.c.data, screenRoleSource)
	if err != nil {
		return nil, refused("%s", err.Error())
	}
	for _, value := range array(s.c.data["guards"]) {
		g := obj(value)
		rx, err := regexp.Compile(str(g["pattern"]))
		if err != nil {
			return nil, invalid("guards.pattern: cannot be compiled")
		}
		scan.guards = append(scan.guards, scanGuard{str(g["name"]), g["kind"], rx})
	}
	events, err := s.events(lane, "")
	if err != nil {
		return nil, err
	}
	byRun := map[int]*scanRun{}
	for _, e := range events {
		p := obj(e["payload"])
		kind := str(e["kind"])
		number := integer(p["run"])
		if kind == "lane.refusal" {
			scan.known[str(p["refusal"])] = true
		}
		if kind == "lane.workaround_suspected" {
			scan.known[str(p["suspicion"])] = true
		}
		if number > through {
			continue
		}
		if kind == "lane.started" {
			if err = checkPayload(kind, p); err != nil {
				return nil, err
			}
			start, err := moment(eventTime(e))
			if err != nil {
				return nil, err
			}
			run := &scanRun{run: number, launch: str(p["launch"]), runner: str(p["runner"]), worktree: realPath(str(p["worktree"])), log: str(p["log"]), start: start, values: object{"lane": lane, "account": p["account"], "effort": p["effort"], "log": p["log"], "model": p["model"], "project": p["project"], "worktree": p["worktree"], "session": p["session_id"]}, logEnd: -1}
			record, err := s.record(lane, run.launch)
			if err != nil {
				return nil, err
			}
			span := obj(record["log"])
			if isWhole(span["start"]) {
				run.rangeKnown = true
				run.logStart = int64(numberValue(span["start"]))
				if isWhole(span["end"]) {
					run.logEnd = int64(numberValue(span["end"]))
				}
			}
			scan.runs = append(scan.runs, run)
			byRun[number] = run
			scan.found[number] = map[string]bool{}
			continue
		}
		if contains([]string{"lane.ended", "lane.lost", "lane.gone"}, kind) {
			if run := byRun[number]; run != nil {
				run.end, _ = moment(eventTime(e))
				run.ended = true
			}
		}
	}
	if len(scan.runs) == 0 || scan.runs[len(scan.runs)-1].run != through {
		return nil, refused("the refusal scanner's current run has not started")
	}
	current := scan.runs[len(scan.runs)-1]
	current.ended = false
	current.end = time.Time{}
	current.rangeKnown = true
	current.logStart = logStart
	current.logEnd = -1
	for i := 0; i+1 < len(scan.runs); i++ {
		run, next := scan.runs[i], scan.runs[i+1]
		if run.rangeKnown && run.logEnd < 0 && next.rangeKnown {
			run.logEnd = next.logStart
		}
	}
	for _, run := range scan.runs {
		data, err := s.state.read("lanes/"+lane+"/scans/"+run.launch+".json", 16*1024*1024)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			scan.inventories[run.launch] = object{"unreadable": true}
			continue
		}
		coverage, err := decodeJSON(data)
		if err != nil || !validScanCoverage(coverage, run.launch) {
			scan.inventories[run.launch] = object{"unreadable": true}
			continue
		}
		scan.inventories[run.launch] = coverage
		for _, value := range array(coverage["inventory"]) {
			entry := obj(value)
			path := str(entry["path"])
			old := scan.earlier[path]
			if old == nil {
				old = copyObject(entry)
				old["launches"] = map[string]any{}
				scan.earlier[path] = old
			}
			obj(old["launches"])[run.launch] = true
			if old["state"] != "covered" || entry["state"] != "covered" || old["first"] != nil && entry["first"] != nil && old["first"] != entry["first"] {
				old["first"] = "replaced"
			}
			if numberValue(entry["seen"]) > numberValue(old["seen"]) {
				old["seen"] = entry["seen"]
				old["tail"] = entry["tail"]
			} else if numberValue(entry["seen"]) == numberValue(old["seen"]) && old["tail"] != nil && entry["tail"] != nil && old["tail"] != entry["tail"] {
				old["first"] = "replaced"
			}
		}
	}
	dir, err := s.state.dir("lanes/"+lane, false)
	if err != nil {
		return nil, err
	}
	queue, _, err := pendingQueue(dir)
	dir.Close()
	if err != nil {
		return nil, err
	}
	for _, line := range queue {
		e, err := decodeJSON(line)
		if err == nil {
			p := obj(e["payload"])
			if e["kind"] == "lane.refusal" {
				scan.known[str(p["refusal"])] = true
			}
			if e["kind"] == "lane.workaround_suspected" {
				scan.known[str(p["suspicion"])] = true
			}
		}
	}
	return scan, nil
}
func numberValue(v any) float64 { return number(v) }
func (s *laneScan) latest(t time.Time) *scanRun {
	var latest *scanRun
	for i, run := range s.runs {
		start := run.start
		if i == 0 {
			start = start.Add(-2 * time.Second)
		}
		if !t.IsZero() && !t.Before(start) {
			latest = run
		}
	}
	return latest
}
func (s *laneScan) runAt(t time.Time) *scanRun {
	run := s.latest(t)
	if run != nil && (!run.ended || !t.After(run.end.Add(5*time.Second))) {
		return run
	}
	return nil
}
func (s *laneScan) runNumber(t time.Time) int {
	if run := s.runAt(t); run != nil {
		return run.run
	}
	return 0
}
func (s *laneScan) problem(run int, reason string, path any) {
	entry := object{"reason": reason}
	if path != nil {
		entry["path"] = path
	}
	for _, old := range s.problems[run] {
		if equalJSON(old, entry) {
			return
		}
	}
	s.problems[run] = append(s.problems[run], entry)
}
func expandRecordTemplate(template string, values object) (string, string) {
	escaped := object{}
	for key, value := range values {
		if value == nil {
			continue
		}
		escaped[key] = strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]").Replace(str(value))
	}
	for _, match := range regexp.MustCompile(`\{([a-z_]+)\}`).FindAllStringSubmatchIndex(template, -1) {
		field := template[match[2]:match[3]]
		value := values[field]
		if value == nil {
			if field == "session" {
				return "", "no-session"
			}
			return "", "template-unusable"
		}
		atStart := match[0] == 0 && (field == "worktree" || field == "log")
		if !atStart && (strings.Contains(str(value), "/") || value == "." || value == "..") {
			return "", "bad-placeholder"
		}
	}
	pattern, err := expandTemplate(template, escaped, "account effort lane log model project session worktree", false)
	if err != nil {
		return "", "template-unusable"
	}
	if strings.HasPrefix(pattern, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "template-unusable"
		}
		pattern = filepath.Join(home, pattern[2:])
	}
	return pattern, ""
}
func (s *laneScan) discover() {
	for _, run := range s.runs {
		runner := obj(obj(s.s.c.data["runners"])[run.runner])
		if len(s.guards) == 0 || len(array(runner["records"])) == 0 {
			continue
		}
		for _, value := range array(runner["records"]) {
			entry := obj(value)
			for _, template := range texts(entry["paths"]) {
				if entry["format"] == "text" {
					key := run.log + "\x00" + strconv.Itoa(run.run)
					if r := s.records[key]; r != nil {
						continue
					}
					if !run.rangeKnown {
						s.problem(run.run, "log-range-unknown", safeScanPath(run.log))
						continue
					}
					r := s.newRecord(key, run.log, "text")
					r.run = run.run
					r.start = run.logStart
					r.offset = run.logStart
					r.consumed = run.logStart
					r.end = run.logEnd
					if run.logStart > 0 {
						r.line = -1
					}
					r.templates[run.run] = append(r.templates[run.run], template)
					continue
				}
				pattern, why := expandRecordTemplate(template, run.values)
				if why != "" {
					s.problem(run.run, why, template)
					continue
				}
				matches, err := recordMatches(pattern, 10000)
				if err != nil {
					s.problem(run.run, "unreadable", safeScanPath(pattern))
					continue
				}
				for _, path := range matches {
					s.consider(path, str(entry["format"]), run, template)
				}
			}
		}
	}
}
func (s *laneScan) newRecord(key, path, format string) *scanRecord {
	r := &scanRecord{path: path, shown: path, format: format, state: "covered", index: len(s.recordOrder), end: -1, templates: map[int][]string{}, launches: map[string]bool{}, counts: map[int]object{}, other: map[int]bool{}}
	s.records[key] = r
	s.recordOrder = append(s.recordOrder, r)
	return r
}
func (s *laneScan) consider(path, format string, run *scanRun, template string) {
	file, info, real, err := openScanRecord(path, s.recordZones())
	if file != nil {
		defer file.Close()
	}
	if real == "" {
		real = realPath(path) // An inventory hint only; it never authorizes a read.
	}
	s.found[run.run][real] = true
	if info != nil && !info.Mode().IsRegular() {
		return
	}
	if err != nil {
		var p *problem
		if errorsAsProblem(err, &p) && p.code == 2 {
			s.blocked[real] = true
			number := run.run
			if info != nil {
				if owner := s.latest(info.ModTime()); owner != nil {
					number = owner.run
				}
			}
			s.problem(number, "refused-zone", safeScanPath(path))
		} else {
			s.problem(run.run, "unreadable", safeScanPath(path))
		}
		return
	}
	if r := s.records[real]; r != nil {
		if !contains(r.templates[run.run], template) {
			r.templates[run.run] = append(r.templates[run.run], template)
		}
		return
	}
	if s.blocked[real] {
		return
	}
	if info.ModTime().Before(s.runs[0].start.Add(-2 * time.Second)) {
		s.before[real] = info.ModTime()
		return
	}
	delete(s.before, real)
	count := 0
	for _, r := range s.recordOrder {
		if !r.foreign {
			count++
		}
	}
	if count >= 200 {
		s.problem(run.run, "too-many-records", safeScanPath(path))
		return
	}
	r := s.newRecord(real, real, format)
	r.shown = path
	r.mtime = info.ModTime()
	r.templates[run.run] = []string{template}
	if old := s.earlier[real]; old != nil {
		r.first = str(old["first"])
		r.seen = int64(numberValue(old["seen"]))
		r.tail = str(old["tail"])
		for launch := range obj(old["launches"]) {
			r.launches[launch] = true
		}
	}
}
func (s *laneScan) recordZones() []string {
	return append([]string{s.s.c.home, s.s.c.states, s.s.c.dir, s.s.c.state}, s.s.c.otherPaths...)
}
func (s *laneScan) opener(r *scanRecord) func() (*os.File, error) {
	return func() (*os.File, error) {
		if r.format == "text" {
			return openLog(s.s, s.lane)
		}
		file, _, _, err := openScanRecord(r.path, s.recordZones())
		return file, err
	}
}
func (s *laneScan) poll(final bool) error {
	s.discover()
	items := []*scanItem{}
	for _, r := range s.recordOrder {
		if r.foreign || r.format != "claude-code" {
			continue
		}
		r.read(s.opener(r), final, func(line int, offset int64, raw []byte) {
			value, parseErr := recordJSON([]byte(strings.ToValidUTF8(string(raw), "\ufffd")))
			if parseErr != nil {
				r.partly = true
			}
			category, found, cwd, at := parseScanLine(value)
			if cwd != "" && r.cwd == "" {
				r.cwd = realPath(cwd)
				owned := false
				for _, run := range s.runs {
					if within(r.cwd, run.worktree) {
						owned = true
					}
				}
				if !owned {
					r.foreign = true
					if owner := s.latest(r.mtime); owner != nil {
						r.other[owner.run] = true
					}
					return
				}
			}
			if r.foreign {
				return
			}
			if category == "message" {
				r.recognised = true
			}
			if category == "partial" {
				r.partly = true
			}
			when, normal := scanTime(at)
			if !when.IsZero() {
				r.cursor = when
			} else {
				when = r.cursor
				if when.IsZero() {
					when = r.mtime
				}
			}
			run := s.runAt(when)
			if run == nil {
				if owner := s.latest(when); owner != nil {
					r.count(owner.run, "outside_runs", 1)
				}
				return
			}
			if r.cwd != "" && !within(r.cwd, run.worktree) {
				r.other[run.run] = true
				return
			}
			r.count(run.run, "lines", 1)
			if category == "unknown" {
				r.count(run.run, "unknown_lines", 1)
			}
			if category == "other" {
				r.count(run.run, "other_lines", 1)
			}
			if r.cwd == "" {
				return
			}
			for index, item := range found {
				item.record = r
				item.run = run.run
				item.line = line
				item.offset = offset
				item.index = index
				item.when = when
				item.at = normal
				items = append(items, item)
			}
		}, s.runNumber)
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if !a.when.Equal(b.when) {
			return a.when.Before(b.when)
		}
		if a.record.index != b.record.index {
			return a.record.index < b.record.index
		}
		if a.offset != b.offset {
			return a.offset < b.offset
		}
		return a.index < b.index
	})
	for _, item := range items {
		if err := s.handle(item); err != nil {
			return err
		}
	}
	for _, r := range s.recordOrder {
		if r.format != "text" {
			continue
		}
		var readError error
		r.read(s.opener(r), final, func(line int, offset int64, raw []byte) {
			r.count(r.run, "lines", 1)
			text, tail, cut := boundedScanText(strings.ToValidUTF8(string(raw), "\ufffd"))
			item := &scanItem{kind: "log", text: text, tail: tail, cut: cut, run: r.run, line: line, offset: offset, record: r}
			guard, message := s.search(item)
			if guard != nil && readError == nil {
				readError = s.refusedItem(item, nil, guard, message)
			}
		}, s.runNumber)
		if readError != nil {
			return readError
		}
	}
	if final {
		for _, key := range s.order {
			if call := s.open[key]; call != nil && call.class == "shell" {
				if err := s.decide(call); err != nil {
					return err
				}
			}
		}
		s.open = map[string]*scanItem{}
		s.deadlines = map[string]time.Time{}
	} else {
		now := time.Now()
		for key, deadline := range s.deadlines {
			if !now.Before(deadline) {
				delete(s.deadlines, key)
				if call := s.open[key]; call != nil {
					if err := s.decide(call); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func (s *laneScan) search(item *scanItem) (*scanGuard, string) {
	if item.cut {
		item.record.count(item.run, "cut_results", 1)
	}
	began := time.Now()
	for _, text := range []string{item.text, item.tail} {
		lines := strings.Split(text, "\n")
		for index, line := range lines {
			if len([]rune(line)) > 4096 {
				item.record.count(item.run, "cut_lines", 1)
			}
			line = cutText(line, 4096)
			for i := range s.guards {
				if time.Since(began) >= time.Second {
					item.record.count(item.run, "timed_out", 1)
					return nil, ""
				}
				guard := &s.guards[i]
				if guard.rx.MatchString(line) {
					return guard, strings.Join(lines[index:min(index+3, len(lines))], "\n")
				}
			}
		}
	}
	return nil, ""
}
func (s *laneScan) handle(item *scanItem) error {
	key := ""
	if item.idGiven {
		key = item.record.path + "\x00" + item.id
	}
	if item.kind == "call" {
		if item.class == "shell" {
			if err := s.substitutionCall(item); err != nil {
				return err
			}
		}
		if key == "" {
			return nil
		}
		if s.open[key] == nil {
			s.order = append(s.order, key)
		}
		s.open[key] = item
		if len(s.open) > 4096 {
			for len(s.order) > 0 {
				old := s.order[0]
				s.order = s.order[1:]
				if call := s.open[old]; call != nil {
					if call.class == "shell" {
						if err := s.decide(call); err != nil {
							return err
						}
					}
					delete(s.open, old)
					delete(s.deadlines, old)
					break
				}
			}
		}
		if item.class == "shell" {
			s.deadlines[key] = time.Now().Add(2 * time.Second)
		}
		return nil
	}
	var guard *scanGuard
	var message string
	if item.kind == "hook" || item.error {
		guard, message = s.search(item)
	}
	if guard != nil {
		delete(s.deadlines, key)
		call := s.open[key]
		delete(s.open, key)
		return s.refusedItem(item, call, guard, message)
	}
	if item.kind == "result" {
		if call := s.open[key]; call != nil && call.compare == nil {
			call.compare = append([]*scanRefusal{}, s.refusals...)
			if call.class == "shell" {
				s.deadlines[key] = time.Now().Add(5 * time.Second)
			}
		}
	}
	return nil
}

func (s *laneScan) substitutionCall(call *scanItem) error {
	found, err := lane.ShellSubstitutionInText(call.text, s.textTools)
	if err != nil || !found {
		return err
	}
	place := call.id
	if !call.idGiven || place == "" {
		place = fmt.Sprintf("@%d:%d", call.offset, call.index)
	}
	id := "ws-" + scanDigest(s.lane, observation.Kind, call.record.path, place)[:24]
	if s.known[id] {
		return nil
	}
	tool := scanSafeName(call.tool, toolPattern)
	if tool == nil {
		tool = "shell"
	}
	p := observation.Payload(call.run, id, tool, call.at, scanExcerpt(call.text, call.fullLength, call.fullHash), scanSafeName(call.id, callPattern), scanPosition(call))
	if err := s.emit("lane.workaround_suspected", checkedScanPayload(p), call.at); err != nil {
		return err
	}
	s.known[id] = true
	return nil
}
func checkedScanPayload(p object) object {
	data, err := canonical(p)
	if checkValueCredentials(p, "payload", 0) == nil && err == nil && len(data) <= 512*1024 {
		return p
	}
	for _, key := range []string{"command", "message"} {
		if excerpt := obj(p[key]); excerpt != nil {
			excerpt["text"] = nil
			excerpt["withheld"] = true
		}
	}
	for _, key := range []string{"targets", "paths"} {
		if p[key] != nil {
			paths := []string{}
			for _, path := range texts(p[key]) {
				if path == "(command)" {
					paths = append(paths, path)
				} else {
					paths = append(paths, "(withheld "+digest([]byte(path))+")")
				}
			}
			p[key] = cappedScanPaths(paths, nil)
		}
	}
	for _, container := range []object{p, obj(p["call"])} {
		if record := obj(container["record"]); record != nil {
			record["path"] = "(withheld " + digest([]byte(str(record["path"]))) + ")"
		}
	}
	if call := obj(p["call"]); call != nil {
		call["id"] = nil
	}
	if hook := obj(p["hook"]); hook != nil {
		hook["event"] = nil
		hook["name"] = nil
	}
	return p
}
func (s *laneScan) refusedItem(item, call *scanItem, guard *scanGuard, message string) error {
	place := item.id
	if !item.idGiven {
		place = fmt.Sprintf("@%d:%d", item.offset, item.index)
	}
	id := "rf-" + scanDigest(s.lane, item.record.path, place)[:24]
	via, format := "tool-result", "claude-code"
	if item.kind == "hook" {
		via = "hook"
	}
	if item.kind == "log" {
		via = "log"
		format = "text"
		launch := ""
		for _, run := range s.runs {
			if run.run == item.run {
				launch = run.launch
			}
		}
		id = "rf-" + scanDigest(s.lane, item.record.path, launch, fmt.Sprintf("@%d:0", item.offset))[:24]
	}
	info := &scanRefusal{id: id, path: item.record.path, run: item.run, offset: item.offset, when: item.when, targets: map[string]bool{}}
	var command, tool, hook, callData any
	if call != nil {
		writes, named := call.writes, call.named
		if call.class == "shell" {
			writes, named = analyseShell(call.text, call.cwd)
		}
		targets := writes
		if len(targets) == 0 {
			targets = named
		}
		for _, path := range targets {
			info.targets[path] = true
		}
		info.shingles = shellShingles(call.text)
		info.checked = true
		command = scanExcerpt(call.text, call.fullLength, call.fullHash)
		tool = scanSafeName(call.tool, toolPattern)
	}
	s.refusals = append(s.refusals, info)
	if len(s.refusals) > 64 {
		s.refusals = s.refusals[1:]
	}
	if s.known[id] {
		return nil
	}
	if via == "hook" {
		hook = object{"event": scanSafeName(item.hookEvent, regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)), "name": scanSafeName(item.hookName, regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}$`))}
	}
	if via != "log" {
		var callPosition any
		if call != nil {
			callPosition = scanPosition(call)
		}
		callData = object{"id": scanSafeName(item.id, callPattern), "record": callPosition}
	}
	targets := []string{}
	for _, path := range sortedSet(info.targets) {
		targets = append(targets, safeScanPath(path))
	}
	p := object{"run": item.run, "refusal": id, "guard": guard.name, "kind": guard.kind, "format": format, "via": via, "hook": hook, "tool": tool, "at": item.at, "command": command, "message": scanExcerpt(message, -1, ""), "targets": cappedScanPaths(targets, nil), "call": callData, "record": scanPosition(item), "workarounds_checked": info.checked}
	p = checkedScanPayload(p)
	if err := s.emit("lane.refusal", p, item.at); err != nil {
		return err
	}
	s.known[id] = true
	return nil
}
func (s *laneScan) decide(call *scanItem) error {
	previous := s.refusals
	if call.compare != nil {
		previous = call.compare
	}
	var writes []string
	var shingles map[string]bool
	for _, refusal := range previous {
		later := call.run > refusal.run || call.run == refusal.run && (call.record.path == refusal.path && call.offset > refusal.offset || call.record.path != refusal.path && !call.when.IsZero() && !refusal.when.IsZero() && call.when.After(refusal.when))
		if !refusal.checked || !later {
			continue
		}
		if writes == nil {
			writes, _ = analyseShell(call.text, call.cwd)
			shingles = shellShingles(call.text)
		}
		ways := []string{}
		paths := map[string]bool{}
		hit := []string{}
		for _, path := range writes {
			if refusal.targets[path] {
				hit = append(hit, path)
				paths[path] = true
			}
		}
		if len(hit) > 0 {
			ways = append(ways, "shell-write")
		}
		similar := shellSimilarity(shingles, refusal.shingles)
		if similar != nil {
			ways = append(ways, "reworded")
			for _, path := range writes {
				paths[path] = true
			}
		}
		if len(ways) == 0 {
			continue
		}
		place := call.id
		if !call.idGiven {
			place = fmt.Sprintf("@%d:%d", call.offset, call.index)
		}
		id := "ws-" + scanDigest(refusal.id, call.record.path, place)[:24]
		if s.known[id] {
			continue
		}
		safePaths, safeHit := []string{}, []string{}
		for _, path := range sortedSet(paths) {
			safePaths = append(safePaths, safeScanPath(path))
		}
		for _, path := range hit {
			safeHit = append(safeHit, safeScanPath(path))
		}
		if len(safePaths) == 0 {
			safePaths = []string{"(command)"}
		}
		sort.Strings(ways)
		tool := scanSafeName(call.tool, toolPattern)
		if tool == nil {
			tool = "shell"
		}
		p := object{"run": call.run, "suspicion": id, "refusal": refusal.id, "how": ways, "paths": cappedScanPaths(safePaths, safeHit), "tool": tool, "at": call.at, "command": scanExcerpt(call.text, call.fullLength, call.fullHash), "call": object{"id": scanSafeName(call.id, callPattern), "record": scanPosition(call)}, "similarity": similar}
		if err := s.emit("lane.workaround_suspected", checkedScanPayload(p), call.at); err != nil {
			return err
		}
		s.known[id] = true
	}
	return nil
}
