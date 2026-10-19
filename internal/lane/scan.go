package lane

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/textcontext"
)

type scanRun struct {
	number                        int
	launch, runner, worktree, log string
	start, end                    float64
	ended, ran, logKnown, logCut  bool
	logStart, logEnd              int64
	values                        object
}
type guard struct {
	name       string
	kind       any
	expression *boundedRegexp
}
type refusalScan struct {
	s              *session
	lane, by       string
	runs           []*scanRun
	guards         []guard
	textTools      []textcontext.Tool
	known          map[string]bool
	records        []*scanRecord
	recordByPath   map[string]*scanRecord
	oldInventory   map[string]object
	inventoryByRun map[int]map[string]object
	discovered     time.Time
	problems       map[int][]any
	foundPaths     map[int]map[string]bool
	before         map[string]bool
	calls          map[string]*scanItem
	callOrder      []string
	refused        []*refusalInfo
	final          bool
	live           bool
	appended       object
	refusedEvents  int
	emit           func(object) error
}

func configured(c *configuration, runner string) bool {
	if len(list(c.data["guards"])) == 0 {
		return false
	}
	return runner == "" || len(list(obj(obj(c.data["runners"])[runner])["records"])) > 0
}
func (s *session) scanRuns(lane string) ([]*scanRun, error) {
	events, err := s.laneEvents(lane, "lane.started", "lane.ended", "lane.lost", "lane.gone")
	if err != nil {
		return nil, err
	}
	runs := []*scanRun{}
	byNumber := map[int]*scanRun{}
	for _, e := range events {
		p := obj(e["payload"])
		at := str(e["occurred_at"])
		if at == "" {
			at = str(e["recorded_at"])
		}
		when, _ := moment(at)
		if str(e["kind"]) == "lane.started" {
			values := clone(p)
			values["lane"] = lane
			values["session"] = p["session_id"]
			r := &scanRun{number: integer(p["run"]), launch: str(p["launch"]), runner: str(p["runner"]), worktree: realPath(str(p["worktree"])), log: str(p["log"]), start: when, ran: true, logEnd: -1, values: values}
			runs = append(runs, r)
			byNumber[r.number] = r
		} else if r := byNumber[integer(p["run"])]; r != nil {
			r.ended = true
			if r.end == 0 || str(e["kind"]) == "lane.ended" {
				r.end = when
			}
			if str(e["kind"]) == "lane.ended" {
				r.ran = p["exit_code"] != nil || p["signal"] != nil
			}
		}
	}
	for i, r := range runs {
		if i+1 < len(runs) {
			r.ended = true
		}
		record, e := s.readRecord(lane, r.launch)
		if e == nil {
			log := obj(record["log"])
			if whole(log["start"], 0, 1<<62) {
				r.logKnown = true
				r.logStart = int64(number(log["start"]))
				if whole(log["end"], 0, 1<<62) {
					r.logEnd = int64(number(log["end"]))
				}
			}
		}
	}
	for i, r := range runs {
		if i+1 < len(runs) && r.logKnown && r.logEnd < 0 && runs[i+1].logKnown {
			r.logEnd = runs[i+1].logStart
		}
		if !r.logKnown {
			continue
		}
		for _, earlier := range runs[:i] {
			if earlier.logKnown && earlier.logEnd >= 0 && (r.logStart < earlier.logEnd || r.logStart < earlier.logStart) {
				end := r.logStart
				if end > earlier.logEnd {
					end = earlier.logEnd
				}
				if end < earlier.logStart {
					end = earlier.logStart
				}
				earlier.logEnd = end
				earlier.logCut = true
			}
		}
	}
	return runs, nil
}
func moment(s string) (float64, any) {
	if s == "" || len(s) > 64 {
		return 0, nil
	}
	var parsed time.Time
	var err error
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999"} {
		parsed, err = time.Parse(layout, s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return 0, nil
	}
	return float64(parsed.UnixNano()) / 1e9, parsed.UTC().Format("2006-01-02T15:04:05.000000Z")
}
func (scan *refusalScan) runOf(when float64, window bool) *scanRun {
	var result *scanRun
	for i, r := range scan.runs {
		slack := 0.0
		if i == 0 {
			slack = 2
		}
		if when > 0 && r.start > 0 && when >= r.start-slack {
			result = r
		}
	}
	if window && result != nil && result.end > 0 && when > result.end+5 {
		return nil
	}
	return result
}
func safePath(path string) string {
	if !filepath.IsAbs(path) || len([]rune(path)) > 4096 || strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return "(withheld " + digest([]byte(path)) + ")"
	}
	if rule, _ := credential(path); rule != "" {
		return "(withheld " + digest([]byte(path)) + ")"
	}
	return path
}
func safeName(v, pattern string) any {
	if !match(pattern, v) {
		return nil
	}
	if r, _ := credential(v); r != "" {
		return nil
	}
	return v
}
func recordDigest(parts ...string) string { return digest([]byte(strings.Join(parts, "\x00"))) }
func excerpt(text string) object {
	withheld := false
	limit := len(cutText(text, 240))
	for _, shape := range secretShapes {
		for _, pos := range shape.pattern.FindAllStringIndex(text, -1) {
			if pos[0] < limit && secretBoundary(shape, text, pos[0], pos[1]) {
				if !shape.digits || regexp.MustCompile(`[0-9]`).MatchString(text[pos[0]:pos[1]]) {
					withheld = true
					break
				}
			}
		}
		if withheld {
			break
		}
	}
	if !withheld {
		for _, pos := range assignment.FindAllStringIndex(text, -1) {
			if pos[0] >= limit {
				break
			}
			end := strings.IndexByte(text[pos[0]:], '\n')
			sample := text[pos[0]:]
			if end >= 0 {
				sample = sample[:end]
			}
			if rule, _ := credential(sample); rule != "" {
				withheld = true
				break
			}
		}
	}
	var shown any
	if !withheld {
		shown = cutText(text, 240)
	}
	return object{"text": shown, "withheld": withheld, "length": len([]rune(text)), "sha256": digest([]byte(text))}
}
func cappedPaths(paths []string, first []string) []string {
	priority := unique(append([]string{}, first...))
	rest := []string{}
	for _, s := range unique(paths) {
		if !contains(priority, s) {
			rest = append(rest, s)
		}
	}
	all := append(priority, rest...)
	kept := []string{}
	size := 0
	for _, path := range all {
		if len(kept) >= 1023 || size+len(path)+3 > 256*1024 {
			break
		}
		kept = append(kept, path)
		size += len(path) + 3
	}
	if left := len(all) - len(kept); left > 0 {
		kept = append(kept, fmt.Sprintf("(%d more)", left))
	}
	return unique(kept)
}
func checkedRefusal(p object) object {
	if checkSecrets(p) == nil && len(canonical(p)) <= 512*1024 {
		return p
	}
	for _, k := range []string{"command", "message"} {
		if m := obj(p[k]); m != nil {
			m["text"] = nil
			m["withheld"] = true
		}
	}
	for _, k := range []string{"targets", "paths"} {
		if _, ok := p[k]; ok {
			paths := []string{}
			for _, v := range stringsOf(p[k]) {
				if v == "(command)" {
					paths = append(paths, v)
				} else {
					paths = append(paths, "(withheld "+digest([]byte(v))+")")
				}
			}
			p[k] = cappedPaths(paths, nil)
		}
	}
	for _, m := range []object{p, obj(p["call"])} {
		if r := obj(m["record"]); r != nil {
			r["path"] = "(withheld " + digest([]byte(str(r["path"]))) + ")"
		}
	}
	if m := obj(p["call"]); m != nil {
		m["id"] = nil
	}
	if p["hook"] != nil {
		p["hook"] = object{"event": nil, "name": nil}
	}
	return p
}
func expandRecord(template string, r *scanRun) (string, string) {
	for _, p := range placeholders.FindAllStringSubmatchIndex(template, -1) {
		field := template[p[2]:p[3]]
		v := r.values[field]
		if v == nil {
			if field == "session" {
				return "", "no-session"
			}
			return "", "template-unusable"
		}
		atStart := p[0] == 0 && (field == "worktree" || field == "log")
		if !atStart && (strings.Contains(str(v), "/") || str(v) == "." || str(v) == "..") {
			return "", "bad-placeholder"
		}
	}
	text := template
	for _, p := range placeholders.FindAllStringSubmatch(template, -1) {
		v := str(r.values[p[1]])
		v = strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]").Replace(v)
		text = strings.ReplaceAll(text, p[0], v)
	}
	return expandHome(text), ""
}
func globRecords(pattern string) ([]string, []string, bool) {
	if !filepath.IsAbs(pattern) {
		return nil, nil, false
	}
	bases := []string{"/"}
	errors := []string{}
	overflow := false
	for _, part := range strings.Split(strings.TrimPrefix(pattern, "/"), "/") {
		if part == "" {
			continue
		}
		next := []string{}
		if part == "**" {
			visited := map[string]bool{}
			queue := append([]string{}, bases...)
			for len(queue) > 0 && len(next) <= 10000 {
				path := queue[0]
				queue = queue[1:]
				info, e := os.Stat(path)
				if e != nil {
					if !os.IsNotExist(e) {
						errors = append(errors, path)
					}
					continue
				}
				if !info.IsDir() {
					continue
				}
				st, ok := info.Sys().(*syscall.Stat_t)
				key := realPath(path)
				if ok {
					key = fmt.Sprintf("%d/%d", st.Dev, st.Ino)
				}
				if visited[key] {
					continue
				}
				visited[key] = true
				next = append(next, path)
				entries, e := os.ReadDir(path)
				if e != nil {
					errors = append(errors, path)
					continue
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".") {
						continue
					}
					child := filepath.Join(path, entry.Name())
					info, e := os.Stat(child)
					if e == nil && info.IsDir() {
						queue = append(queue, child)
					}
				}
			}
		} else if strings.ContainsAny(part, "*?[") {
			for _, base := range bases {
				entries, e := os.ReadDir(base)
				if e != nil {
					if !os.IsNotExist(e) && !strings.Contains(e.Error(), "not a directory") {
						errors = append(errors, base)
					}
					continue
				}
				for _, entry := range entries {
					name := entry.Name()
					if strings.HasPrefix(name, ".") && !strings.HasPrefix(part, ".") {
						continue
					}
					yes, e := filepath.Match(part, name)
					if e == nil && yes {
						next = append(next, filepath.Join(base, name))
					}
				}
				if len(next) > 10000 {
					break
				}
			}
		} else {
			for _, base := range bases {
				next = append(next, filepath.Join(base, part))
			}
		}
		if len(next) > 10000 {
			next = next[:10000]
			overflow = true
		}
		bases = next
		if len(bases) == 0 {
			break
		}
	}
	found := []string{}
	for _, p := range bases {
		if _, e := os.Lstat(p); e == nil {
			found = append(found, p)
		} else if !os.IsNotExist(e) {
			errors = append(errors, filepath.Dir(p))
		}
	}
	return found, unique(errors), overflow
}
func (scan *refusalScan) problem(run int, reason, path string) {
	item := object{"reason": reason}
	if path != "" {
		item["path"] = path
	}
	for _, old := range scan.problems[run] {
		if bytes.Equal(canonical(old), canonical(item)) {
			return
		}
	}
	scan.problems[run] = append(scan.problems[run], item)
}
func newScan(s *session, lane, by string, final bool, emit func(object) error) (*refusalScan, error) {
	runs, err := s.scanRuns(lane)
	if err != nil {
		return nil, err
	}
	scan := &refusalScan{s: s, lane: lane, by: by, runs: runs, known: map[string]bool{}, recordByPath: map[string]*scanRecord{}, oldInventory: map[string]object{}, inventoryByRun: map[int]map[string]object{}, problems: map[int][]any{}, foundPaths: map[int]map[string]bool{}, before: map[string]bool{}, calls: map[string]*scanItem{}, refused: []*refusalInfo{}, final: final, appended: object{"refusals": 0, "suspicions": 0}, emit: emit}
	scan.textTools, err = textcontext.Load(s.c.home, s.c.data, screenRoleSource)
	if err != nil {
		return nil, refuse("%s", err.Error())
	}
	row, err := s.row(lane)
	if err != nil {
		return nil, err
	}
	found := refusalState(row)
	for _, group := range []string{"recorded", "suspected"} {
		for id := range obj(found[group]) {
			scan.known[id] = true
		}
	}
	waiting, err := s.waiting(lane)
	if err != nil {
		return nil, err
	}
	for _, e := range waiting {
		p := obj(e["payload"])
		for _, k := range []string{"refusal", "suspicion"} {
			if str(p[k]) != "" {
				scan.known[str(p[k])] = true
			}
		}
	}
	for _, v := range list(s.c.data["guards"]) {
		m := obj(v)
		re, err := compileBounded(str(m["pattern"]))
		if err != nil {
			return nil, invalid("configuration "+s.c.name+": config.toml", "guards.pattern", "unsupported regular expression")
		}
		scan.guards = append(scan.guards, guard{str(m["name"]), m["kind"], re})
	}
	for _, run := range runs {
		scan.foundPaths[run.number] = map[string]bool{}
		scan.inventoryByRun[run.number] = map[string]object{}
		coverage, _, err := s.readCoverage(lane, run.launch)
		if err != nil {
			return nil, err
		}
		for _, entry := range list(coverage["inventory"]) {
			m := obj(entry)
			path := str(m["path"])
			scan.inventoryByRun[run.number][path] = clone(m)
			if str(m["format"]) == "text" {
				continue
			}
			old := scan.oldInventory[path]
			if old == nil {
				scan.oldInventory[path] = clone(m)
			} else {
				if old["first"] != nil && m["first"] != nil && old["first"] != m["first"] {
					old["state"] = "replaced"
				}
				if str(m["state"]) != "covered" && str(old["state"]) == "covered" {
					old["state"] = m["state"]
				}
				if number(m["seen"]) > number(old["seen"]) {
					old["seen"] = m["seen"]
					old["tail"] = m["tail"]
				} else if number(m["seen"]) == number(old["seen"]) && old["tail"] != nil && m["tail"] != nil && old["tail"] != m["tail"] {
					old["state"] = "replaced"
				}
			}
		}
	}
	return scan, nil
}
func (scan *refusalScan) discover() error {
	if len(scan.runs) == 0 || len(scan.guards) == 0 {
		return nil
	}
	first := scan.runs[0].start
	for _, run := range scan.runs {
		if !configured(scan.s.c, run.runner) {
			continue
		}
		runner := obj(obj(scan.s.c.data["runners"])[run.runner])
		for _, v := range list(runner["records"]) {
			entry := obj(v)
			format := str(entry["format"])
			for _, template := range stringsOf(entry["paths"]) {
				if format == "text" {
					if !run.logKnown {
						scan.problem(run.number, "log-range-unknown", safePath(run.log))
						continue
					}
					key := fmt.Sprintf("%s\x00%d", run.log, run.number)
					record := scan.recordByPath[key]
					if record == nil {
						record = newScanRecord(run.log, run.log, "text", len(scan.records))
						record.run = run.number
						record.launch = run.launch
						record.start = run.logStart
						record.offset = run.logStart
						record.end = run.logEnd
						record.cut = run.logCut
						scan.records = append(scan.records, record)
						scan.recordByPath[key] = record
					}
					record.templates[run.number] = append(record.templates[run.number], template)
					continue
				}
				pattern, why := expandRecord(template, run)
				if why != "" {
					scan.problem(run.number, why, template)
					continue
				}
				matches, errors, overflow := globRecords(pattern)
				for _, p := range errors {
					scan.problem(run.number, "unreadable", safePath(p))
				}
				if overflow {
					scan.problem(run.number, "too-many-records", template)
				}
				for _, path := range matches {
					real := realPath(path)
					scan.foundPaths[run.number][real] = true
					if record := scan.recordByPath[real]; record != nil {
						record.templates[run.number] = append(record.templates[run.number], template)
						continue
					}
					info, e := os.Stat(real)
					if e != nil {
						scan.problem(run.number, "unreadable", safePath(path))
						continue
					}
					if !info.Mode().IsRegular() {
						continue
					}
					if float64(info.ModTime().UnixNano())/1e9 < first-2 {
						scan.before[real] = true
						continue
					}
					refusedZone := inside(real, scan.s.c.home) || inside(real, scan.s.c.states) || inside(real, scan.s.c.state) || inside(real, scan.s.c.directory)
					for _, z := range scan.s.c.zones {
						refusedZone = refusedZone || inside(real, z.path)
					}
					if refusedZone {
						scan.problem(run.number, "refused-zone", safePath(path))
						continue
					}
					if len(scan.records) >= 200 {
						scan.problem(run.number, "too-many-records", safePath(path))
						continue
					}
					record := newScanRecord(real, path, format, len(scan.records))
					record.mtime = float64(info.ModTime().UnixNano()) / 1e9
					record.templates[run.number] = append(record.templates[run.number], template)
					record.previous = scan.oldInventory[real]
					scan.records = append(scan.records, record)
					scan.recordByPath[real] = record
				}
			}
		}
	}
	return nil
}
