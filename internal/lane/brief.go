package lane

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

//go:embed protocol.md
var protocolBytes []byte

const launcherVersion = "0.6.0-dev4"

//go:embed continue.md
var continueBytes []byte

type composedBrief struct {
	output, original []byte
	rules            []ruleInput
	source, project  string
	touches          []string
}

func ended(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b
	}
	return append(append([]byte{}, b...), '\n')
}
func (c *configuration) compose(lane, project, source string, data []byte, touches []string) (*composedBrief, error) {
	if !utf8.Valid(data) {
		return nil, refuse("the brief must be UTF-8 text")
	}
	text := string(data)
	if strings.Contains(text, "<!-- laneboss launcher block: begin") {
		return nil, refuse("the brief already contains a launcher block; give the original brief")
	}
	if rule, line := credential(text); rule != "" {
		return nil, refuse("brief line %d: looks like a credential (%s); nothing was written", line, rule)
	}
	if err := checkSections(text, touches); err != nil {
		return nil, err
	}
	rules := c.ruleInputs(project)
	var b bytes.Buffer
	if len(data) > 0 {
		b.Write(ended(data))
	}
	shownProject := project
	if shownProject == "" {
		shownProject = "none"
	}
	fmt.Fprintf(&b, "\n<!-- laneboss launcher block: begin (protocol 1.2.0) -->\n\n---\n\n# Launcher block\n\nEverything above this block is the brief exactly as written. laneboss %s appended this block.\n\n- Configuration: %s\n- Project: %s\n- Lane: %s\n- Protocol version: 1.2.0\n- Brief sha256: %s\n\n", launcherVersion, c.name, shownProject, lane, digest(data))
	b.Write(ended(protocolBytes))
	for _, r := range rules {
		fmt.Fprintf(&b, "\n## Standing rules: %s (sha256 %s)\n\n", r.name, digest(r.data))
		b.Write(ended(r.data))
	}
	b.WriteString("\n<!-- laneboss launcher block: end -->\n")
	return &composedBrief{b.Bytes(), data, rules, source, project, unique(touches)}, nil
}

type section struct {
	title string
	level int
	lines []string
}

func checkSections(text string, touches []string) error {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	sections := []section{}
	active := []int{}
	fence := ""
	heading := regexp.MustCompile(`^(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$`)
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimLeft(line, " ")
		if len(line)-len(trim) <= 3 && (strings.HasPrefix(trim, "```") || strings.HasPrefix(trim, "~~~")) {
			end := 0
			for end < len(trim) && trim[end] == trim[0] {
				end++
			}
			if fence == "" {
				fence = trim[:end]
				continue
			}
			if trim[0] == fence[0] && end >= len(fence) && strings.TrimSpace(trim[end:]) == "" {
				fence = ""
				continue
			}
		}
		if fence != "" {
			continue
		}
		if m := heading.FindStringSubmatch(line); m != nil {
			level := len(m[1])
			keep := []int{}
			for _, index := range active {
				if sections[index].level < level {
					keep = append(keep, index)
				}
			}
			sections = append(sections, section{m[2], level, []string{}})
			active = append(keep, len(sections)-1)
			continue
		}
		for _, index := range active {
			sections[index].lines = append(sections[index].lines, line)
		}
	}
	for _, touch := range touches {
		if !contains([]string{"billing", "deploy"}, touch) {
			return refuse("--touches must be billing or deploy")
		}
		head := "(?i)\\bcosts?\\b"
		labels := []string{`unit[\s-]+prices?`, `per[\s-]*run[\s-]+caps?`, `daily[\s-]+caps?`, `worst[\s-]+cases?`}
		names := []string{"unit price", "per-run cap", "daily cap", "worst case"}
		if touch == "deploy" {
			head = `(?i)\bpre[\s-]?flight\b`
			labels = []string{`calls?`, `permissions?`, `(?:where[\s-]+)?granted(?:[\s-]+(?:in|at|by))?`, `read[\s-]?backs?`}
			names = []string{"calls", "permission", "where granted", "read-back"}
		}
		lines := []string{}
		found := false
		for _, s := range sections {
			if regexp.MustCompile(head).MatchString(s.title) {
				found = true
				lines = append(lines, s.lines...)
			}
		}
		if !found {
			return refuse("--touches %s needs a cost or preflight section", touch)
		}
		for index, label := range labels {
			if !labelValue(lines, label) {
				return refuse("the %s section has no value for: %s", touch, names[index])
			}
		}
	}
	return nil
}
func meaningful(s string) bool {
	s = strings.TrimSpace(strings.Trim(strings.TrimSpace(s), "*_`"))
	return !contains([]string{"", "-", "--", "—", "n/a", "N/A", "tbd", "TBD"}, s)
}
func tableCells(line string) []string {
	r := []string{}
	for _, s := range strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|") {
		r = append(r, strings.TrimSpace(s))
	}
	return r
}
func labelValue(lines []string, label string) bool {
	form := regexp.MustCompile(`(?i)^\s*(?:[-*+]\s+|[0-9]+[.)]\s+)?[*_]*(?:` + label + `)[*_]*\s*[:=]\s*(.*)$`)
	table := [][]string{}
	flush := func() bool {
		if len(table) < 3 {
			return false
		}
		for _, s := range table[1] {
			if s != "" && !match(`\s*:?-{3,}:?\s*`, s) {
				return false
			}
		}
		for col, head := range table[0] {
			if match(`(?i)[*_]*(?:`+label+`)[*_]*`, head) {
				for _, row := range table[2:] {
					if col < len(row) && meaningful(row[col]) {
						return true
					}
				}
			}
		}
		return false
	}
	for _, line := range append(append([]string{}, lines...), "") {
		if m := form.FindStringSubmatch(line); m != nil && meaningful(m[1]) {
			return true
		}
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			table = append(table, tableCells(line))
		} else {
			if flush() {
				return true
			}
			table = nil
		}
	}
	return false
}
func (s *session) render(lane string, b *composedBrief) (object, error) {
	r, err := s.laneRoot(lane, true)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	inputs := []any{}
	consumed := []ruleInput{{"brief", b.original}, {"protocol", protocolBytes}}
	consumed = append(consumed, b.rules...)
	created := []string{}
	outputHash := digest(b.output)
	outputName := "rendered/" + outputHash + ".md"
	written := false
	ok := false
	defer func() {
		if !ok {
			if written {
				r.Remove(outputName)
			}
			for _, name := range created {
				if s.db != nil {
					var refs int
					err := s.db.QueryRow("SELECT count(*) FROM events WHERE kind='brief.rendered' AND instr(payload,?)>0", name).Scan(&refs)
					if err == nil && refs == 0 {
						r.Remove("inputs/" + name)
					}
				}
			}
		}
	}()
	for index, item := range consumed {
		hash := digest(item.data)
		copy := "lanes/" + lane + "/inputs/" + hash
		old, e := rootRead(r, "inputs/"+hash, 8*1024*1024)
		if e == nil {
			if !bytes.Equal(old, item.data) {
				return nil, integrity("kept input does not match its hash")
			}
		} else if os.IsNotExist(e) {
			if e = rootWrite(r, "inputs/"+hash, item.data, false, 0600); e != nil && !os.IsExist(e) {
				return nil, e
			}
			if e == nil {
				created = append(created, hash)
			}
		} else {
			return nil, e
		}
		entry := object{"role": "rules", "path": item.name, "sha256": hash, "copy": copy}
		if index == 0 {
			entry["role"] = "brief"
			entry["path"] = b.source
		} else if index == 1 {
			delete(entry, "path")
			entry["role"] = "protocol"
			entry["version"] = "1.2.0"
		}
		inputs = append(inputs, entry)
	}
	old, e := rootRead(r, outputName, 8*1024*1024)
	if e == nil {
		if !bytes.Equal(old, b.output) {
			return nil, integrity("the rendered brief does not hold the bytes its name promises")
		}
	} else if os.IsNotExist(e) {
		if err = rootWrite(r, outputName, b.output, false, 0644); err != nil {
			return nil, err
		}
		written = true
	} else {
		return nil, e
	}
	output := object{"path": s.lanePath(lane, "rendered", outputHash+".md"), "sha256": outputHash}
	payload := object{"inputs": inputs, "output": output, "project": nullable(b.project), "touches": b.touches, "launcher_version": launcherVersion}
	event := envelope(lane, "brief.rendered", payload, "laneboss")
	event["occurred_at"] = nil
	if _, err = s.append(event, 10); err != nil {
		return nil, err
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	ok = true
	return output, nil
}
func (s *session) verifyRendered(lane string, v any) error {
	m := obj(v)
	if !fileValue(v) || str(m["path"]) != s.lanePath(lane, "rendered", str(m["sha256"])+".md") {
		return integrity("lane %s's rendered brief is not where the store says it is", lane)
	}
	r, err := s.laneRoot(lane, false)
	if err != nil {
		return integrity("lane %s's rendered brief is missing", lane)
	}
	defer r.Close()
	b, err := rootRead(r, "rendered/"+str(m["sha256"])+".md", 5*1024*1024)
	if err != nil {
		return integrity("lane %s's rendered brief cannot be handed over", lane)
	}
	if digest(b) != str(m["sha256"]) {
		return integrity("lane %s's rendered brief no longer holds the bytes it was rendered with", lane)
	}
	return nil
}
func (s *session) checkRendered(e object) error {
	p := obj(e["payload"])
	lane := str(e["lane"])
	if lane == "" || !exactKeys(p, strings.Fields("inputs output project touches launcher_version")) || len(list(p["inputs"])) < 2 || !fileValue(p["output"]) {
		return refuse("brief.rendered payload is not in this version's form")
	}
	r, err := s.laneRoot(lane, false)
	if err != nil {
		return refuse("brief.rendered kept inputs are missing")
	}
	defer r.Close()
	for index, v := range list(p["inputs"]) {
		m := obj(v)
		role, field := "rules", "path"
		if index == 0 {
			role = "brief"
		}
		if index == 1 {
			role = "protocol"
			field = "version"
		}
		if !exactKeys(m, []string{"role", "sha256", "copy", field}) || str(m["role"]) != role || str(m["copy"]) != "lanes/"+lane+"/inputs/"+str(m["sha256"]) {
			return refuse("brief.rendered input is not kept under its hash")
		}
		b, err := rootRead(r, "inputs/"+str(m["sha256"]), 8*1024*1024)
		if err != nil || digest(b) != str(m["sha256"]) {
			return refuse("brief.rendered kept input is missing or does not match its hash")
		}
	}
	return nil
}
