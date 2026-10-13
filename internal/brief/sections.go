package brief

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

type section struct {
	title string
	body  []string
}
type heading struct {
	index, level int
	title        string
}
type sectionLabel struct{ name, pattern string }
type sectionSpec struct {
	name    string
	heading *regexp.Regexp
	labels  []sectionLabel
}

// Unlike regexp's ASCII-only \s, Python's label checks accept Unicode spaces.
const space = `[\t\n\v\f\r \x{001c}-\x{001f}\x{0085}\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

var (
	headingPattern   = regexp.MustCompile(`^(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$`)
	fencePattern     = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
	closingPattern   = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})[ \\t]*$")
	separatorPattern = regexp.MustCompile(`^` + space + `*:?-{3,}:?` + space + `*$`)
	sectionSpecs     = map[string]sectionSpec{
		"billing": {"Cost", regexp.MustCompile(`(?i)costs?`), []sectionLabel{
			{"unit price", `unit(?:` + space + `|-)+prices?`},
			{"per-run cap", `per(?:` + space + `|-)*run(?:` + space + `|-)+caps?`},
			{"daily cap", `daily(?:` + space + `|-)+caps?`},
			{"worst case", `worst(?:` + space + `|-)+cases?`},
		}},
		"deploy": {"Preflight", regexp.MustCompile(`(?i)pre(?:` + space + `|-)?flight`), []sectionLabel{
			{"calls", `calls?`}, {"permission", `permissions?`},
			{"where granted", `(?:where(?:` + space + `|-)+)?granted(?:(?:` + space + `|-)+(?:in|at|by))?`},
			{"read-back", `read(?:` + space + `|-)?backs?`},
		}},
	}
)

func sections(text string) []section {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(text, "\n")
	fenced := make([]bool, len(lines))
	fence := ""
	var headings []heading
	for i, line := range lines {
		if fence == "" {
			if match := fencePattern.FindStringSubmatch(line); match != nil {
				fence = match[1]
			}
			fenced[i] = fence != ""
		} else {
			fenced[i] = true
			if match := closingPattern.FindStringSubmatch(line); match != nil && match[1][0] == fence[0] && len(match[1]) >= len(fence) {
				fence = ""
			}
		}
		if !fenced[i] {
			if match := headingPattern.FindStringSubmatch(line); match != nil {
				headings = append(headings, heading{i, len(match[1]), match[2]})
			}
		}
	}
	result := make([]section, 0, len(headings))
	for i, h := range headings {
		end := len(lines)
		for _, later := range headings[i+1:] {
			if later.level <= h.level {
				end = later.index
				break
			}
		}
		body := make([]string, 0, end-h.index-1)
		for j := h.index + 1; j < end; j++ {
			if !fenced[j] {
				body = append(body, lines[j])
			}
		}
		result = append(result, section{h.title, body})
	}
	return result
}

func tableCells(line string) []string {
	line = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "|"), "|")
	cells := strings.Split(line, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

func meaningful(value string) bool {
	value = strings.TrimSpace(strings.Trim(strings.TrimSpace(value), "*_`"))
	switch value {
	case "", "-", "--", "—", "n/a", "N/A", "tbd", "TBD":
		return false
	}
	return true
}

func headingMatches(pattern *regexp.Regexp, text string) bool {
	for _, match := range pattern.FindAllStringIndex(text, -1) {
		if match[0] > 0 {
			r, _ := utf8.DecodeLastRuneInString(text[:match[0]])
			if wordRune(r) {
				continue
			}
		}
		if match[1] < len(text) {
			r, _ := utf8.DecodeRuneInString(text[match[1]:])
			if wordRune(r) {
				continue
			}
		}
		return true
	}
	return false
}

func hasValue(lines []string, label string) bool {
	linePattern := regexp.MustCompile(`(?i)^` + space + `*(?:[-*+]` + space + `+|[0-9]+[.)]` + space + `+)?[*_]*(?:` + label + `)[*_]*` + space + `*[:=]` + space + `*(.*)$`)
	headerPattern := regexp.MustCompile(`(?i)^[*_]*(?:` + label + `)[*_]*$`)
	for _, line := range lines {
		if match := linePattern.FindStringSubmatch(line); match != nil && meaningful(match[1]) {
			return true
		}
	}
	var table [][]string
	for i := 0; i <= len(lines); i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			table = append(table, tableCells(line))
			continue
		}
		if len(table) >= 3 {
			valid := true
			for _, cell := range table[1] {
				if cell != "" && !separatorPattern.MatchString(cell) {
					valid = false
					break
				}
			}
			if valid {
				for col, header := range table[0] {
					if headerPattern.MatchString(header) {
						for _, row := range table[2:] {
							if col < len(row) && meaningful(row[col]) {
								return true
							}
						}
					}
				}
			}
		}
		table = nil
	}
	return false
}

func checkSections(text string, touches []string) error {
	found := sections(text)
	for _, touch := range touches {
		spec, ok := sectionSpecs[touch]
		if !ok {
			return refused("--touches: must be billing or deploy")
		}
		var lines []string
		matched := false
		for _, s := range found {
			if headingMatches(spec.heading, s.title) {
				matched = true
				lines = append(lines, s.body...)
			}
		}
		var missing []string
		for _, label := range spec.labels {
			if !hasValue(lines, label.pattern) {
				missing = append(missing, label.name)
			}
		}
		if !matched {
			return refused("--touches %s needs a \"%s\" section (a heading containing \"%s\") that states: %s", touch, spec.name, strings.ToLower(spec.name), strings.Join(missing, ", "))
		}
		if len(missing) > 0 {
			return refused("the %s section has no value for: %s; write 'Label: value' lines or a table with one column per label and a row of values", strings.ToLower(spec.name), strings.Join(missing, ", "))
		}
	}
	return nil
}
