package laneturns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var scanCountKeys = []string{"lines", "unknown_lines", "other_lines", "oversized", "timed_out", "cut_results", "cut_lines", "outside_runs"}

type scanRun struct {
	run                           int
	launch, runner, worktree, log string
	values                        object
	start, end                    time.Time
	ended                         bool
	logStart, logEnd              int64
	rangeKnown                    bool
}
type scanRecord struct {
	path, shown, format, state, first, tail, cwd                     string
	index, line                                                      int
	offset, consumed, seen                                           int64
	start, end                                                       int64
	run                                                              int
	partial                                                          []byte
	skipping, incomplete, recognised, partly, foreign, finished, cut bool
	mtime, cursor                                                    time.Time
	templates                                                        map[int][]string
	launches                                                         map[string]bool
	counts                                                           map[int]object
	other                                                            map[int]bool
}
type scanItem struct {
	kind, id, tool, class, cwd, text, tail string
	fullLength                             int
	fullHash                               string
	writes, named                          []string
	error, cut, idGiven                    bool
	hookEvent, hookName                    string
	record                                 *scanRecord
	run, line, index                       int
	offset                                 int64
	when                                   time.Time
	at                                     any
	compare                                []*scanRefusal
}

func recordJSON(data []byte) (object, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value object
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, integrity("a session record line has trailing JSON data")
	}
	return value, nil
}
func (r *scanRecord) count(run int, key string, n int) {
	if r.counts[run] == nil {
		r.counts[run] = object{}
		for _, key := range scanCountKeys {
			r.counts[run][key] = 0
		}
	}
	r.counts[run][key] = integer(r.counts[run][key]) + n
}
func boundedScanText(text string) (string, string, bool) {
	r := []rune(text)
	if len(r) <= 131072 {
		return text, "", false
	}
	tail := string(r[len(r)-65536-1:])
	if at := strings.IndexByte(tail, '\n'); at >= 0 {
		tail = tail[at+1:]
	} else {
		tail = ""
	}
	return string(r[:65536]), tail, true
}
func scanTime(value any) (time.Time, any) {
	s := str(value)
	if s == "" || len(s) > 64 {
		return time.Time{}, nil
	}
	if strings.HasSuffix(s, "z") {
		s = s[:len(s)-1] + "Z"
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999", "2006-01-02"} {
			if t, err = time.ParseInLocation(layout, s, time.UTC); err == nil {
				break
			}
		}
	}
	if err != nil {
		return time.Time{}, nil
	}
	t = t.UTC().Truncate(time.Microsecond)
	return t, stamp(t)
}
func scanResultText(value any) (string, bool) {
	if s, ok := value.(string); ok {
		return s, false
	}
	if value == nil {
		return "", false
	}
	if !isArray(value) {
		return "", true
	}
	parts := []string{}
	unknown := false
	for _, value := range array(value) {
		if s, ok := value.(string); ok {
			parts = append(parts, s)
			continue
		}
		block := obj(value)
		if block != nil && (block["type"] == "text" || block["type"] == "tool_reference") {
			if s, ok := block["text"].(string); ok {
				parts = append(parts, s)
			}
		} else {
			unknown = true
		}
	}
	return strings.Join(parts, "\n"), unknown
}
func parseScanLine(value object) (string, []*scanItem, string, any) {
	items := []*scanItem{}
	kind := str(value["type"])
	if kind == "" {
		return "unknown", items, "", nil
	}
	cwd := str(value["cwd"])
	if !strings.HasPrefix(cwd, "/") {
		cwd = ""
	}
	at := value["timestamp"]
	if kind == "attachment" {
		a := obj(value["attachment"])
		text := ""
		switch a["type"] {
		case "hook_blocking_error":
			text = str(obj(a["blockingError"])["blockingError"])
		case "hook_non_blocking_error":
			text = str(a["stderr"])
			if text == "" {
				text = str(a["content"])
			}
		default:
			return "other", items, cwd, at
		}
		head, tail, cut := boundedScanText(text)
		return "hook", []*scanItem{{kind: "hook", id: str(a["toolUseID"]), text: head, tail: tail, cut: cut, idGiven: isStringValue(a["toolUseID"]), hookEvent: str(a["hookEvent"]), hookName: str(a["hookName"])}}, cwd, at
	}
	if kind != "assistant" && kind != "user" {
		return "other", items, cwd, at
	}
	message := obj(value["message"])
	if message == nil {
		return "unknown", items, cwd, at
	}
	content := message["content"]
	if _, ok := content.(string); ok {
		return "message", items, cwd, at
	}
	if !isArray(content) {
		return "unknown", items, cwd, at
	}
	partial := false
	for _, value := range array(content) {
		block := obj(value)
		typ := str(block["type"])
		known := []string{"text", "tool_result"}
		if kind == "assistant" {
			known = []string{"text", "thinking", "tool_use"}
		}
		if !contains(known, typ) {
			partial = true
			continue
		}
		if typ == "tool_result" {
			text, unknown := scanResultText(block["content"])
			partial = partial || unknown
			head, tail, cut := boundedScanText(text)
			items = append(items, &scanItem{kind: "result", id: str(block["tool_use_id"]), text: head, tail: tail, cut: cut, idGiven: isStringValue(block["tool_use_id"]), error: flag(block["is_error"])})
			continue
		}
		if typ != "tool_use" {
			continue
		}
		tool := str(block["name"])
		args := obj(block["input"])
		item := &scanItem{kind: "call", id: str(block["id"]), tool: tool, class: "other", idGiven: isStringValue(block["id"]), cwd: cwd, writes: []string{}, named: []string{}}
		text := ""
		if tool == "Bash" {
			item.class = "shell"
			text = str(args["command"])
		} else if contains([]string{"Write", "Edit", "MultiEdit", "NotebookEdit"}, tool) {
			item.class = "file"
			pathKey, bodyKey := "file_path", "content"
			switch tool {
			case "Edit":
				bodyKey = "new_string"
			case "MultiEdit":
				bodyKey = "edits"
			case "NotebookEdit":
				pathKey = "notebook_path"
				bodyKey = "new_source"
			}
			path := str(args[pathKey])
			body := str(args[bodyKey])
			if tool == "MultiEdit" {
				parts := []string{}
				for _, edit := range array(args[bodyKey]) {
					if s, ok := obj(edit)["new_string"].(string); ok {
						parts = append(parts, s)
					}
				}
				body = strings.Join(parts, "\n")
			}
			text = path + "\n" + body
			if resolved := resolveShellPath(path, cwd); resolved != "" {
				item.writes = append(item.writes, resolved)
				item.named = append(item.named, resolved)
			}
		} else {
			var out bytes.Buffer
			printJSON(&out, args)
			text = strings.TrimSuffix(out.String(), "\n")
			for _, key := range []string{"file_path", "path", "notebook_path"} {
				if path := resolveShellPath(str(args[key]), cwd); path != "" {
					item.named = append(item.named, path)
				}
			}
		}
		item.text = cutText(text, 65536)
		item.fullLength = len([]rune(text))
		item.fullHash = digest([]byte(text))
		items = append(items, item)
	}
	category := "message"
	if partial {
		category = "partial"
	}
	return category, items, cwd, at
}
func scanAnchor(file *os.File, offset int64) (string, error) {
	n := min(int64(4096), offset)
	data := make([]byte, n)
	if n == 0 {
		return digest(data), nil
	}
	read, err := file.ReadAt(data, offset-n)
	if err != nil && err != io.EOF {
		return "", err
	}
	if int64(read) != n {
		return "", integrity("a record's anchor is missing")
	}
	return digest(data), nil
}
func (r *scanRecord) read(opener func() (*os.File, error), final bool, consume func(int, int64, []byte), runAt func(time.Time) int) {
	if r.state == "replaced" || r.state == "refused-zone" {
		return
	}
	file, err := opener()
	if err != nil {
		r.state = "unreadable"
		var p *problem
		if errorsAsProblem(err, &p) && p.code == 2 {
			r.state = "refused-zone"
		}
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		r.state = "unreadable"
		return
	}
	r.mtime = info.ModTime()
	r.state = "covered"
	if r.format == "claude-code" {
		prefix, err := io.ReadAll(io.LimitReader(file, 16*1024*1024+1))
		if err != nil {
			r.state = "unreadable"
			return
		}
		newline := bytes.IndexByte(prefix, '\n')
		head := ""
		if newline >= 0 {
			head = digest(prefix[:newline+1])
		}
		anchor, err := scanAnchor(file, r.seen)
		if r.first != "" && (head != r.first || info.Size() < max(r.seen, r.offset) || r.tail != "" && (err != nil || anchor != r.tail)) {
			r.state = "replaced"
			return
		}
		r.incomplete = head == ""
		if r.first == "" {
			r.first = head
		}
		if r.incomplete {
			return
		}
	}
	stop := info.Size()
	if r.end >= 0 {
		stop = min(stop, r.end)
	}
	if r.format == "text" && info.Size() < max(r.offset, max(int64(0), r.end)) {
		r.cut = true
	}
	if r.cut {
		r.state = "truncated"
	}
	if r.line < 0 {
		r.line = 0
		position := int64(0)
		chunk := make([]byte, 4*1024*1024)
		for position < r.offset {
			n, err := file.ReadAt(chunk[:min(int64(len(chunk)), r.offset-position)], position)
			if err != nil && err != io.EOF {
				r.state = "unreadable"
				return
			}
			if n == 0 {
				break
			}
			r.line += bytes.Count(chunk[:n], []byte{'\n'})
			position += int64(n)
		}
	}
	chunk := make([]byte, 4*1024*1024)
	for r.offset < stop {
		n, err := file.ReadAt(chunk[:min(int64(len(chunk)), stop-r.offset)], r.offset)
		if err != nil && err != io.EOF {
			r.state = "unreadable"
			return
		}
		if n == 0 {
			break
		}
		r.offset += int64(n)
		start := 0
		for start < n {
			at := bytes.IndexByte(chunk[start:n], '\n')
			if at < 0 {
				if !r.skipping {
					r.partial = append(r.partial, chunk[start:n]...)
					if len(r.partial) > 16*1024*1024 {
						r.partial = nil
						r.skipping = true
						when := r.cursor
						if when.IsZero() {
							when = r.mtime
						}
						r.count(runAt(when), "oversized", 1)
					}
				}
				break
			}
			end := start + at
			if r.skipping {
				r.skipping = false
				r.line++
				r.consumed = r.offset - int64(n) + int64(end) + 1
			} else {
				line := append(r.partial, chunk[start:end]...)
				r.partial = nil
				r.line++
				begin := r.consumed
				r.consumed += int64(len(line)) + 1
				if len(line) > 16*1024*1024 {
					when := r.cursor
					if when.IsZero() {
						when = r.mtime
					}
					r.count(runAt(when), "oversized", 1)
				} else {
					consume(r.line, begin, line)
					if r.foreign {
						return
					}
				}
			}
			start = end + 1
		}
	}
	r.seen = max(r.seen, r.offset)
	if r.format == "claude-code" {
		tail, err := scanAnchor(file, r.seen)
		if err != nil {
			r.state = "unreadable"
			return
		}
		r.tail = tail
	}
	if final && len(r.partial) > 0 && !r.skipping {
		r.line++
		consume(r.line, r.consumed, r.partial)
		r.consumed += int64(len(r.partial))
		r.partial = nil
	}
	if final {
		r.skipping = false
		r.finished = true
	}
}
func errorsAsProblem(err error, p **problem) bool {
	for err != nil {
		if v, ok := err.(*problem); ok {
			*p = v
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}
func scanPosition(item *scanItem) object {
	return object{"path": safeScanPath(item.record.shown), "line": item.line, "offset": item.offset, "item": item.index}
}
func scanSafeName(value string, pattern *regexp.Regexp) any {
	if value != "" && pattern.MatchString(value) {
		if rule, _ := findCredential(value); rule == "" {
			return value
		}
	}
	return nil
}
func safeScanPath(path string) string {
	if !validAbsolute(path) || screened(path) != path {
		return "(withheld " + digest([]byte(path)) + ")"
	}
	return path
}
func scanDigest(parts ...string) string { return digest([]byte(strings.Join(parts, "\x00"))) }
func scanExcerpt(text string, length int, hash string) object {
	if length < 0 {
		length = len([]rune(text))
	}
	if hash == "" {
		hash = digest([]byte(text))
	}
	withheld := credentialBeginsBefore(text, 240)
	var shownText any
	if !withheld {
		shownText = cutText(text, 240)
	}
	return object{"text": shownText, "withheld": withheld, "length": length, "sha256": hash}
}
func credentialBeginsBefore(text string, n int) bool {
	prefix := cutText(text, n)
	limit := len(prefix)
	for _, shape := range credentialShapes {
		if match := shape.pattern.FindStringIndex(text); match != nil && match[0] < limit {
			return true
		}
	}
	for _, match := range assignment.FindAllStringIndex(text, -1) {
		if match[0] >= limit {
			break
		}
		rest := text[match[1]:]
		if at := strings.IndexByte(rest, '\n'); at >= 0 {
			rest = rest[:at]
		}
		if literalValue(rest) {
			return true
		}
	}
	return false
}
func cappedScanPaths(paths, first []string) []string {
	priority := map[string]bool{}
	all := map[string]bool{}
	for _, path := range first {
		priority[path] = true
		all[path] = true
	}
	for _, path := range paths {
		all[path] = true
	}
	ordered := sortedSet(priority)
	for _, path := range sortedSet(all) {
		if !priority[path] {
			ordered = append(ordered, path)
		}
	}
	kept := []string{}
	size := 0
	for _, path := range ordered {
		if len(kept) >= 1023 || size+len([]byte(path))+3 > 256*1024 {
			break
		}
		kept = append(kept, path)
		size += len([]byte(path)) + 3
	}
	if left := len(all) - len(kept); left > 0 {
		kept = append(kept, fmt.Sprintf("(%d more)", left))
	}
	sort.Strings(kept)
	return kept
}
