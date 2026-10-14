package lane

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var recordCountNames = strings.Fields("lines unknown_lines other_lines oversized timed_out cut_results cut_lines outside_runs")

type scanRecord struct {
	path, shown, format, state, launch, cwd, realCwd        string
	index, run, line                                        int
	start, end, offset, seen, readTo                        int64
	first, tail                                             any
	mtime, cursor                                           float64
	previous                                                object
	templates                                               map[int][]string
	counts                                                  map[int]object
	otherDirectory                                          map[int]bool
	cut, partial, recognised, incomplete, foreign, finished bool
	file                                                    *os.File
	reader                                                  *bufio.Reader
	pending                                                 []*scanItem
}
type scanItem struct {
	kind, id, tool, class, text, cwd, event, name, sha string
	length, run, line, index                           int
	offset                                             int64
	when                                               float64
	at                                                 any
	error, cut                                         bool
	tail                                               string
	writes, named                                      []string
	record                                             *scanRecord
	compare                                            []*refusalInfo
	compared                                           bool
	resultWhen                                         float64
}

func newScanRecord(path, shown, format string, index int) *scanRecord {
	return &scanRecord{path: path, shown: shown, format: format, state: "covered", index: index, end: -1, templates: map[int][]string{}, counts: map[int]object{}, otherDirectory: map[int]bool{}}
}
func (r *scanRecord) count(run int, key string, n int) {
	if run <= 0 {
		return
	}
	m := r.counts[run]
	if m == nil {
		m = object{}
		for _, k := range recordCountNames {
			m[k] = 0
		}
		r.counts[run] = m
	}
	m[key] = integer(m[key]) + n
}
func fileAnchor(f *os.File, offset int64) (string, error) {
	size := offset
	if size > 4096 {
		size = 4096
	}
	if size < 0 {
		size = 0
	}
	data := make([]byte, size)
	_, err := f.ReadAt(data, offset-size)
	if err != nil && err != io.EOF {
		return "", err
	}
	return digest(data), nil
}
func boundedLine(reader *bufio.Reader) ([]byte, int64, bool, bool, error) {
	data := []byte{}
	var size int64
	oversized := false
	for {
		part, err := reader.ReadSlice('\n')
		size += int64(len(part))
		if !oversized {
			limit := 16 * 1024 * 1024
			if len(part) > 0 && part[len(part)-1] == '\n' {
				limit++
			}
			if len(data)+len(part) > limit {
				oversized = true
				data = nil
			} else {
				data = append(data, part...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return data, size, len(part) > 0 && part[len(part)-1] == '\n', oversized, err
	}
}
func (r *scanRecord) open(scan *refusalScan) bool {
	if r.state == "replaced" || r.state == "refused-zone" {
		return false
	}
	if r.format == "text" {
		root, err := scan.s.laneRoot(scan.lane, false)
		if err != nil {
			r.state = "unreadable"
			return false
		}
		info, err := root.Lstat("output.log")
		if err == nil && !info.Mode().IsRegular() {
			root.Close()
			r.state = "refused-zone"
			return false
		}
		r.file, err = childOpen(root, "output.log", os.O_RDONLY|syscall.O_NONBLOCK, 0)
		root.Close()
		if err != nil {
			r.state = "unreadable"
			if errors.Is(err, syscall.ELOOP) {
				r.state = "refused-zone"
			}
			return false
		}
	} else {
		real := realPath(r.path)
		for _, zone := range append([]zone{{path: scan.s.c.home}, {path: scan.s.c.states}, {path: scan.s.c.state}, {path: scan.s.c.directory}}, scan.s.c.zones...) {
			if inside(real, zone.path) {
				r.state = "refused-zone"
				return false
			}
		}
		root, err := rootDirectory(filepath.Dir(real))
		if err != nil {
			r.state = "unreadable"
			return false
		}
		r.file, err = childOpen(root, filepath.Base(real), os.O_RDONLY|syscall.O_NONBLOCK, 0)
		root.Close()
		if err != nil {
			r.state = "unreadable"
			return false
		}
	}
	info, err := r.file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		r.state = "unreadable"
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		r.file.Close()
		r.file = nil
		r.state = "refused-zone"
		return false
	}
	if stat.Nlink > 1 {
		zones := []string{scan.s.c.home, scan.s.c.states, scan.s.c.state, scan.s.c.directory}
		for _, zone := range scan.s.c.zones {
			zones = append(zones, zone.path)
		}
		linked, err := HardlinkInZones(info, zones)
		if err != nil || linked {
			r.file.Close()
			r.file = nil
			r.state = "refused-zone"
			return false
		}
	}
	r.state = "covered"
	r.mtime = float64(info.ModTime().UnixNano()) / 1e9
	stop := info.Size()
	if r.end >= 0 && r.end < stop {
		stop = r.end
	}
	if r.format != "text" {
		firstReader := bufio.NewReaderSize(io.NewSectionReader(r.file, 0, info.Size()), 65536)
		first, _, complete, large, e := boundedLine(firstReader)
		if e != nil && e != io.EOF {
			r.state = "unreadable"
			return false
		}
		r.incomplete = !complete || large
		var firstHash any
		if complete && !large {
			firstHash = digest(first)
		}
		checkpoint := object{"first": r.first, "seen": r.seen, "tail": r.tail, "state": r.state}
		if r.first == nil && r.previous != nil {
			checkpoint = r.previous
		}
		saved := int64(number(checkpoint["seen"]))
		anchor, e := fileAnchor(r.file, saved)
		if str(checkpoint["state"]) == "replaced" || (checkpoint["first"] != nil && firstHash != checkpoint["first"]) || info.Size() < saved || (checkpoint["tail"] != nil && (e != nil || str(checkpoint["tail"]) != anchor)) {
			r.state = "replaced"
			r.first = checkpoint["first"]
			r.seen = saved
			r.tail = checkpoint["tail"]
			return false
		}
		if r.first == nil {
			r.first = firstHash
		}
		if r.incomplete {
			r.finished = r.finished || scan.final
			return false
		}
	} else {
		if r.cut || info.Size() < r.readTo || info.Size() < r.offset || info.Size() < r.start || (r.end >= 0 && info.Size() < r.end) {
			r.state = "truncated"
			r.cut = true
		}
		if r.offset == r.start && r.start > 0 && r.line == 0 {
			prefix := io.NewSectionReader(r.file, 0, r.start)
			buffer := make([]byte, 65536)
			for {
				n, e := prefix.Read(buffer)
				r.line += bytes.Count(buffer[:n], []byte{'\n'})
				if e != nil {
					break
				}
			}
		}
	}
	if !scan.live {
		r.offset = r.start
	}
	if stop < r.offset {
		stop = r.offset
	}
	r.reader = bufio.NewReaderSize(io.NewSectionReader(r.file, r.offset, stop-r.offset), 65536)
	return true
}

func (r *scanRecord) checkpoint() {
	if r.file == nil {
		return
	}
	readTo := max(r.offset, r.readTo)
	if readTo > r.seen || r.tail == nil {
		if readTo > r.seen {
			r.seen = readTo
		}
		if r.format != "text" {
			anchor, err := fileAnchor(r.file, r.seen)
			if err != nil {
				r.state = "unreadable"
			} else {
				r.tail = anchor
			}
		}
	}
}
func resultText(value any) (string, bool) {
	if text, ok := value.(string); ok {
		return text, false
	}
	blocks := list(value)
	if blocks == nil {
		return "", value != nil
	}
	parts := []string{}
	unknown := false
	for _, v := range blocks {
		if s, ok := v.(string); ok {
			parts = append(parts, s)
			continue
		}
		m := obj(v)
		if m != nil && contains([]string{"text", "tool_reference"}, str(m["type"])) {
			if _, ok := m["text"].(string); ok {
				parts = append(parts, str(m["text"]))
			}
		} else {
			unknown = true
		}
	}
	return strings.Join(parts, "\n"), unknown
}
func boundResult(text string) (string, string, bool) {
	runes := []rune(text)
	if len(runes) <= 131072 {
		return text, "", false
	}
	tail := string(runes[len(runes)-65537:])
	if newline := strings.IndexByte(tail, '\n'); newline >= 0 {
		tail = tail[newline+1:]
	} else {
		tail = ""
	}
	return string(runes[:65536]), tail, true
}
func callItem(block object, cwd string) *scanItem {
	id, tool := str(block["id"]), str(block["name"])
	input := obj(block["input"])
	item := &scanItem{kind: "call", id: id, tool: tool, cwd: cwd, class: "other", writes: []string{}, named: []string{}}
	if tool == "Bash" {
		item.class = "shell"
		item.text = str(input["command"])
	} else {
		fields := map[string][2]string{"Write": {"file_path", "content"}, "Edit": {"file_path", "new_string"}, "MultiEdit": {"file_path", "edits"}, "NotebookEdit": {"notebook_path", "new_source"}}
		if pair, ok := fields[tool]; ok {
			item.class = "file"
			path := str(input[pair[0]])
			body := str(input[pair[1]])
			if tool == "MultiEdit" {
				parts := []string{}
				for _, edit := range list(input[pair[1]]) {
					if _, ok := obj(edit)["new_string"].(string); ok {
						parts = append(parts, str(obj(edit)["new_string"]))
					}
				}
				body = strings.Join(parts, "\n")
			}
			item.text = path + "\n" + body
			if found := shellResolve(path, cwd); found != "" {
				item.writes = []string{found}
				item.named = []string{found}
			}
		} else {
			item.text = string(canonical(input))
			for _, k := range []string{"file_path", "path", "notebook_path"} {
				if found := shellResolve(str(input[k]), cwd); found != "" {
					item.named = append(item.named, found)
				}
			}
		}
	}
	item.length = len([]rune(item.text))
	item.sha = digest([]byte(item.text))
	item.text = cutText(item.text, 65536)
	return item
}
func parseClaude(value any) (string, []*scanItem, string, string) {
	m := obj(value)
	kind := str(m["type"])
	cwd := str(m["cwd"])
	if !filepath.IsAbs(cwd) {
		cwd = ""
	}
	at := str(m["timestamp"])
	if m == nil || kind == "" {
		return "unknown", nil, cwd, at
	}
	if kind == "attachment" {
		a := obj(m["attachment"])
		text := ""
		if str(a["type"]) == "hook_blocking_error" {
			text = str(obj(a["blockingError"])["blockingError"])
		} else if str(a["type"]) == "hook_non_blocking_error" {
			text = str(a["stderr"])
			if text == "" {
				text = str(a["content"])
			}
		} else {
			return "other", nil, cwd, at
		}
		head, tail, cut := boundResult(text)
		return "hook", []*scanItem{{kind: "hook", id: str(a["toolUseID"]), event: str(a["hookEvent"]), name: str(a["hookName"]), text: head, tail: tail, cut: cut}}, cwd, at
	}
	if kind != "assistant" && kind != "user" {
		return "other", nil, cwd, at
	}
	message := obj(m["message"])
	if message == nil {
		return "unknown", nil, cwd, at
	}
	if _, text := message["content"].(string); text {
		return "message", nil, cwd, at
	}
	blocks := list(message["content"])
	if blocks == nil {
		return "unknown", nil, cwd, at
	}
	items := []*scanItem{}
	partial := false
	for _, v := range blocks {
		block := obj(v)
		t := str(block["type"])
		allowed := []string{"text", "thinking", "tool_use"}
		if kind == "user" {
			allowed = []string{"tool_result", "text"}
		}
		if !contains(allowed, t) {
			partial = true
			continue
		}
		if t == "tool_use" {
			items = append(items, callItem(block, cwd))
		} else if t == "tool_result" {
			text, unknown := resultText(block["content"])
			partial = partial || unknown
			head, tail, cut := boundResult(text)
			items = append(items, &scanItem{kind: "result", id: str(block["tool_use_id"]), error: flag(block["is_error"]), text: head, tail: tail, cut: cut})
		}
	}
	if partial {
		return "partial", items, cwd, at
	}
	return "message", items, cwd, at
}
func (r *scanRecord) next(scan *refusalScan) *scanItem {
	for {
		if len(r.pending) > 0 {
			item := r.pending[0]
			r.pending = r.pending[1:]
			return item
		}
		if r.reader == nil {
			return nil
		}
		raw, size, complete, oversized, err := boundedLine(r.reader)
		if size == 0 {
			if err != io.EOF && err != nil {
				r.state = "unreadable"
			}
			r.finished = r.finished || scan.final
			return nil
		}
		offset := r.offset
		r.offset += size
		r.readTo = max(r.readTo, r.offset)
		r.line++
		if !complete && !scan.final {
			r.offset = offset
			r.line--
			r.finished = false
			return nil
		}
		owner := scan.runOf(r.cursor, true)
		if owner == nil {
			owner = scan.runOf(r.mtime, true)
		}
		if oversized {
			if owner != nil {
				r.count(owner.number, "oversized", 1)
			}
			if err == io.EOF {
				r.finished = r.finished || scan.final
				return nil
			}
			continue
		}
		raw = bytes.TrimSuffix(raw, []byte{'\n'})
		normalized := []byte(strings.ToValidUTF8(string(raw), "�"))
		value, e := parseJSON(normalized)
		if e != nil {
			// Session records use the vendor's JSON conventions: repeated fields use
			// the last value, and irrelevant number precision must not hide a refusal.
			decoder := json.NewDecoder(bytes.NewReader(normalized))
			decoder.UseNumber()
			var permissive, extra any
			if decoder.Decode(&permissive) == nil && decoder.Decode(&extra) == io.EOF {
				value = permissive
				if !validJSONUnicode(normalized) {
					r.partial = true
				}
			} else {
				value = nil
				if recordNonfinite(normalized) {
					r.partial = true
				}
			}
		}
		category, items, cwd, at := parseClaude(value)
		if cwd != "" && r.cwd == "" {
			r.cwd = cwd
			r.realCwd = realPath(cwd)
			belongs := false
			for _, run := range scan.runs {
				if r.realCwd == run.worktree || strings.HasPrefix(r.realCwd, strings.TrimRight(run.worktree, "/")+"/") {
					belongs = true
				}
			}
			if !belongs {
				r.foreign = true
				if owner := scan.runOf(r.mtime, false); owner != nil {
					r.otherDirectory[owner.number] = true
				}
				return nil
			}
		}
		if category == "message" {
			r.recognised = true
		} else if category == "partial" {
			r.partial = true
		}
		when, normal := moment(at)
		if when > 0 {
			r.cursor = when
		} else {
			when = r.cursor
			if when == 0 {
				when = r.mtime
			}
		}
		run := scan.runOf(when, true)
		if run == nil {
			if owner := scan.runOf(when, false); owner != nil {
				r.count(owner.number, "outside_runs", 1)
			}
			continue
		}
		if r.cwd != "" && !(r.realCwd == run.worktree || strings.HasPrefix(r.realCwd, strings.TrimRight(run.worktree, "/")+"/")) {
			r.otherDirectory[run.number] = true
			continue
		}
		r.count(run.number, "lines", 1)
		if category == "unknown" {
			r.count(run.number, "unknown_lines", 1)
		} else if category == "other" {
			r.count(run.number, "other_lines", 1)
		}
		if r.cwd == "" {
			continue
		}
		for index, item := range items {
			item.run = run.number
			item.line = r.line
			item.offset = offset
			item.index = index
			item.record = r
			item.when = when
			item.at = normal
			r.pending = append(r.pending, item)
		}
		if err != nil && err != io.EOF {
			r.state = "unreadable"
			r.reader = nil
		}
		if err == io.EOF {
			r.finished = r.finished || scan.final
			r.reader = nil
		}
	}
}

func recordNonfinite(data []byte) bool {
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if quoted && data[i] == '\\' {
			i++
			continue
		}
		if quoted {
			continue
		}
		for _, token := range []string{"NaN", "Infinity", "-Infinity"} {
			if bytes.HasPrefix(data[i:], []byte(token)) {
				left := i == 0 || strings.ContainsRune("{[, :\t\r\n", rune(data[i-1]))
				end := i + len(token)
				right := end == len(data) || strings.ContainsRune("}], \t\r\n", rune(data[end]))
				if left && right {
					return true
				}
			}
		}
	}
	return false
}

type itemHeap []*scanItem

func (h itemHeap) Len() int { return len(h) }
func (h itemHeap) Less(i, j int) bool {
	a, b := h[i], h[j]
	if a.when != b.when {
		return a.when < b.when
	}
	if a.record.index != b.record.index {
		return a.record.index < b.record.index
	}
	if a.offset != b.offset {
		return a.offset < b.offset
	}
	return a.index < b.index
}
func (h itemHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *itemHeap) Push(v any)   { *h = append(*h, v.(*scanItem)) }
func (h *itemHeap) Pop() any     { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }
func (scan *refusalScan) read() error {
	if !scan.live || scan.final || scan.discovered.IsZero() || time.Since(scan.discovered) >= time.Second {
		if err := scan.discover(); err != nil {
			return err
		}
		scan.discovered = time.Now()
	}
	defer func() {
		for _, r := range scan.records {
			if r.file != nil {
				r.checkpoint()
				r.file.Close()
				r.file = nil
				r.reader = nil
			}
		}
	}()
	items := &itemHeap{}
	for _, r := range scan.records {
		if r.format == "text" {
			continue
		}
		if r.open(scan) {
			if item := r.next(scan); item != nil {
				heap.Push(items, item)
			}
		}
	}
	for items.Len() > 0 {
		item := heap.Pop(items).(*scanItem)
		if err := scan.handle(item); err != nil {
			return err
		}
		if next := item.record.next(scan); next != nil {
			heap.Push(items, next)
		}
	}
	for _, r := range scan.records {
		if r.format == "text" && r.open(scan) {
			for {
				raw, size, complete, large, err := boundedLine(r.reader)
				if size == 0 {
					r.finished = r.finished || scan.final
					break
				}
				offset := r.offset
				r.offset += size
				r.readTo = max(r.readTo, r.offset)
				r.line++
				if !complete && !scan.final {
					r.offset = offset
					r.line--
					break
				}
				if large {
					r.count(r.run, "oversized", 1)
					continue
				}
				r.count(r.run, "lines", 1)
				text, tail, cut := boundResult(strings.ToValidUTF8(string(bytes.TrimSuffix(raw, []byte{'\n'})), "�"))
				item := &scanItem{kind: "text", text: text, tail: tail, cut: cut, run: r.run, line: r.line, offset: offset, index: 0, record: r}
				g, message := scan.search(item)
				if g != nil {
					if err := scan.refusedText(item, g, message); err != nil {
						return err
					}
				}
				if err != nil {
					if err != io.EOF {
						r.state = "unreadable"
					}
					r.finished = r.finished || scan.final
					break
				}
			}
		}
	}
	for _, key := range scan.callOrder {
		call := scan.calls[key]
		if call == nil || call.class != "shell" {
			continue
		}
		wait := 2.0
		when := call.when
		if call.compared {
			wait = 5
			when = call.resultWhen
		}
		now := float64(time.Now().UnixNano()) / 1e9
		if scan.final || now >= when+wait {
			if err := scan.decide(call); err != nil {
				return err
			}
		}
	}
	return nil
}
