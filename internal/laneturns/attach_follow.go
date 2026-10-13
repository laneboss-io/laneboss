package laneturns

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const bypassWarning = "WARNING: approvals are bypassed: the agent may run any command and change any file it can reach."
const denialNotice = "note: this request ran without approval rights."

func modeLines(mode string) string {
	text := "permission mode (as the agent reports it): " + mode + "\n"
	if mode == "bypassPermissions" {
		text += bypassWarning + "\n"
	}
	return text
}
func ago(seconds float64) string {
	n := max(0, int(seconds))
	switch {
	case n < 120:
		return fmt.Sprintf("%d seconds", n)
	case n < 7200:
		return fmt.Sprintf("%d minutes", n/60)
	case n < 172800:
		return fmt.Sprintf("%d hours", n/3600)
	default:
		return fmt.Sprintf("%d days", n/86400)
	}
}
func displayStatus(row object) string {
	if row["state"] != "waiting" {
		return "not running: state " + str(row["state"])
	}
	at, _ := moment(row["state_at"])
	reason := "None"
	if row["reason"] != nil {
		reason = str(row["reason"])
	}
	code := "none"
	if row["exit_code"] != nil {
		code = fmt.Sprint(integer(row["exit_code"]))
	}
	waiting := queued(obj(row["mail"]))
	text := fmt.Sprintf("idle: run %d ended with reason %s, exit code %s, %s ago; messages waiting: %d", integer(row["run"]), reason, code, ago(time.Since(at).Seconds()), waiting)
	if waiting > 0 {
		text += "; type /turn to start a turn for them"
	}
	return text
}
func logRange(s *laneSession, lane string, run int, size int64) (int64, int64, bool, error) {
	events, err := s.store.events(lane, "lane.started")
	if err != nil {
		return 0, 0, false, err
	}
	var current, next object
	for _, e := range events {
		p := obj(e["payload"])
		if integer(p["run"]) == run {
			current = p
		}
		if integer(p["run"]) == run+1 {
			next = p
		}
	}
	if current == nil {
		return 0, 0, false, nil
	}
	record, err := s.record(lane, str(current["launch"]))
	if err != nil {
		return 0, 0, false, err
	}
	log := obj(record["log"])
	if log == nil || !isWhole(log["start"]) {
		return 0, 0, false, nil
	}
	start := int64(number(log["start"]))
	end := size
	if isWhole(log["end"]) {
		end = int64(number(log["end"]))
	} else if next != nil {
		later, err := s.record(lane, str(next["launch"]))
		if err != nil {
			return 0, 0, false, err
		}
		if isWhole(obj(later["log"])["start"]) {
			end = int64(number(obj(later["log"])["start"]))
		}
	}
	if start < 0 || end < start || end > size {
		return 0, 0, false, integrity("the lane's log range is outside its log")
	}
	return start, end, true, nil
}
func openLog(s *laneSession, lane string) (*os.File, error) {
	dir, err := s.state.dir("lanes/"+lane, false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return regularAt(dir, "output.log", "the lane's log", os.O_RDONLY, 0)
}
func rangeLines(f *os.File, start, end int64) ([]string, error) {
	if start < 0 || end < start {
		return nil, integrity("the lane's log range is invalid")
	}
	data, err := io.ReadAll(io.NewSectionReader(f, start, end-start))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSuffix(data, []byte{'\n'})
	parts := bytes.Split(data, []byte{'\n'})
	if len(data) == 0 {
		return []string{}, nil
	}
	lines := make([]string, len(parts))
	for i, part := range parts {
		lines[i] = strings.ToValidUTF8(string(part), "\ufffd")
	}
	return lines, nil
}
func scanMode(s *laneSession, lane, stream string, row object) (string, error) {
	if stream == "text" {
		return "", nil
	}
	f, err := openLog(s, lane)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	for run := integer(row["run"]); run > 0; run-- {
		start, end, ok, err := logRange(s, lane, run, info.Size())
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		lines, err := rangeLines(f, start, end)
		if err != nil {
			return "", err
		}
		mode := ""
		for _, line := range lines {
			for _, item := range readStream(stream, line) {
				if item["kind"] == "mode" {
					mode = str(item["mode"])
				}
			}
		}
		if mode != "" {
			return mode, nil
		}
	}
	return "", nil
}

type attachFollower struct {
	c                     *configuration
	lane, stream, mode    string
	seen, current         int
	offset                int64
	carry                 []byte
	streamed              string
	openLine, denialNoted bool
	result                object
	send                  chan<- string
	stop                  <-chan struct{}
	s                     *laneSession
	fd                    *os.File
}

func (f *attachFollower) emit(text string) {
	if text == "" {
		return
	}
	select {
	case f.send <- text:
	case <-f.stop:
	}
}
func (f *attachFollower) lineStart() {
	if f.openLine {
		f.emit("\n")
		f.openLine = false
	}
}
func (f *attachFollower) render(item object) {
	switch str(item["kind"]) {
	case "answer":
		text := str(item["text"])
		if value, exists := item["streamed"]; exists && value == false {
			if at := strings.Index(f.streamed, text); at >= 0 {
				f.streamed = f.streamed[at+len(text):]
				return
			}
			f.lineStart()
			if !strings.HasSuffix(text, "\n") {
				text += "\n"
			}
			f.emit(text)
		} else if f.stream == "text" {
			f.emit(text + "\n")
		} else {
			f.streamed += text
			if len(f.streamed) > 1048576 {
				f.streamed = f.streamed[len(f.streamed)-1048576:]
			}
			f.emit(text)
			if text != "" {
				f.openLine = !strings.HasSuffix(text, "\n")
			}
		}
	case "tool":
		f.lineStart()
		f.emit(str(item["label"]) + "\n")
	case "mode":
		mode := str(item["mode"])
		if mode != f.mode {
			f.mode = mode
			f.lineStart()
			f.emit(modeLines(mode))
		}
	case "result":
		f.result = item
		f.streamed = ""
		f.lineStart()
		for _, denial := range texts(item["denials"]) {
			f.emit(denial + "\n")
			if !f.denialNoted {
				f.denialNoted = true
				f.emit(denialNotice + "\n")
			}
		}
		if flag(item["error"]) {
			f.emit("note: the result line says that the request ended in an error.\n")
		}
	case "notice":
		f.lineStart()
		f.emit("notice: " + str(item["text"]) + "\n")
	case "raw":
		f.lineStart()
		f.emit(str(item["text"]) + "\n")
	}
}
func (f *attachFollower) readTo(end int64, finish bool) error {
	if f.fd == nil {
		return nil
	}
	if end < f.offset {
		return integrity("the lane's output log was truncated")
	}
	chunk := make([]byte, 1024*1024)
	for f.offset < end {
		want := min(int64(len(chunk)), end-f.offset)
		n, err := f.fd.ReadAt(chunk[:want], f.offset)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		f.offset += int64(n)
		parts := bytes.Split(append(f.carry, chunk[:n]...), []byte{'\n'})
		f.carry = append([]byte{}, parts[len(parts)-1]...)
		for _, part := range parts[:len(parts)-1] {
			for _, item := range readStream(f.stream, strings.ToValidUTF8(string(part), "\ufffd")) {
				f.render(item)
			}
		}
	}
	if finish && len(f.carry) > 0 {
		for _, item := range readStream(f.stream, strings.ToValidUTF8(string(f.carry), "\ufffd")) {
			f.render(item)
		}
		f.carry = nil
	}
	return nil
}
func (f *attachFollower) earlierCost(run int, size int64) (any, error) {
	if f.stream == "text" || run <= 1 {
		return nil, nil
	}
	start, end, ok, err := logRange(f.s, f.lane, run-1, size)
	if err != nil || !ok {
		return nil, err
	}
	lines, err := rangeLines(f.fd, start, end)
	if err != nil {
		return nil, err
	}
	var cost any
	for _, line := range lines {
		for _, item := range readStream(f.stream, line) {
			if item["kind"] == "result" {
				cost = item["cost"]
			}
		}
	}
	return cost, nil
}
func (f *attachFollower) finish(row object, size int64) error {
	start, end, ok, err := logRange(f.s, f.lane, f.current, size)
	_ = start
	if err != nil {
		return err
	}
	if !ok {
		end = f.offset
	}
	earlier, err := f.earlierCost(f.current, size)
	if err != nil {
		return err
	}
	if err = f.readTo(end, true); err != nil {
		return err
	}
	f.lineStart()
	events, err := f.s.store.events(f.lane, "lane.ended")
	if err != nil {
		return err
	}
	var ended object
	for _, e := range events {
		if integer(obj(e["payload"])["run"]) == f.current {
			ended = obj(e["payload"])
		}
	}
	if ended == nil {
		reason := "not known"
		if integer(row["run"]) == f.current {
			reason = str(row["reason"])
		}
		f.emit(fmt.Sprintf("run %d ended without an end event (reason %s)\n", f.current, shown(reason)))
	} else {
		code := "none"
		if ended["exit_code"] != nil {
			code = fmt.Sprint(integer(ended["exit_code"]))
		} else if ended["signal"] != nil {
			code = fmt.Sprintf("signal %d", integer(ended["signal"]))
		}
		if f.stream == "text" {
			f.emit(fmt.Sprintf("[run %d | exit %s | %.1f seconds]\n", f.current, code, number(ended["duration_seconds"])))
		} else {
			total := f.result["cost"]
			turn, session := "unknown", "unknown"
			if total != nil {
				session = fmt.Sprintf("$%.4f", number(total))
				if earlier != nil && number(total) >= number(earlier) {
					turn = fmt.Sprintf("$%.4f", number(total)-number(earlier))
				}
			}
			f.emit(fmt.Sprintf("[run %d | exit %s | this turn %s | session %s | %.1f seconds]\n", f.current, code, turn, session, number(ended["duration_seconds"])))
		}
	}
	if integer(row["run"]) == f.current && !flag(row["running"]) {
		f.emit(displayStatus(row) + "\n")
	}
	f.current = 0
	return nil
}
func (f *attachFollower) look() error {
	if f.s == nil {
		s, err := openSession(f.c, false)
		if err != nil {
			return err
		}
		f.s = s
	} else if err := f.s.refresh(); err != nil {
		return err
	}
	row, err := f.s.known(f.lane)
	if err != nil {
		return err
	}
	if f.fd == nil {
		f.fd, err = openLog(f.s, f.lane)
		if os.IsNotExist(err) && !flag(row["running"]) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	info, err := f.fd.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	if f.current > 0 && (integer(row["run"]) != f.current || !flag(row["running"])) {
		if err = f.finish(row, size); err != nil {
			return err
		}
	}
	for f.current == 0 && f.seen < integer(row["run"]) {
		run := f.seen + 1
		start, end, ok, err := logRange(f.s, f.lane, run, size)
		if err != nil {
			return err
		}
		live := flag(row["running"]) && integer(row["run"]) == run
		if !ok && live {
			return nil
		}
		f.current = run
		f.seen = run
		f.offset = 0
		f.carry = nil
		f.streamed = ""
		f.openLine = false
		f.result = nil
		if ok {
			f.offset = start
		}
		if live {
			f.emit(fmt.Sprintf("following run %d (live)\n", run))
		} else {
			f.emit(fmt.Sprintf("run %d had ended when attach looked\n", run))
		}
		if live {
			return f.readTo(size, false)
		}
		if !ok {
			end = 0
		}
		_ = end
		if err = f.finish(row, size); err != nil {
			return err
		}
	}
	if f.current > 0 {
		return f.readTo(size, false)
	}
	return nil
}
func (f *attachFollower) follow() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	defer func() {
		if f.s != nil {
			f.s.close()
		}
		if f.fd != nil {
			f.fd.Close()
		}
	}()
	var lastTrouble time.Time
	for {
		err := f.look()
		if err != nil {
			if f.s != nil {
				f.s.close()
				f.s = nil
			}
			if f.fd != nil {
				f.fd.Close()
				f.fd = nil
			}
			if time.Since(lastTrouble) >= 10*time.Second {
				lastTrouble = time.Now()
				f.lineStart()
				f.emit("note: the view could not read the lane: " + safeDetail(err) + "\n")
			}
		}
		select {
		case <-f.stop:
			return
		case <-ticker.C:
		}
	}
}
