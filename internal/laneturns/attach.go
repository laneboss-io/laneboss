package laneturns

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const attachHelp = "/turn   start a turn for the messages that wait\n/stop   stop the turn that this attach started (Ctrl-C does the same)\n/help   this list\n/exit   leave attach; a turn that is live goes on"
const attachHint = "nothing was stopped; leave with /exit or Ctrl-D (Ctrl-C stops only a turn that this attach started)"
const keyNotice = "Ctrl-C noted: attach acts on it when the lane command now running returns; another Ctrl-C at least 2 seconds after this one leaves attach now, without waiting"

func attachHintText(discarded bool, typed any) string {
	if !discarded {
		return attachHint
	}
	if typed == nil {
		return "anything typed was discarded; " + attachHint
	}
	if typed == true {
		return "the line was discarded; " + attachHint
	}
	return attachHint
}

type attachResult struct {
	kind  string
	value object
	err   error
	text  string
	run   int
}
type inputChunk struct {
	data    []byte
	err     error
	drawing bool
}
type attachSignal struct {
	value   os.Signal
	drawing bool
}
type attachView struct {
	c              *configuration
	lane           string
	out, errOut    io.Writer
	terminal, echo bool
	buffer         []byte
	cursor         int
	continued      []string
	prompt         string
	pending        string
	fresh          bool
	busy           string
	message        int
	keys           int
	during         int
	firstKey       time.Time
	stopRequested  bool
	started        map[int]bool
	results        chan attachResult
	done           <-chan struct{}
	history        []string
	historyPos     int
	drawing        atomic.Bool
}

func (v *attachView) somethingTyped() bool { return len(v.buffer) > 0 || len(v.continued) > 0 }
func (v *attachView) typing() bool         { return len(v.buffer) > 0 }

func (v *attachView) put(text string) {
	if text == "" {
		return
	}
	if _, err := io.WriteString(v.out, text); err == nil {
		v.fresh = strings.HasSuffix(text, "\n")
	}
}
func (v *attachView) emit(text string) {
	if v.prompt == "" {
		v.put(text)
		return
	}
	v.pending += text
	if v.terminal && v.typing() {
		return
	}
	at := strings.LastIndexByte(v.pending, '\n')
	if at < 0 {
		return
	}
	complete := v.pending[:at+1]
	v.pending = v.pending[at+1:]
	if v.terminal {
		v.put("\n\x1b[A\r\x1b[K" + complete + v.prompt)
	} else {
		v.put("\n" + complete + v.prompt)
	}
}
func (v *attachView) say(text string) { v.emit(text + "\n") }
func (v *attachView) endLine() {
	v.prompt = ""
	v.put(v.pending)
	v.pending = ""
	if !v.fresh {
		v.put("\n")
	}
}
func (v *attachView) showPrompt() {
	if v.busy != "" {
		return
	}
	// A key during the held-output flush acts at this prompt. Only keys that
	// arrive during the draw itself wait for Enter or another key.
	v.endLine()
	v.drawing.Store(true)
	defer v.drawing.Store(false)
	v.prompt = "attach> "
	if len(v.continued) > 0 {
		v.prompt = "... "
	}
	v.put(v.prompt)
	if v.echo && len(v.buffer) > 0 {
		v.put(string(v.buffer))
	}
}
func (v *attachView) redraw() {
	if len(v.buffer) == 0 {
		v.emit("")
	}
	if !v.terminal || !v.echo {
		return
	}
	v.put("\r\x1b[K" + v.prompt + string(v.buffer))
	if v.cursor < len(v.buffer) {
		tail := utf8.RuneCount(v.buffer[v.cursor:])
		if tail > 0 {
			v.put(fmt.Sprintf("\x1b[%dD", tail))
		}
	}
}
func (v *attachView) request(kind, text string, fn func() (object, error)) {
	v.busy = kind
	v.keys = 0
	v.during = 0
	v.firstKey = time.Time{}
	v.stopRequested = false
	go func() {
		result, err := fn()
		select {
		case v.results <- attachResult{kind: kind, value: result, err: err, text: text}:
		case <-v.done:
		}
	}()
}
func (v *attachView) startTurn() {
	a := arguments{action: "turn", values: map[string]string{"lane": v.lane}, flags: map[string]bool{}}
	v.request("turn", "", func() (object, error) { return turn(v.c, a, nil, nil) })
}
func (v *attachView) handle(text string) *int {
	v.message = 0
	if text == "" {
		v.showPrompt()
		return nil
	}
	if strings.HasPrefix(text, "/") {
		switch strings.TrimRight(text, " \t\r\n") {
		case "/exit":
			code := 0
			return &code
		case "/help":
			v.say(attachHelp)
			v.showPrompt()
		case "/turn":
			v.startTurn()
		case "/stop":
			return v.interrupt(false)
		default:
			if rule, _ := findCredential(text); rule != "" {
				v.say("not sent: the line is not a command (type /help); it holds a credential shape, which is not repeated")
			} else {
				v.say("not sent: " + cutText(shown(text), 60) + " is not a command (type /help)")
			}
			v.showPrompt()
		}
		return nil
	}
	if !utf8.ValidString(text) {
		v.say("not sent: the line is not valid UTF-8 text")
		v.showPrompt()
		return nil
	}
	v.request("send", text, func() (object, error) { return sendMessage(v.c, v.lane, "attach", []byte(text)) })
	return nil
}
func (v *attachView) liveRun() (int, error) {
	s, err := openSession(v.c, false)
	if err != nil {
		return 0, err
	}
	defer s.close()
	row, err := s.known(v.lane)
	if err != nil {
		return 0, err
	}
	if flag(row["running"]) {
		return integer(row["run"]), nil
	}
	return 0, nil
}
func (v *attachView) interrupt(discarded bool) *int {
	counted := v.keys
	typed := v.somethingTyped()
	v.buffer = nil
	v.cursor = 0
	v.continued = nil
	v.endLine()
	v.request("interrupt", "", func() (object, error) {
		run, err := v.liveRun()
		return object{"run": run, "discarded": discarded, "typed": typed}, err
	})
	v.keys = counted
	return nil
}
func (v *attachView) beginStop(run int) {
	v.say(fmt.Sprintf("stopping run %d", run))
	v.busy = "stop"
	v.keys = 0
	v.during = 0
	v.firstKey = time.Time{}
	v.stopRequested = false
	go func() {
		value, err := stopAttachedRun(v.c, v.lane, run, func() {
			select {
			case v.results <- attachResult{kind: "stop-request", run: run}:
			case <-v.done:
			}
		})
		select {
		case v.results <- attachResult{kind: "stop", value: value, err: err, run: run}:
		case <-v.done:
		}
	}()
}
func (v *attachView) key() *int {
	if v.busy == "" {
		return v.interrupt(true)
	}
	if v.busy == "stop" && v.stopRequested {
		v.endLine()
		v.say("leaving attach; the stop request stands, and the supervising process finishes the stop")
		code := 130
		return &code
	}
	v.keys++
	v.during++
	if v.during == 1 {
		v.firstKey = time.Now()
		if v.busy == "send" || v.busy == "turn" {
			v.say(keyNotice)
		}
	} else if (v.busy == "send" || v.busy == "turn") && time.Since(v.firstKey) >= 2*time.Second {
		v.endLine()
		if v.busy == "turn" {
			what := "a turn"
			if v.message > 0 {
				what = fmt.Sprintf("a turn for message %d", v.message)
			}
			v.say(fmt.Sprintf("leaving attach; %s may be starting, and it was not stopped: see lane status, and lane stop --lane %s stops it", what, v.lane))
		} else {
			v.say("leaving attach; the lane command that was running may not be finished; see lane status")
		}
		code := 130
		return &code
	}
	return nil
}
func (v *attachView) signal(event attachSignal) *int {
	if event.value != syscall.SIGINT {
		code := 128 + int(event.value.(syscall.Signal))
		return &code
	}
	if event.drawing {
		v.keys++
		return nil
	}
	return v.key()
}
func (v *attachView) result(r attachResult) *int {
	if r.kind == "stop-request" {
		v.stopRequested = true
		v.say(fmt.Sprintf("stop requested for run %d; press Ctrl-C again to stop waiting (the request stands)", r.run))
		if v.keys > 0 {
			v.endLine()
			v.say("leaving attach; the stop request stands, and the supervising process finishes the stop")
			code := 130
			return &code
		}
		return nil
	}
	keys := v.keys
	v.busy = ""
	v.keys = 0
	switch r.kind {
	case "interrupt":
		if r.err != nil {
			v.say("note: " + safeDetail(r.err))
			v.say(attachHint)
			v.showPrompt()
			return nil
		}
		run := integer(r.value["run"])
		if run == 0 {
			hint := attachHintText(flag(r.value["discarded"]), r.value["typed"])
			v.say(hint)
			v.showPrompt()
		} else if v.started[run] {
			v.beginStop(run)
			if keys > 0 {
				v.keys = keys
			}
		} else {
			v.say(fmt.Sprintf("leaving attach: run %d was not started by this attach, and goes on", run))
			code := 130
			return &code
		}
	case "send":
		if r.err != nil {
			v.say("not sent: " + safeDetail(r.err))
			if rule, _ := findCredential(r.text); rule == "" {
				v.say("your line: " + shown(r.text))
				if v.terminal && !strings.Contains(r.text, "\n") {
					v.buffer = []byte(r.text)
					v.cursor = len(v.buffer)
				}
			}
			v.showPrompt()
		} else {
			v.message = integer(r.value["sequence"])
			v.say(fmt.Sprintf("message %d sent", v.message))
			v.startTurn()
			if keys > 0 {
				v.keys = keys
				v.firstKey = time.Now()
			}
		}
	case "turn":
		if r.err != nil {
			if v.message > 0 {
				v.say(fmt.Sprintf("message %d queued: %s", v.message, safeDetail(r.err)))
				v.say("it goes with the next turn; attach does not start that turn (type /turn once the live turn has ended)")
			} else {
				v.say("no turn started: " + safeDetail(r.err))
			}
			v.showPrompt()
		} else if !flag(r.value["started"]) {
			v.say("no turn started: no message waits")
			v.showPrompt()
		} else {
			run := integer(r.value["run"])
			v.started[run] = true
			numbers := []string{}
			for _, n := range array(obj(r.value["turn"])["mail"]) {
				numbers = append(numbers, fmt.Sprint(integer(n)))
			}
			v.say(fmt.Sprintf("turn started: run %d (messages %s)", run, strings.Join(numbers, ", ")))
			if keys > 0 {
				v.interrupt(false)
			} else {
				v.showPrompt()
			}
		}
	case "stop":
		if r.err != nil {
			if p, ok := r.err.(*problem); ok && strings.Contains(p.message, "not going on") {
				v.say(fmt.Sprintf("run %d had ended; nothing was stopped", r.run))
				v.showPrompt()
				return nil
			}
			code := reportError(v.errOut, r.err)
			return &code
		}
		v.say(fmt.Sprintf("run %d ended with reason %s; survivors %d", r.run, str(r.value["reason"]), integer(r.value["survivors"])))
		v.showPrompt()
	}
	if keys > 0 && v.busy == "" && r.kind != "interrupt" && r.kind != "stop" {
		return v.interrupt(false)
	}
	return nil
}
func runAttach(c *configuration, a arguments, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	lane := a.get("lane")
	s, err := openSession(c, false)
	if err != nil {
		return reportError(stderr, err)
	}
	row, err := s.known(lane)
	if err != nil {
		s.close()
		return reportError(stderr, err)
	}
	previous, err := s.latest(lane)
	if err != nil {
		s.close()
		return reportError(stderr, err)
	}
	runner := obj(obj(c.data["runners"])[str(previous["runner"])])
	stream := str(runner["stream"])
	if stream == "" {
		stream = "text"
	}
	mode, err := scanMode(s, lane, stream, row)
	if err != nil {
		mode = ""
	}
	s.close()
	restore := func() {}
	terminal, echo := false, false
	if f, ok := stdin.(*os.File); ok {
		restore, terminal, echo = terminalMode(f)
	}
	defer restore()
	done := make(chan struct{})
	defer close(done)
	v := &attachView{c: c, lane: lane, out: stdout, errOut: stderr, terminal: terminal, echo: echo, fresh: true, started: map[int]bool{}, results: make(chan attachResult, 8), done: done}
	sessionID := str(previous["session_id"])
	if sessionID == "" {
		sessionID = "none"
	}
	v.say(shown(fmt.Sprintf("lane %s: state %s, run %d, session %s, runner %s, model %s", lane, str(row["state"]), integer(row["run"]), sessionID, screened(str(row["runner"])), screened(str(row["model"])))))
	if !flag(obj(row["mail"])["turn_based"]) {
		v.say("this lane is not turn-based: attach is a view only here, and a typed line is refused by lane send")
	}
	if mode == "" {
		v.say("permission mode: not reported yet")
	} else {
		v.emit(modeLines(mode))
	}
	if !flag(row["running"]) {
		v.say(displayStatus(row))
	}
	seen := integer(row["run"])
	if flag(row["running"]) {
		seen--
	}
	output := make(chan string, 64)
	follower := &attachFollower{c: c, lane: lane, stream: stream, mode: mode, seen: seen, send: output, stop: done}
	go follower.follow()
	inputs := make(chan inputChunk, 64)
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := stdin.Read(buffer)
			if n > 0 {
				chunk := append([]byte{}, buffer[:n]...)
				select {
				case inputs <- inputChunk{data: chunk, drawing: v.drawing.Load()}:
				case <-done:
					return
				}
			}
			if err != nil {
				select {
				case inputs <- inputChunk{err: err}:
				case <-done:
				}
				return
			}
		}
	}()
	rawSignals := make(chan os.Signal, 8)
	signals := make(chan attachSignal, 8)
	signal.Notify(rawSignals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(rawSignals)
	go func() {
		for {
			select {
			case sig := <-rawSignals:
				event := attachSignal{value: sig, drawing: v.drawing.Load()}
				select {
				case signals <- event:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}()
	defer v.endLine()
	v.showPrompt()
	escape := ""
	queued := []byte{}
	eof := false
	for {
		if v.busy == "" && len(queued) > 0 {
			chunk := queued
			queued = nil
			for i, ch := range chunk {
				if v.busy != "" {
					queued = append(queued, chunk[i:]...)
					break
				}
				if code := v.byte(ch, &escape); code != nil {
					return *code
				}
			}
			continue
		}
		if eof && v.busy == "" {
			if len(v.buffer) > 0 || len(v.continued) > 0 {
				text := strings.Join(append(v.continued, string(v.buffer)), "\n")
				v.buffer = nil
				v.cursor = 0
				v.continued = nil
				v.endLine()
				if code := v.handle(text); code != nil {
					return *code
				}
				continue
			}
			select {
			case sig := <-signals:
				if code := v.signal(sig); code != nil {
					return *code
				}
			case <-time.After(200 * time.Millisecond):
				return 0
			}
			continue
		}
		select {
		case sig := <-signals:
			if code := v.signal(sig); code != nil {
				return *code
			}
		case text := <-output:
			v.emit(text)
		case result := <-v.results:
			if code := v.result(result); code != nil {
				return *code
			}
		case chunk := <-inputs:
			if chunk.err != nil {
				eof = true
				continue
			}
			for _, ch := range chunk.data {
				if v.busy != "" && ch != 3 {
					queued = append(queued, ch)
					continue
				}
				if ch == 3 && chunk.drawing {
					v.keys++
					continue
				}
				if code := v.byte(ch, &escape); code != nil {
					return *code
				}
			}
		}
	}
}
func (v *attachView) byte(ch byte, escape *string) *int {
	if ch == 3 {
		return v.key()
	}
	if *escape != "" {
		*escape += string(ch)
		if len(*escape) < 3 {
			return nil
		}
		seq := *escape
		if ch >= '0' && ch <= '9' && len(seq) < 8 {
			return nil
		}
		*escape = ""
		switch seq {
		case "\x1b[A":
			if len(v.history) > 0 {
				v.historyPos = max(0, v.historyPos-1)
				v.buffer = []byte(v.history[v.historyPos])
				v.cursor = len(v.buffer)
				v.redraw()
			}
		case "\x1b[B":
			v.historyPos = min(len(v.history), v.historyPos+1)
			v.buffer = nil
			if v.historyPos < len(v.history) {
				v.buffer = []byte(v.history[v.historyPos])
			}
			v.cursor = len(v.buffer)
			v.redraw()
		case "\x1b[D":
			if v.cursor > 0 {
				_, size := utf8.DecodeLastRune(v.buffer[:v.cursor])
				v.cursor -= size
				v.redraw()
			}
		case "\x1b[C":
			if v.cursor < len(v.buffer) {
				_, size := utf8.DecodeRune(v.buffer[v.cursor:])
				v.cursor += size
				v.redraw()
			}
		case "\x1b[3~":
			if v.cursor < len(v.buffer) {
				_, size := utf8.DecodeRune(v.buffer[v.cursor:])
				v.buffer = append(v.buffer[:v.cursor], v.buffer[v.cursor+size:]...)
				v.redraw()
			}
		}
		return nil
	}
	if ch == 27 && v.terminal {
		*escape = "\x1b"
		return nil
	}
	switch ch {
	case 4:
		if len(v.buffer) == 0 {
			code := 0
			return &code
		}
		if v.cursor < len(v.buffer) {
			_, size := utf8.DecodeRune(v.buffer[v.cursor:])
			v.buffer = append(v.buffer[:v.cursor], v.buffer[v.cursor+size:]...)
			v.redraw()
		}
		return nil
	case '\r', '\n':
		text := string(v.buffer)
		if v.terminal {
			// The line editor's newline belongs to a continuation prompt's
			// draw, but the pending output that follows it does not.
			continuing := strings.HasSuffix(text, "\\")
			v.drawing.Store(continuing)
			v.put("\n")
			v.drawing.Store(false)
		}
		v.buffer = nil
		v.cursor = 0
		v.endLine()
		if strings.HasSuffix(text, "\\") {
			v.continued = append(v.continued, strings.TrimSuffix(text, "\\"))
			v.showPrompt()
			return nil
		}
		if len(v.continued) > 0 {
			text = strings.Join(append(v.continued, text), "\n")
			v.continued = nil
		}
		if rule, _ := findCredential(text); text != "" && rule == "" {
			v.history = append(v.history, text)
			v.historyPos = len(v.history)
		}
		return v.handle(text)
	case 127, 8:
		if v.cursor > 0 {
			_, size := utf8.DecodeLastRune(v.buffer[:v.cursor])
			v.buffer = append(v.buffer[:v.cursor-size], v.buffer[v.cursor:]...)
			v.cursor -= size
			v.redraw()
		}
		return nil
	case 1:
		v.cursor = 0
		v.redraw()
		return nil
	case 5:
		v.cursor = len(v.buffer)
		v.redraw()
		return nil
	case 21:
		v.buffer = v.buffer[v.cursor:]
		v.cursor = 0
		v.redraw()
		return nil
	}
	if ch < 32 && ch != '\t' {
		return nil
	}
	if len(v.buffer) >= maxMessage+1 {
		return nil
	}
	v.buffer = append(v.buffer[:v.cursor], append([]byte{ch}, v.buffer[v.cursor:]...)...)
	v.cursor++
	if v.terminal && v.echo {
		if v.cursor == len(v.buffer) {
			v.put(string([]byte{ch}))
		} else {
			v.redraw()
		}
	}
	return nil
}
func stopAttachedRun(c *configuration, lane string, run int, onRequest func()) (object, error) {
	s, err := openSession(c, false)
	if err != nil {
		return nil, err
	}
	defer s.close()
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	p, err := s.latest(lane)
	if err != nil {
		return nil, err
	}
	if p == nil || p["run"] == nil || integer(p["run"]) != run || !flag(row["running"]) {
		return nil, refused("run %d is not going on, so nothing was stopped", run)
	}
	if err = checkSocket(str(obj(p["session"])["socket"])); err != nil {
		return nil, err
	}
	record, err := s.record(lane, str(p["launch"]))
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, refused("the lane's run has no run record; nothing could be signalled")
	}
	alive, err := processAlive(obj(record["supervisor"]))
	if err != nil {
		return nil, err
	}
	if alive {
		sent, err := signalChecked(obj(record["supervisor"]), syscall.SIGTERM)
		if err != nil {
			return nil, err
		}
		if !sent {
			return nil, refused("the supervising process could not be signalled; nothing was stopped")
		}
		onRequest()
	}
	deadline := time.Now().Add(time.Duration((c.setting("lanes", "stop_grace_seconds", 10) + 30) * float64(time.Second)))
	for {
		if err = s.refresh(); err != nil {
			return nil, err
		}
		e, err := s.store.last(lane, "lane.ended")
		if err != nil {
			return nil, err
		}
		if e != nil && integer(obj(e["payload"])["run"]) == run {
			return obj(e["payload"]), nil
		}
		data, readErr := s.state.read("lanes/"+lane+"/pending.jsonl", 16*1024*1024)
		if readErr == nil {
			for _, line := range bytes.Split(data, []byte{'\n'}) {
				event, err := decodeJSON(line)
				if err == nil && event["kind"] == "lane.ended" && integer(obj(event["payload"])["run"]) == run {
					return obj(event["payload"]), nil
				}
			}
		}
		alive, err = processAlive(obj(record["supervisor"]))
		if err != nil {
			return nil, err
		}
		if !alive {
			record, err = s.record(lane, str(p["launch"]))
			if err != nil {
				return nil, err
			}
			known := recordMembers(record)
			_, survivors, err := stopIdentities(&known, c.setting("lanes", "stop_grace_seconds", 10), func() ([]object, error) {
				return discoverProcesses(known, integer(obj(record["runner"])["pid"]), false)
			})
			if err != nil {
				return nil, err
			}
			if err = checkLost(s, lane); err != nil {
				return nil, err
			}
			return object{"run": run, "reason": "lost", "survivors": len(survivors)}, nil
		}
		if time.Now().After(deadline) {
			return nil, refused("the supervising process has not finished the stop; the request stands")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
