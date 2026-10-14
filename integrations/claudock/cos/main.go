// Command cos is an interactive front for turn-by-turn agent sessions.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/claudockcli"
	"laneboss.io/laneboss/internal/cosprocess"
)

const usage = "usage: cos.py ACCOUNT [MODEL] [--resume SESSION] [--mode default|acceptEdits|plan] [--bypass-permissions]"
const warning = "WARNING: approvals are bypassed: the agent may run any command and change any file it can reach."
const bypass = "bypassPermissions"
const hint = "  (denied: this request ran without approval rights; see /mode)"

var names = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\[\]-]*$`)
var sessionID = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)
var helpLines = []string{"/exit          leave (Ctrl-D does the same); the session can be resumed later", "/help          this list", "/cost          the session's total cost so far", "/session       the session id and how to resume it", "/model NAME    use another model from the next request", "/mode [NAME]   show or set the permission mode: default, acceptEdits or plan", "A line ending in a backslash continues on the next line. Any other line goes to the agent."}

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func text(v any) string           { s, _ := v.(string); return s }
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
func numeric(v any) *float64 {
	n, ok := v.(json.Number)
	if !ok {
		return nil
	}
	f, e := n.Float64()
	if e != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return &f
}
func label(word string, name, input any) string {
	n, ok := name.(string)
	if !ok {
		n = "?"
	}
	detail := ""
	m := object(input)
	for _, key := range []string{"command", "file_path", "pattern", "path", "url"} {
		if s, ok := m[key].(string); ok {
			detail = cut(s, 100)
			break
		}
	}
	result := "  [" + word + " " + n + "]"
	if detail != "" {
		result += " " + detail
	}
	return result
}
func tty(f *os.File) bool {
	_, e := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	return e == nil
}

type session struct {
	wrapper, account, model, sid, mode, reported string
	confirmed, tty, col0, shown, hinted          bool
	turn, held                                   int
	total, prev                                  *float64
	noted, tools                                 map[string]bool
	streamed                                     map[string]string
	result                                       map[string]any
	signals                                      chan os.Signal
}

func (s *session) write(value string) { fmt.Fprint(os.Stdout, value) }
func (s *session) endLine() {
	if s.held > 0 || !s.col0 {
		s.write("\n")
	}
	s.held = 0
	s.col0 = true
}
func (s *session) say(value string, dim bool) {
	s.endLine()
	value = strings.Map(func(r rune) rune {
		if r < 32 || r >= 127 && r <= 159 {
			return ' '
		}
		return r
	}, value)
	if s.tty && dim {
		s.write("\x1b[2m" + value + "\x1b[0m\n")
	} else {
		s.write(value + "\n")
	}
}
func (s *session) answer(value string) {
	value = strings.Map(func(r rune) rune {
		if r < 9 || r >= 11 && r <= 31 || r >= 127 && r <= 159 {
			return -1
		}
		return r
	}, value)
	body := strings.TrimRight(value, "\n")
	if body != "" {
		s.write(strings.Repeat("\n", s.held) + body)
		s.held = len(value) - len(body)
		s.col0 = false
		s.shown = true
	} else {
		s.held += len(value)
	}
}
func (s *session) handle(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	d := json.NewDecoder(strings.NewReader(finiteJSON(line)))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		s.say("[raw] "+line, false)
		return
	}
	if e := d.Decode(new(any)); e != io.EOF {
		s.say("[raw] "+line, false)
		return
	}
	event := object(v)
	switch event["type"] {
	case "system":
		if event["subtype"] != "init" {
			return
		}
		s.confirmed = true
		if mode, ok := event["permissionMode"].(string); ok {
			s.reported = mode
			key := mode + "\x00" + s.mode
			if mode == bypass && s.mode != bypass && !s.noted[key] {
				s.noted[key] = true
				if s.mode != "" {
					s.say("WARNING: the agent reports bypassPermissions although --mode "+s.mode+" was passed.", false)
				}
				s.say(warning, false)
			} else if s.mode == "" && mode != "default" && mode != bypass && !s.noted[key] {
				s.noted[key] = true
				s.say("  [account default permission mode: "+mode+"]", true)
			}
		}
	case "stream_event":
		e := object(event["event"])
		if e["type"] == "message_start" {
			s.streamed = map[string]string{}
			s.endLine()
		} else if e["type"] == "content_block_delta" {
			delta := object(e["delta"])
			value, ok := delta["text"].(string)
			if delta["type"] == "text_delta" && ok {
				key := "0"
				switch index := e["index"].(type) {
				case json.Number:
					if !strings.ContainsAny(index.String(), ".eE") {
						key = index.String()
					}
				case bool:
					if index {
						key = "1"
					}
				}
				s.streamed[key] += value
				s.answer(value)
			}
		}
	case "assistant":
		blocks, _ := object(event["message"])["content"].([]any)
		for _, v := range blocks {
			b := object(v)
			if b["type"] == "text" && text(b["text"]) != "" {
				value := text(b["text"])
				found := false
				for key, printed := range s.streamed {
					if printed == value {
						delete(s.streamed, key)
						found = true
						break
					}
				}
				if !found {
					s.endLine()
					s.answer(value)
				}
			} else if b["type"] == "tool_use" {
				if id, ok := b["id"].(string); ok {
					if s.tools[id] {
						continue
					}
					s.tools[id] = true
				}
				s.say(label("tool", b["name"], b["input"]), true)
			}
		}
	case "result":
		s.result = event
	}
}
func (s *session) finish(started time.Time, code int) {
	s.endLine()
	if s.result == nil {
		s.say(fmt.Sprintf("[turn %d | no result | exit %d]", s.turn, code), true)
		return
	}
	denials, _ := s.result["permission_denials"].([]any)
	count := 0
	for _, v := range denials {
		if d := object(v); d != nil {
			s.say(label("denied", d["tool_name"], d["tool_input"]), true)
			count++
		}
	}
	if count > 0 && !s.hinted {
		s.hinted = true
		s.say(hint, true)
	}
	if s.result["is_error"] == true && !s.shown {
		if result, ok := s.result["result"].(string); ok {
			s.say("  [error] "+cut(result, 200), true)
		}
	}
	this, total := "?", "?"
	if cost := numeric(s.result["total_cost_usd"]); cost != nil {
		if s.prev != nil {
			this = fmt.Sprintf("$%.4f", *cost-*s.prev+0)
		}
		total = fmt.Sprintf("$%.4f", *cost)
		s.prev = cost
		s.total = cost
	}
	s.say(fmt.Sprintf("[turn %d | this turn %s | session %s | %.1f s]", s.turn, this, total, time.Since(started).Seconds()), true)
}
func (s *session) command() []string {
	mode := "--session-id"
	if s.confirmed {
		mode = "--resume"
	}
	args := []string{"run", s.account, "--", "-p", mode, s.sid, "--model", s.model, "--output-format", "stream-json", "--verbose", "--include-partial-messages"}
	if s.mode != "" {
		args = append(args, "--permission-mode", s.mode)
	}
	return args
}
func (s *session) stopped(pid int) (bool, int) {
	if cosprocess.Gone(pid) {
		return false, 0
	}
	s.say("[stopping the request: wait a few seconds, do not press Ctrl-C again]", false)
	left, code := cosprocess.Stop(pid, cosprocess.DefaultWaits, cosprocess.DefaultPS, func(line string) { s.say(line, false) }, s.signals)
	if len(left) > 0 {
		groups := []string{}
		for _, pid := range left {
			groups = append(groups, strconv.Itoa(pid))
		}
		s.say("WARNING: processes of this request may still be running (group "+strings.Join(groups, ", ")+")", false)
	}
	return true, code
}

type lineResult struct {
	line string
	err  error
}

func readLines(r io.Reader, done <-chan struct{}) <-chan lineResult {
	out := make(chan lineResult)
	go func() {
		defer close(out)
		reader := bufio.NewReader(r)
		for {
			line, e := reader.ReadString('\n')
			line = string([]rune(line))
			select {
			case out <- lineResult{line, e}:
			case <-done:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	return out
}
func (s *session) ask(message string) int {
	inputRead, inputWrite, e := os.Pipe()
	if e != nil {
		fmt.Fprintln(os.Stderr, "cos: cannot create request input")
		return 0
	}
	defer inputWrite.Close()
	outputRead, outputWrite, e := os.Pipe()
	if e != nil {
		inputRead.Close()
		fmt.Fprintln(os.Stderr, "cos: cannot create request output")
		return 0
	}
	defer outputRead.Close()
	cmd := exec.Command(s.wrapper, s.command()...)
	cmd.Stdin = inputRead
	cmd.Stdout = outputWrite
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	e = cmd.Start()
	inputRead.Close()
	outputWrite.Close()
	if e != nil {
		fmt.Fprintf(os.Stderr, "cos: cannot start %s: %s\n", s.wrapper, e)
		return 0
	}
	waited := make(chan int, 1)
	go func() {
		e := cmd.Wait()
		code := 0
		if e != nil {
			code = cmd.ProcessState.ExitCode()
			if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				code = -int(status.Signal())
			}
		}
		waited <- code
	}()
	s.turn++
	started := time.Now()
	s.result = nil
	s.shown = false
	s.streamed = map[string]string{}
	s.held = 0
	go func() { io.WriteString(inputWrite, message+"\n"); inputWrite.Close() }()
	done := make(chan struct{})
	defer close(done)
	lines := readLines(outputRead, done)
	var completion <-chan int
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				lines = nil
				completion = waited
				continue
			}
			if line.line != "" {
				s.handle(strings.TrimRight(line.line, "\r\n"))
			}
		case code := <-completion:
			s.finish(started, code)
			return 0
		case sig := <-s.signals:
			stopped, exit := s.stopped(cmd.Process.Pid)
			if sig != syscall.SIGINT {
				return 128 + int(sig.(syscall.Signal))
			}
			if exit != 0 {
				return exit
			}
			if stopped {
				s.say("[interrupted]", true)
			}
			return 0
		}
	}
}
func (s *session) resumeLine() string {
	if !s.confirmed {
		return "no session was started"
	}
	return "session " + s.sid + "  (continue later with: --resume " + s.sid + ")"
}
func (s *session) local(line string) int {
	words := strings.Fields(line)
	if len(words) == 0 || strings.Contains(line, "\n") {
		return 0
	}
	rest := words[1:]
	switch words[0] {
	case "/exit":
		if len(rest) != 0 {
			return 0
		}
		return 2
	case "/help":
		if len(rest) != 0 {
			return 0
		}
		for _, line := range helpLines {
			s.say(line, false)
		}
	case "/cost":
		if len(rest) != 0 {
			return 0
		}
		if s.total == nil {
			s.say("session total: unknown (no request has finished yet)", false)
		} else {
			s.say(fmt.Sprintf("session total so far: $%.4f over %d request(s) in this run", *s.total, s.turn), false)
		}
	case "/session":
		if len(rest) != 0 {
			return 0
		}
		s.say(s.resumeLine(), false)
	case "/model":
		if len(rest) == 0 {
			s.say("model: "+s.model, false)
		} else if len(rest) == 1 && names.MatchString(rest[0]) {
			s.model = rest[0]
			s.say("model: "+s.model+" (from the next request)", false)
		} else {
			s.say("usage: /model NAME  (letters, digits and . _ : [ ] -)", false)
		}
	case "/mode":
		if len(rest) == 1 && rest[0] == bypass {
			s.say("bypass can only be chosen at the start (--bypass-permissions)", false)
		} else if len(rest) == 1 && validMode(rest[0]) {
			s.mode = rest[0]
		} else if len(rest) > 0 {
			s.say("usage: /mode [default|acceptEdits|plan]", false)
		}
		mode := s.mode
		if mode == "" {
			reported := ""
			if s.reported != "" {
				reported = ": " + s.reported
			}
			mode = "none passed (the account's own default applies" + reported + ")"
		}
		s.say("mode: "+mode, false)
		if s.mode == bypass {
			s.say(warning, false)
		}
	default:
		return 0
	}
	return 1
}
func validMode(s string) bool { return s == "default" || s == "acceptEdits" || s == "plan" }
func (s *session) loop() int {
	wrapper, e := claudockcli.Resolve()
	if e != nil {
		fmt.Fprintln(os.Stderr, "cos: "+e.Error())
		return 2
	}
	s.wrapper = wrapper
	s.say(fmt.Sprintf("cos: account %s, model %s, session %s  (type /help for commands)", s.account, s.model, s.sid), false)
	if s.mode == bypass {
		s.say(warning, false)
	} else if s.mode == "" {
		s.say("permission mode: the account's own default (not chosen here); it may be bypassPermissions:", false)
		s.say("the agent may then run any command and change any file. To narrow it: --mode default|acceptEdits|plan, or /mode.", false)
	}
	done := make(chan struct{})
	defer close(done)
	lines := readLines(os.Stdin, done)
	parts := []string{}
	stdinTTY := tty(os.Stdin)
	for {
		if len(parts) > 0 {
			s.write(". ")
		} else {
			s.write("> ")
		}
		select {
		case sig := <-s.signals:
			if sig != syscall.SIGINT {
				return 128 + int(sig.(syscall.Signal))
			}
			parts = nil
			s.write("\n(type /exit or press Ctrl-D to leave)\n")
			continue
		case line, ok := <-lines:
			if !ok || line.err != nil && line.line == "" {
				if stdinTTY {
					s.write("\n")
				}
				s.say(s.resumeLine(), false)
				return 0
			}
			value := strings.TrimSuffix(strings.TrimSuffix(line.line, "\n"), "\r")
			s.col0 = stdinTTY
			if strings.HasSuffix(value, "\\") {
				parts = append(parts, strings.TrimSuffix(value, "\\"))
				continue
			}
			message := strings.Join(append(parts, value), "\n")
			parts = nil
			if strings.TrimSpace(message) == "" {
				continue
			}
			switch s.local(strings.TrimSpace(message)) {
			case 2:
				s.say(s.resumeLine(), false)
				return 0
			case 0:
				if code := s.ask(message); code != 0 {
					return code
				}
			}
		}
	}
}
func usageError(message string) int {
	fmt.Fprintln(os.Stderr, usage)
	fmt.Fprintln(os.Stderr, "cos.py: error: "+message)
	return 2
}
func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	pos := []string{}
	options := map[string]string{}
	chosenBypass := false
	literal := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !literal && arg == "--" {
			literal = true
			continue
		}
		if !literal && (arg == "-h" || arg == "--help") {
			fmt.Println(usage + "\n\npositional arguments:\n  account\n  model\n\noptions:\n  -h, --help\n  --resume SESSION\n  --mode {default,acceptEdits,plan}\n  --bypass-permissions")
			return 0
		}
		if !literal && strings.HasPrefix(arg, "-") {
			label, value, attached := strings.Cut(arg, "=")
			if label == "--bypass-permissions" {
				if attached {
					return usageError("argument --bypass-permissions: ignored explicit argument")
				}
				chosenBypass = true
				continue
			}
			if label != "--mode" && label != "--resume" {
				return usageError("unrecognized arguments: " + arg)
			}
			if !attached {
				if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
					return usageError("argument " + label + ": expected one argument")
				}
				i++
				value = args[i]
			}
			options[label] = value
		} else {
			pos = append(pos, arg)
		}
	}
	if len(pos) == 0 {
		return usageError("the following arguments are required: account")
	}
	if len(pos) > 2 {
		return usageError("unrecognized arguments: " + strings.Join(pos[2:], " "))
	}
	for _, value := range pos {
		if !names.MatchString(value) {
			return usageError(fmt.Sprintf("%q must match [A-Za-z0-9][A-Za-z0-9._:[]-]*", value))
		}
	}
	model := os.Getenv("COS_MODEL")
	if model == "" {
		model = "claude-sonnet-5-5"
	}
	if len(pos) == 2 {
		model = pos[1]
	}
	if !names.MatchString(model) {
		return usageError(fmt.Sprintf("COS_MODEL %q must match [A-Za-z0-9][A-Za-z0-9._:[]-]*", model))
	}
	mode := options["--mode"]
	if _, ok := options["--mode"]; ok && !validMode(mode) {
		return usageError("argument --mode: invalid choice: " + strconv.Quote(mode))
	}
	if chosenBypass && mode != "" {
		return usageError("--mode and --bypass-permissions exclude each other")
	}
	if chosenBypass {
		mode = bypass
	}
	sid, resumed := options["--resume"]
	if resumed && !sessionID.MatchString(sid) {
		return usageError(fmt.Sprintf("argument --resume: %q is not a UUID", sid))
	}
	if !resumed {
		sid = uuid.NewString()
	}
	zero := 0.0
	s := session{account: pos[0], model: model, sid: strings.ToLower(sid), mode: mode, confirmed: resumed, tty: tty(os.Stdout), col0: true, noted: map[string]bool{}, tools: map[string]bool{}, streamed: map[string]string{}, signals: make(chan os.Signal, 16)}
	if !resumed {
		s.prev = &zero
	}
	signal.Notify(s.signals, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	defer signal.Stop(s.signals)
	return s.loop()
}
