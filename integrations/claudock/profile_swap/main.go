// Command profile_swap selects quota and resumes the same Claude Code history.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/claudockcli"
)

const defaultPrompt = "Continue the same session from where it stopped."
const header = "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC"
const nameError = "profile names must be nonempty, contain no controls, and not start with '-'"

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")
var limits = []*regexp.Regexp{
	regexp.MustCompile(`^You['’]ve hit your (?:limit|usage limit|session limit|weekly limit|Opus limit|Sonnet limit)(?:[.!]| · (?:resets|limit resets) [^\r\n]+)?(?: · progress saved)?$`),
	regexp.MustCompile(`^Usage limit reached(?: · limit resets [^\r\n]+)?$`),
}

type settings struct {
	exclude, prefer []string
	maxUsed         float64
	includeConsole  bool
}
type window struct {
	used  float64
	reset *time.Time
}
type profile struct {
	name, plan string
	windows    []window
}

func (p profile) console() bool { return p.plan == "Console API" }
func (p profile) tightest() float64 {
	v := 0.0
	for _, w := range p.windows {
		v = math.Max(v, w.used)
	}
	return v
}
func (p profile) freeAt(threshold float64) *time.Time {
	if threshold == 0 {
		return nil
	}
	var latest *time.Time
	for _, w := range p.windows {
		if w.used >= threshold {
			if w.reset == nil {
				return nil
			}
			if latest == nil || w.reset.After(*latest) {
				latest = w.reset
			}
		}
	}
	return latest
}
func validName(s string) bool {
	if strings.TrimSpace(s) == "" || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if r < 32 || (r >= 127 && r <= 159) {
			return false
		}
	}
	return true
}
func expand(s string) string {
	if s == "~" || strings.HasPrefix(s, "~/") {
		if h, e := os.UserHomeDir(); e == nil {
			return filepath.Join(h, strings.TrimPrefix(strings.TrimPrefix(s, "~"), "/"))
		}
	}
	return s
}
func number(s string) (float64, error) {
	return strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(s), "_", ""), 64)
}
func finite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func names(d map[string]any, key string) ([]string, error) {
	v, ok := d[key]
	if !ok {
		return nil, nil
	}
	array, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("settings %s must be an array of profile names", key)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, item := range array {
		s, ok := item.(string)
		if !ok || !validName(s) {
			return nil, fmt.Errorf("settings %s: %s", key, nameError)
		}
		if seen[s] {
			return nil, fmt.Errorf("settings %s must not repeat a profile name", key)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}
func readSettings(file string, override *float64, console bool) (settings, error) {
	s := settings{maxUsed: 85}
	d := map[string]any{}
	if file != "" {
		raw, e := os.ReadFile(expand(file))
		if e != nil || !utf8.Valid(raw) {
			return s, errors.New("cannot read settings as TOML")
		}
		if _, e = toml.Decode(string(raw), &d); e != nil {
			return s, errors.New("cannot read settings as TOML")
		}
	}
	for key := range d {
		if key != "exclude" && key != "max_used_percent" && key != "prefer" && key != "include_console" {
			return s, errors.New("settings contain an unknown key")
		}
	}
	if v, ok := d["max_used_percent"]; ok {
		switch v := v.(type) {
		case int64:
			s.maxUsed = float64(v)
		case float64:
			s.maxUsed = v
		default:
			return s, errors.New("settings max_used_percent must be a number from 0 to 100")
		}
		if !finite(s.maxUsed) || s.maxUsed < 0 || s.maxUsed > 100 {
			return s, errors.New("settings max_used_percent: percentage must be a finite number from 0 to 100")
		}
	}
	if v, ok := d["include_console"]; ok {
		b, ok := v.(bool)
		if !ok {
			return s, errors.New("settings include_console must be true or false")
		}
		s.includeConsole = b
	}
	var e error
	s.exclude, e = names(d, "exclude")
	if e != nil {
		return s, e
	}
	s.prefer, e = names(d, "prefer")
	if e != nil {
		return s, e
	}
	if override != nil {
		s.maxUsed = *override
	}
	s.includeConsole = s.includeConsole || console
	return s, nil
}
func resetTime(s string) (*time.Time, error) {
	switch s {
	case "", "-", "—", "unknown":
		return nil, nil
	}
	if len(s) > 10 && s[10] == ' ' {
		s = s[:10] + "T" + s[11:]
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700", "2006-01-02T15:04:05.999999999-07", "2006-01-02T15:04-07:00"} {
		if t, e := time.Parse(layout, s); e == nil {
			t = t.UTC()
			return &t, nil
		}
	}
	return nil, errors.New("claudock usage has an invalid reset time; expected an ISO timestamp with a time zone")
}
func parseUsage(text string) ([]profile, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) == 0 || lines[0] != header {
		return nil, errors.New("claudock usage has an invalid TSV header")
	}
	profiles := []profile{}
	indices := map[string]int{}
	now := time.Now()
	for index, line := range lines[1:] {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		row := index + 2
		if len(fields) != 5 {
			return nil, fmt.Errorf("claudock usage row %d must have five TSV columns", row)
		}
		name, plan, win := fields[0], fields[1], fields[2]
		used, e := number(strings.TrimSuffix(fields[3], "%"))
		if !validName(name) || e != nil {
			return nil, fmt.Errorf("claudock usage row %d has an invalid profile or percentage", row)
		}
		if plan == "" || win == "" || !finite(used) || used < 0 {
			return nil, fmt.Errorf("claudock usage row %d has an invalid window or percentage", row)
		}
		i, ok := indices[name]
		if ok && profiles[i].plan != plan {
			return nil, fmt.Errorf("claudock usage row %d has inconsistent profile plan values", row)
		}
		reset, e := resetTime(fields[4])
		if e != nil {
			return nil, e
		}
		if reset != nil && !reset.After(now) {
			used = 0
		}
		if !ok {
			i = len(profiles)
			indices[name] = i
			profiles = append(profiles, profile{name: name, plan: plan})
		}
		profiles[i].windows = append(profiles[i].windows, window{used, reset})
	}
	return profiles, nil
}
func choose(profiles []profile, s settings, excluded map[string]bool) (profile, error) {
	eligible := []profile{}
	consoleCount := 0
	for _, p := range profiles {
		if excluded[p.name] {
			continue
		}
		if !s.includeConsole && p.console() {
			consoleCount++
			continue
		}
		eligible = append(eligible, p)
	}
	preference := map[string]int{}
	for i, n := range s.prefer {
		preference[n] = i
	}
	rank := func(a, b profile) bool {
		if a.console() != b.console() {
			return !a.console()
		}
		if a.tightest() != b.tightest() {
			return a.tightest() < b.tightest()
		}
		ai, ok := preference[a.name]
		if !ok {
			ai = len(preference)
		}
		bi, ok := preference[b.name]
		if !ok {
			bi = len(preference)
		}
		if ai != bi {
			return ai < bi
		}
		return a.name < b.name
	}
	sort.SliceStable(eligible, func(i, j int) bool { return rank(eligible[i], eligible[j]) })
	for _, p := range eligible {
		if p.tightest() < s.maxUsed {
			return p, nil
		}
	}
	note := ""
	if consoleCount > 0 {
		note = fmt.Sprintf("; Console API profiles excluded: %d (per-token billing; opt in with --include-console or include_console = true)", consoleCount)
	}
	prefix := fmt.Sprintf("no profile under %g%%: next to free up is ", s.maxUsed)
	if len(eligible) == 0 {
		return profile{}, errors.New(prefix + "none at unknown (no eligible profiles)" + note)
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		a, b := eligible[i].freeAt(s.maxUsed), eligible[j].freeAt(s.maxUsed)
		if a == nil || b == nil {
			if (a == nil) != (b == nil) {
				return a != nil
			}
			return rank(eligible[i], eligible[j])
		}
		if !a.Equal(*b) {
			return a.Before(*b)
		}
		return rank(eligible[i], eligible[j])
	})
	p := eligible[0]
	stamp := "unknown"
	if t := p.freeAt(s.maxUsed); t != nil {
		stamp = t.Format("2006-01-02T15:04:05Z")
		if t.Nanosecond() != 0 {
			stamp = t.Format("2006-01-02T15:04:05.000000Z")
		}
	}
	return profile{}, errors.New(prefix + p.name + " at " + stamp + note)
}
func messageTexts(line string) []string {
	clean := strings.TrimSpace(sgr.ReplaceAllString(line, ""))
	if !strings.HasPrefix(clean, "{") {
		return []string{clean}
	}
	var event map[string]any
	if json.Unmarshal([]byte(clean), &event) != nil {
		return nil
	}
	texts := []string{}
	if event["type"] == "result" && event["is_error"] == true {
		if s, ok := event["result"].(string); ok {
			texts = append(texts, s)
		}
		if es, ok := event["errors"].([]any); ok {
			for _, e := range es {
				if s, ok := e.(string); ok {
					texts = append(texts, s)
				}
			}
		}
	}
	if event["type"] == "assistant" && event["error"] == "rate_limit" {
		if m, ok := event["message"].(map[string]any); ok {
			if blocks, ok := m["content"].([]any); ok {
				for _, b := range blocks {
					if b, ok := b.(map[string]any); ok && b["type"] == "text" {
						if s, ok := b["text"].(string); ok {
							texts = append(texts, s)
						}
					}
				}
			}
		}
	}
	return texts
}
func limited(file string) (int, error) {
	f, e := os.Open(expand(file))
	if e != nil {
		return 2, errors.New("cannot read log as UTF-8")
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	found := false
	for {
		line, e := reader.ReadString('\n')
		if !utf8.ValidString(line) {
			return 2, errors.New("cannot read log as UTF-8")
		}
		for _, message := range messageTexts(line) {
			for _, part := range strings.FieldsFunc(message, func(r rune) bool {
				return r == '\n' || r == '\r' || r == '\v' || r == '\f' || r == '\u0085' || r == '\u2028' || r == '\u2029'
			}) {
				clean := strings.TrimSpace(sgr.ReplaceAllString(part, ""))
				for _, pattern := range limits {
					if pattern.MatchString(clean) {
						found = true
					}
				}
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return 2, errors.New("cannot read log as UTF-8")
		}
	}
	if found {
		return 0, nil
	}
	return 1, nil
}
func fail(e error) int { fmt.Fprintln(os.Stderr, "profile_swap: "+e.Error()); return 2 }
func help(command string) {
	switch command {
	case "pick":
		fmt.Println("usage: profile_swap.py pick [-h] [--exclude NAME] [--settings FILE] [--max-used PCT] [--max-age S] [--include-console]\n\nPrint the profile with the most quota headroom.")
	case "resume":
		fmt.Println("usage: profile_swap.py resume [-h] (--session ID | --continue) --from NAME [--cwd DIR] [--exclude NAME] [--settings FILE] [--max-used PCT] [--max-age S] [--include-console] [--prompt TEXT] [--dry-run]\n\nAfter --, CLAUDE_ARGS go unchanged to Claude Code. --continue resumes the newest session in --cwd and needs one session per directory. No cross-provider override is added.")
	case "limited":
		fmt.Println("usage: profile_swap.py limited [-h] LOG\n\nExit 0 for a recognized usage/session-limit log, 1 otherwise.")
	default:
		fmt.Println("usage: profile_swap.py [-h] {pick,resume,limited} ...\n\nMove the same Claude Code session between Claudock profiles.\n\npick     Print the profile with the most quota headroom.\nresume   Resume the same session on a profile other than --from.\nlimited  Exit 0 for a recognized usage/session-limit log, 1 otherwise.\n\nClaudock profiles must share history. The cross-provider resume guard stays enabled.")
	}
}
func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() { <-signals; fmt.Fprintln(os.Stderr, "profile_swap: interrupted"); os.Exit(130) }()
	os.Exit(run(os.Args[1:]))
}
func run(args []string) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		help("")
		return 0
	}
	if len(args) == 0 {
		return fail(errors.New("the following arguments are required: command"))
	}
	command := args[0]
	if command != "pick" && command != "resume" && command != "limited" {
		return fail(errors.New("unknown command"))
	}
	args = args[1:]
	var vendor []string
	boundary := false
	for i, arg := range args {
		if arg == "--" {
			vendor = args[i+1:]
			args = args[:i]
			boundary = true
			break
		}
	}
	values := map[string]string{}
	flags := map[string]bool{}
	excludes := []string{}
	positions := []string{}
	allowed := []string{"--help"}
	if command != "limited" {
		allowed = append(allowed, "--exclude", "--settings", "--max-used", "--max-age", "--include-console")
	}
	if command == "resume" {
		allowed = append(allowed, "--session", "--continue", "--from", "--cwd", "--prompt", "--dry-run")
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			help(command)
			return 0
		}
		if !strings.HasPrefix(arg, "--") {
			positions = append(positions, arg)
			continue
		}
		label, v, attached := strings.Cut(arg, "=")
		matched := ""
		for _, key := range allowed {
			if label == key {
				matched = key
				break
			}
			if strings.HasPrefix(key, label) {
				if matched != "" {
					return fail(errors.New("ambiguous option"))
				}
				matched = key
			}
		}
		if matched == "" {
			return fail(errors.New("unrecognized arguments"))
		}
		label = matched
		if label == "--help" {
			if attached {
				return fail(errors.New("argument --help: ignored explicit argument"))
			}
			help(command)
			return 0
		}
		if label == "--include-console" || label == "--continue" || label == "--dry-run" {
			if attached {
				return fail(fmt.Errorf("argument %s: ignored explicit argument", label))
			}
			flags[label] = true
			continue
		}
		if !attached {
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
				return fail(fmt.Errorf("argument %s: expected one argument", label))
			}
			i++
			v = args[i]
		}
		if (label == "--exclude" || label == "--from") && !validName(v) {
			return fail(errors.New(nameError))
		}
		if label == "--max-used" {
			n, err := number(v)
			if err != nil || !finite(n) || n < 0 || n > 100 {
				return fail(errors.New("percentage must be a finite number from 0 to 100"))
			}
		}
		if label == "--max-age" {
			n, err := number(v)
			if err != nil || !finite(n) || n < 0 {
				return fail(errors.New("max age must be a finite nonnegative number of seconds"))
			}
		}
		if label == "--exclude" {
			excludes = append(excludes, v)
		} else {
			values[label] = v
		}
	}
	if boundary && command != "resume" {
		return fail(errors.New("only resume accepts -- CLAUDE_ARGS"))
	}
	if command == "limited" {
		if len(positions) != 1 {
			return fail(errors.New("the following argument is required: LOG"))
		}
		code, e := limited(positions[0])
		if e != nil {
			return fail(e)
		}
		return code
	}
	if len(positions) > 0 {
		return fail(errors.New("unrecognized arguments"))
	}
	var threshold, age *float64
	for _, key := range []string{"--max-used", "--max-age"} {
		if text, ok := values[key]; ok {
			n, e := number(text)
			if key == "--max-used" {
				if e != nil || !finite(n) || n < 0 || n > 100 {
					return fail(errors.New("percentage must be a finite number from 0 to 100"))
				}
				threshold = &n
			} else {
				if e != nil || !finite(n) || n < 0 {
					return fail(errors.New("max age must be a finite nonnegative number of seconds"))
				}
				age = &n
			}
		}
	}
	if command == "resume" {
		_, session := values["--session"]
		if session == flags["--continue"] {
			return fail(errors.New("one of the arguments --session --continue is required"))
		}
		if _, ok := values["--from"]; !ok {
			return fail(errors.New("the following arguments are required: --from"))
		}
	}
	s, e := readSettings(values["--settings"], threshold, flags["--include-console"])
	if e != nil {
		return fail(e)
	}
	excluded := map[string]bool{}
	for _, name := range append(s.exclude, excludes...) {
		excluded[name] = true
	}
	directory, e := os.Getwd()
	if e != nil {
		return fail(errors.New("cannot access directory or start Claudock"))
	}
	if command == "resume" {
		excluded[values["--from"]] = true
		if sid, ok := values["--session"]; ok && (strings.TrimSpace(sid) == "" || strings.HasPrefix(sid, "-")) {
			return fail(errors.New("session id must be nonempty and must not start with '-'"))
		}
		if values["--cwd"] != "" {
			directory = expand(values["--cwd"])
		}
		directory, e = filepath.Abs(directory)
		if e == nil {
			directory, e = filepath.EvalSymlinks(directory)
		}
		if e != nil {
			return fail(errors.New("session directory cannot be resolved"))
		}
		info, e := os.Stat(directory)
		if e != nil {
			return fail(errors.New("session directory cannot be resolved"))
		}
		if !info.IsDir() {
			return fail(errors.New("session directory is not a directory"))
		}
	}
	wrapper, e := claudockcli.Resolve()
	if e != nil {
		return fail(e)
	}
	argv := []string{"usage"}
	if age != nil {
		argv = append(argv, "--max-age", fmt.Sprintf("%g", *age))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrapper, argv...)
	cmd.Dir = directory
	out, e := cmd.Output()
	if ctx.Err() != nil {
		return fail(errors.New("claudock usage did not finish within 60 seconds"))
	}
	if e != nil {
		var exit *exec.ExitError
		if errors.As(e, &exit) {
			return fail(fmt.Errorf("claudock usage failed (exit %d); no profile selected", exit.ExitCode()))
		}
		return fail(errors.New("cannot run or decode claudock usage"))
	}
	if !utf8.Valid(out) {
		return fail(errors.New("cannot run or decode claudock usage"))
	}
	profiles, e := parseUsage(string(out))
	if e != nil {
		return fail(e)
	}
	chosen, e := choose(profiles, s, excluded)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 3
	}
	if command == "pick" {
		fmt.Println(chosen.name)
		return 0
	}
	reason := "most room left among subscription profiles"
	if chosen.console() {
		reason = fmt.Sprintf("Console API opt-in; %g%% credit left; most credit share left", 100-chosen.tightest())
	}
	fmt.Fprintf(os.Stderr, "profile_swap: resuming from %s on %s: tightest window %g%% used (< %g%%); %s\n", values["--from"], chosen.name, chosen.tightest(), s.maxUsed, reason)
	runArgv := []string{wrapper, "run", chosen.name, "--", "-p"}
	if flags["--continue"] {
		runArgv = append(runArgv, "-c")
	} else {
		runArgv = append(runArgv, "--resume", values["--session"])
	}
	prompt, ok := values["--prompt"]
	if !ok {
		prompt = defaultPrompt
	}
	runArgv = append(runArgv, prompt)
	runArgv = append(runArgv, vendor...)
	if flags["--dry-run"] {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		if e = enc.Encode(struct {
			Argv []string `json:"argv"`
			Cwd  string   `json:"cwd"`
		}{runArgv, directory}); e != nil {
			return fail(e)
		}
		return 0
	}
	if e = os.Chdir(directory); e == nil {
		e = syscall.Exec(wrapper, runArgv, os.Environ())
	}
	return fail(errors.New("cannot access directory or start Claudock"))
}
