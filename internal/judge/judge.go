// Package judge implements the bounded external judge protocol and its egress log.
package judge

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/cliargs"
)

const (
	maxTextBytes        = 1024 * 1024
	maxCharacters       = 4000
	maxEgressBytes      = 64 * 1024 * 1024
	outcomeReserve      = 1024
	batchOutcomeReserve = 4096
	withheldText        = "[withheld]"
	nothingAsked        = "nothing was asked"
	outcomeUnlogged     = "the ask was sent and its sending is logged, but its outcome could not be logged"
)

var (
	namePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	questionPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	subjectPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	lanePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	askPattern        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	recordedPattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)
	timestampPattern  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)
)

type commandError struct {
	code            int
	prefix, message string
}

func (e *commandError) Error() string    { return e.prefix + ": " + e.message }
func refused(message string) error       { return &commandError{2, "refused", message} }
func integrity(message string) error     { return &commandError{3, "integrity problem", message} }
func egressProblem(message string) error { return &commandError{7, "egress problem", message} }

type options struct {
	action, config, judge, question, promptFile, lane, since string
	configSet, laneSet, sinceSet, questionSet                bool
	subjects                                                 []textPair
}
type textPair struct{ name, text string }

// Run executes laneboss judge ARGS and returns the process exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	_ = stdin // Judge texts come from files, never from the launcher's input stream.
	o, help, err := parseOptions(args)
	if help {
		fmt.Fprintln(stdout, "usage: laneboss judge {list|ask|egress} --config NAME\nask: --judge NAME --question ID --prompt-file FILE --subject NAME=FILE [--lane LANE]\negress: [--since TIME]\nLANEBOSS_JUDGE_MAX_EGRESS_BYTES can lower the 64 MiB log cap.")
		return 0
	}
	code := 0
	if err == nil {
		code, err = execute(o, stdout, stderr)
	}
	if err != nil {
		var ce *commandError
		if errors.As(err, &ce) {
			fmt.Fprintln(stderr, ce.Error())
			return ce.code
		}
		fmt.Fprintln(stderr, "internal error: the judge command could not be completed")
		return 70
	}
	return code
}

func parseOptions(args []string) (options, bool, error) {
	var o options
	if len(args) == 0 {
		return o, false, refused(cliargs.Required("ACTION"))
	}
	if args[0] == "--help" || args[0] == "-h" {
		return o, true, nil
	}
	o.action = args[0]
	if o.action != "list" && o.action != "ask" && o.action != "egress" {
		return o, false, refused(cliargs.Reject("ACTION"))
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			return o, true, nil
		}
		key, value, equal := strings.Cut(arg, "=")
		allowed := key == "--config" || (o.action == "egress" && key == "--since") || (o.action == "ask" && (key == "--judge" || key == "--question" || key == "--prompt-file" || key == "--subject" || key == "--lane"))
		if !allowed {
			return o, false, refused(cliargs.Reject(""))
		}
		if !equal {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return o, false, refused(cliargs.Expected(key))
			}
			i++
			value = args[i]
		}
		switch key {
		case "--config":
			o.config, o.configSet = value, true
		case "--judge":
			o.judge = value
		case "--question":
			o.question, o.questionSet = value, true
		case "--prompt-file":
			o.promptFile = value
		case "--lane":
			o.lane, o.laneSet = value, true
		case "--since":
			o.since, o.sinceSet = value, true
		case "--subject":
			name, path, ok := strings.Cut(value, "=")
			if !ok || name == "" || path == "" {
				return o, false, refused("--subject must be NAME=FILE")
			}
			for _, pair := range o.subjects {
				if pair.name == name {
					return o, false, refused("--subject names the same text twice")
				}
			}
			o.subjects = append(o.subjects, textPair{name, path})
		}
	}
	if o.action == "ask" && (o.judge == "" || !o.questionSet || o.promptFile == "" || len(o.subjects) == 0) {
		return o, false, refused(cliargs.Required("--judge", "--question", "--prompt-file", "--subject"))
	}
	return o, false, nil
}

func execute(o options, stdout, stderr io.Writer) (int, error) {
	c, err := loadConfiguration(o)
	if err != nil {
		return 0, err
	}
	if o.action == "list" {
		entries := make([]map[string]any, 0, len(c.judges))
		for _, name := range sortedKeys(c.judges) {
			j := c.judges[name]
			entries = append(entries, map[string]any{"name": name, "description": j.description, "program": j.command[0], "timeout_seconds": j.seconds})
		}
		return 0, emitJSON(stdout, entries)
	}
	if o.action == "egress" {
		return 0, readEgress(c, o, stdout)
	}
	for _, pair := range []textPair{{"--judge", o.judge}, {"--question", o.question}, {"--lane", o.lane}} {
		if hasCredential(pair.text) {
			return 0, refused(pair.name + " looks like a credential and is not used (it is not repeated either); " + nothingAsked)
		}
	}
	for _, pair := range o.subjects {
		if hasCredential(pair.name) {
			return 0, refused("a --subject name looks like a credential and is not used (it is not repeated either); " + nothingAsked)
		}
	}
	if !namePattern.MatchString(o.judge) {
		return 0, refused("the judge name must match [a-z0-9][a-z0-9-]{0,31}")
	}
	j, ok := c.judges[o.judge]
	if !ok {
		return 0, refused(fmt.Sprintf("configuration %s has no judge named %s; its judges are %s", shown(c.name), shown(o.judge), strings.Join(sortedKeys(c.judges), ", ")))
	}
	prompt, err := c.readExternal(o.promptFile, "--prompt-file")
	if err != nil {
		return 0, err
	}
	subjects := make([]textPair, 0, len(o.subjects))
	for _, pair := range o.subjects {
		text, readErr := c.readExternal(pair.text, "--subject")
		if readErr != nil {
			return 0, readErr
		}
		subjects = append(subjects, textPair{pair.name, text})
	}
	r, err := buildRequest(o, prompt, subjects)
	if err != nil {
		return 0, err
	}
	result, detail, interrupted, err := askJudge(c, o, j, r)
	if err != nil {
		return 0, err
	}
	if interrupted {
		fmt.Fprintln(stderr, "interrupted")
		return 130, nil
	}
	if err := emitJSON(stdout, result); err != nil {
		return 0, err
	}
	if result.Outcome == "answered" {
		return 0, nil
	}
	fmt.Fprintf(stderr, "unavailable: judge %s gave no answer (%s): %s\n", result.Judge, result.Outcome, detail)
	return 1, nil
}

type request struct {
	data          []byte
	withheld, cut []string
	hash          string
	decode        func([]byte) (answer, bool)
	batch         bool
}

func buildRequest(o options, prompt string, subjects []textPair) (request, error) {
	r := request{withheld: []string{}, cut: []string{}}
	if len(o.question) > 64 || !questionPattern.MatchString(o.question) {
		return r, refused("the question must be lower-case words joined by dots and hyphens, at most 64 characters")
	}
	if o.laneSet && !lanePattern.MatchString(o.lane) {
		return r, refused("--lane: must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	if trimWhitespace(prompt) == "" {
		return r, refused("the prompt must be text that is not empty")
	}
	if utf8.RuneCountInString(prompt) > maxCharacters {
		return r, refused("the prompt must be at most 4000 characters")
	}
	if len(subjects) < 1 || len(subjects) > 8 {
		return r, refused("the subject must name from 1 to 8 texts")
	}
	for _, pair := range subjects {
		if !subjectPattern.MatchString(pair.name) || pair.name == "prompt" {
			return r, refused("a subject name must match [a-z][a-z0-9_-]{0,31} and may not be \"prompt\"")
		}
	}
	if hasCredential(prompt) {
		prompt = withheldText
		r.withheld = append(r.withheld, "prompt")
	}
	var textJSON bytes.Buffer
	textJSON.WriteByte('{')
	for i, pair := range subjects {
		text := pair.text
		if hasCredential(text) {
			text = withheldText
			r.withheld = append(r.withheld, pair.name)
		} else if utf8.RuneCountInString(text) > maxCharacters {
			text = firstCharacters(text, maxCharacters)
			if hasCredential(text) {
				text = withheldText
				r.withheld = append(r.withheld, pair.name)
			} else {
				r.cut = append(r.cut, pair.name)
			}
		}
		if i != 0 {
			textJSON.WriteByte(',')
		}
		textJSON.Write(encodeJSON(pair.name))
		textJSON.WriteByte(':')
		textJSON.Write(encodeJSON(text))
	}
	textJSON.WriteByte('}')
	body := struct {
		Version  int             `json:"laneboss_judge"`
		Question string          `json:"question"`
		Kind     string          `json:"kind"`
		Prompt   string          `json:"prompt"`
		Subject  json.RawMessage `json:"subject"`
		Cut      []string        `json:"cut,omitempty"`
		Withheld []string        `json:"withheld,omitempty"`
	}{1, o.question, "noul", prompt, json.RawMessage(textJSON.Bytes()), r.cut, r.withheld}
	r.data = append(encodeJSON(body), '\n')
	sum := sha256.Sum256(r.data)
	r.hash = hex.EncodeToString(sum[:])
	return r, nil
}

func encodeJSON(value any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		panic("invalid internal JSON value")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func emitJSON(w io.Writer, value any) error {
	_, err := w.Write(append(encodeJSON(value), '\n'))
	return err
}
func firstCharacters(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func shown(s string) string {
	if hasCredential(s) {
		return withheldText
	}
	return s
}
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return hex.EncodeToString(b[:]), nil
}
func utcNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }

func safeOSMessage(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "operating system error"
}
