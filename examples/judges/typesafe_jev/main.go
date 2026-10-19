// Command typesafe_jev implements the external Jev judge contract in Go.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/typesafe"
)

const maxBytes = 1 << 20
const held = "the answer held the key and was not printed"

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var keyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,99}$`)
var modelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$`)
var secret string

type failure struct {
	code    int
	message string
}

func (f *failure) Error() string         { return f.message }
func bad(code int, message string) error { return &failure{code, message} }
func write(fd int, text string) (bool, error) {
	withheld := secret != "" && strings.Contains(text, secret)
	if withheld {
		fd = 2
		text = "typesafe_jev: " + held
	}
	if fd == 2 {
		text = strings.Join(strings.Fields(text), " ")
		runes := []rune(text)
		if len(runes) > 290 {
			runes = runes[:290]
		}
		for i, r := range runes {
			if r > 127 {
				runes[i] = '?'
			}
		}
		text = string(runes)
	}
	out := os.Stdout
	if fd == 2 {
		out = os.Stderr
	}
	_, err := io.WriteString(out, text+"\n")
	return withheld, err
}
func fail(code int, message string) int {
	withheld, _ := write(2, "typesafe_jev: "+message)
	if withheld {
		return 4
	}
	return code
}

type options struct {
	file, key, model, base string
	timeout                float64
	help                   bool
	hasFile                bool
}

func parse(args []string) (options, error) {
	o := options{key: "TYPESAFE_API_KEY", model: "jev-latest", base: "https://api.typesafe.ai", timeout: 8}
	unknown := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		label, value, attached := strings.Cut(arg, "=")
		if label == "-h" || label == "--help" {
			if attached {
				return o, bad(2, "usage error with -h/--help (see --help)")
			}
			o.help = true
			continue
		}
		switch label {
		case "--env-file", "--key-name", "--model", "--base-url", "--timeout":
		default:
			unknown = true
			continue
		}
		if !attached {
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") || args[i+1] == "-h" {
				return o, bad(2, "usage error: "+label+" expected one argument")
			}
			i++
			value = args[i]
		}
		reason := ""
		switch label {
		case "--env-file":
			o.file = value
			o.hasFile = true
		case "--key-name":
			if !keyName.MatchString(value) {
				reason = "must be a variable name such as TYPESAFE_API_KEY"
			}
			o.key = value
		case "--model":
			if !modelName.MatchString(value) {
				reason = "must be a model name such as jev-latest"
			}
			o.model = value
		case "--timeout":
			n, e := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(value), "_", ""), 64)
			if e != nil {
				reason = "must be a number of seconds"
			} else if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 || n > 3600 {
				reason = "must be above 0 and at most 3600 seconds"
			}
			o.timeout = n
		case "--base-url":
			reason = validateURL(value)
			o.base = strings.TrimRight(value, "/")
		}
		if reason != "" {
			return o, bad(2, "usage error: "+label+" "+reason)
		}
	}
	if unknown {
		return o, bad(2, "unrecognized arguments (see --help)")
	}
	return o, nil
}
func validateURL(text string) string {
	if strings.IndexFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r < 32 || r == 127 }) >= 0 {
		return "must not hold spaces or control characters"
	}
	u, e := url.Parse(text)
	if e != nil {
		return "is not a valid URL"
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p <= 0 || p > 65535 {
			return "is not a valid URL"
		}
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "must be an https:// URL with a host"
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "must not carry credentials, a query or a fragment"
	}
	if u.Scheme == "http" && u.Hostname() != "127.0.0.1" {
		return "must be https:// unless the host is 127.0.0.1"
	}
	return ""
}
func decode(data []byte, duplicates bool) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	var e error
	if duplicates {
		value, e = decodeValue(d, 0)
	} else {
		e = d.Decode(&value)
	}
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 1000 {
		return nil, errors.New("JSON depth")
	}
	token, e := d.Token()
	if e != nil {
		return nil, e
	}
	switch token {
	case json.Delim('{'):
		result := map[string]any{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return nil, e
			}
			name, ok := key.(string)
			if !ok {
				return nil, errors.New("object key")
			}
			if _, ok = result[name]; ok {
				return nil, errors.New("duplicate member")
			}
			v, e := decodeValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			result[name] = v
		}
		_, e = d.Token()
		return result, e
	case json.Delim('['):
		result := []any{}
		for d.More() {
			v, e := decodeValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			result = append(result, v)
		}
		_, e = d.Token()
		return result, e
	}
	return token, nil
}
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func readRequest() (string, map[string]any, bool, error) {
	data, e := io.ReadAll(io.LimitReader(os.Stdin, maxBytes+1))
	if e != nil {
		return "", nil, false, bad(2, "there is no standard input")
	}
	if len(data) > maxBytes {
		return "", nil, false, bad(2, "the request is larger than 1 MiB")
	}
	value, e := decode(data, true)
	if e != nil {
		return "", nil, false, bad(2, "the request is not one JSON object in UTF-8")
	}
	request := object(value)
	if request == nil {
		return "", nil, false, bad(2, "the request is not one JSON object")
	}
	if v, ok := request["laneboss_judge"].(json.Number); !ok || v.String() != "1" {
		return "", nil, false, bad(2, "laneboss_judge must be 1")
	}
	if request["kind"] == "typed" {
		state, questions := object(request["state"]), object(request["questions"])
		if state == nil || !typesafe.Questions(questions) || unpaired(data) {
			return "", nil, false, bad(2, "typed request needs named state and documented questions")
		}
		return "laneboss.typed", map[string]any{"state": state, "questions": questions}, false, nil
	}
	if request["kind"] == "laneboss-jobs" {
		state, questions := object(request["state"]), object(request["questions"])
		owned, command := object(questions["owned"]), object(questions["command"])
		criteria := object(command["criteria"])
		shell, shellOK := state["shell_command"].(string)
		if request["question"] != "laneboss.jobs" || !shellOK || shell == "" || !typesafe.Questions(questions) || owned["type"] != "noul" ||
			command["type"] != "choice" || len(criteria) < 2 || len(criteria) > 255 {
			return "", nil, false, bad(2, "job request needs a shell command and generated noul/choice questions")
		}
		for _, question := range []map[string]any{owned, command} {
			text, ok := question["instructions"].(string)
			if !ok || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > 4000 {
				return "", nil, false, bad(2, "job question instructions must be bounded text")
			}
		}
		for name, value := range criteria {
			text, ok := value.(string)
			if name == "" || !ok || text == "" || utf8.RuneCountInString(text) > 4000 {
				return "", nil, false, bad(2, "job choices must have generated names and purposes")
			}
		}
		if _, exists := criteria["none"]; !exists {
			return "", nil, false, bad(2, "job choices must include none")
		}
		return "laneboss.jobs", map[string]any{"state": state, "questions": questions}, unpaired(data), nil
	}
	if request["kind"] != "noul" {
		return "", nil, false, bad(2, "kind must be noul")
	}
	if q, ok := request["question"].(string); !ok || q == "" {
		return "", nil, false, bad(2, "question must be a non-empty string")
	}
	prompt, ok := request["prompt"].(string)
	if !ok || strings.TrimSpace(prompt) == "" {
		return "", nil, false, bad(2, "prompt must be a non-empty string")
	}
	subject := object(request["subject"])
	if len(subject) < 1 || len(subject) > 8 {
		return "", nil, false, bad(2, "subject must hold one to 8 named texts")
	}
	for name, text := range subject {
		if name == "" {
			return "", nil, false, bad(2, "a subject name is empty")
		}
		s, ok := text.(string)
		if !ok {
			return "", nil, false, bad(2, "every subject text must be a string")
		}
		if utf8.RuneCountInString(s) > 4000 {
			return "", nil, false, bad(2, "a subject text is longer than 4000 characters")
		}
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)
	invalid := unpaired(raw["prompt"]) || unpaired(raw["subject"])
	return prompt, subject, invalid, nil
}
func unpaired(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			break
		}
		if data[i] != 'u' || i+4 >= len(data) {
			continue
		}
		n, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if e != nil {
			continue
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return true
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return true
			}
			low, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 6
		}
	}
	return false
}
func expand(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, e := os.UserHomeDir(); e == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
		}
	}
	return path
}
func errorText(e error) string {
	var errno syscall.Errno
	if errors.As(e, &errno) {
		s := errno.Error()
		if len(s) > 0 {
			return strings.ToUpper(s[:1]) + s[1:]
		}
		return s
	}
	return "I/O error"
}
func readKey(path, name string) (string, error) {
	fd, e := syscall.Open(expand(path), syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return "", bad(3, "cannot open the key file: "+errorText(e))
	}
	f := os.NewFile(uintptr(fd), "key")
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return "", bad(3, "cannot read the key file: "+errorText(e))
	}
	if !info.Mode().IsRegular() {
		return "", bad(3, "the key file is not a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", bad(3, fmt.Sprintf("the key file has mode %04o: group and others must have no access (chmod 600)", info.Mode().Perm()))
	}
	data, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return "", bad(3, "cannot read the key file: "+errorText(e))
	}
	if len(data) > 65536 {
		return "", bad(3, "the key file is larger than 64 KiB")
	}
	if !utf8.Valid(data) {
		return "", bad(3, "the key file is not UTF-8 text")
	}
	found := ""
	present := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export") && len(line) > 6 && unicode.IsSpace(rune(line[6])) {
			line = strings.TrimSpace(line[6:])
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '\'' || value[0] == '"') {
			value = value[1 : len(value)-1]
		}
		found = value
		present = true
	}
	if !present {
		return "", bad(3, "the key file has no line for the name given with --key-name")
	}
	if found == "" || strings.IndexFunc(found, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", bad(3, "the key's value is empty or has characters that cannot go in a header")
	}
	if len(found) < 16 {
		return "", bad(3, "the key's value is too short to be a key")
	}
	return found, nil
}
func cleanID(s string) any {
	if identifier.MatchString(s) {
		return s
	}
	return nil
}
func ask(o options, prompt string, subject map[string]any) ([]byte, any, error) {
	body := map[string]any{"state": subject, "model": o.model, "questions": scalarQuestions(prompt)}
	if questions, ok := subject["questions"].(map[string]any); ok && (prompt == "laneboss.jobs" || prompt == "laneboss.typed") {
		body = map[string]any{"state": subject["state"], "model": o.model, "questions": questions}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if e := enc.Encode(body); e != nil {
		return nil, nil, bad(2, "the request holds text that cannot be sent as UTF-8")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.timeout*float64(time.Second)))
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/v1/systemone", bytes.NewReader(b.Bytes()))
	if e != nil {
		return nil, nil, bad(4, "cannot get an answer from the service: ValueError")
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "laneboss-judge-typesafe-jev/1")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	if request.URL.Hostname() == "127.0.0.1" {
		transport.Proxy = nil
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Duration(o.timeout * float64(time.Second)), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var response *http.Response
	for attempt := 0; ; attempt++ {
		request.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
		response, e = client.Do(request)
		if e != nil || (response.StatusCode != 429 && response.StatusCode != 529) || attempt == 2 {
			break
		}
		response.Body.Close()
		delay := time.NewTimer(time.Duration(1<<attempt) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			delay.Stop()
			return nil, nil, httpFailure(ctx.Err(), o.timeout)
		case <-delay.C:
		}
	}
	if e != nil {
		return nil, nil, httpFailure(e, o.timeout)
	}
	defer response.Body.Close()
	id := cleanID(response.Header.Get("x-typesafe-request-id"))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		suffix := ""
		if id != nil {
			suffix = fmt.Sprintf(" (request %s)", id)
		}
		return nil, nil, bad(4, fmt.Sprintf("the service answered HTTP %d%s", response.StatusCode, suffix))
	}
	answer, e := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if e != nil {
		return nil, nil, httpFailure(e, o.timeout)
	}
	if len(answer) > maxBytes {
		return nil, nil, bad(4, "the service's answer is larger than 1 MiB")
	}
	return answer, id, nil
}
func httpFailure(e error, seconds float64) error {
	var timeout net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.As(e, &timeout) && timeout.Timeout() {
		return bad(5, fmt.Sprintf("the service did not answer within %g seconds", seconds))
	}
	return bad(4, "cannot get an answer from the service: "+errorKind(e))
}
func errorKind(e error) string {
	var op *net.OpError
	if errors.As(e, &op) {
		return "OSError"
	}
	return "HTTPException"
}
func probability(n json.Number) (float64, bool) {
	s := n.String()
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mantissa, exponent := s, 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mantissa = s[:i]
		v, e := strconv.Atoi(s[i+1:])
		if e != nil {
			if strings.HasPrefix(s[i+1:], "-") {
				v = -maxBytes * 2
			} else {
				v = maxBytes * 2
			}
		}
		exponent = max(-maxBytes*2, min(maxBytes*2, v))
	}
	integer, fraction, _ := strings.Cut(mantissa, ".")
	digits := integer + fraction
	leading := len(digits) - len(strings.TrimLeft(digits, "0"))
	if leading == len(digits) {
		return 0, true
	}
	if negative {
		return 0, false
	}
	power := len(integer) + exponent - leading
	digits = digits[leading:]
	if power > 1 || power == 1 && (digits[0] != '1' || strings.Trim(digits[1:], "0") != "") {
		return 0, false
	}
	f, e := strconv.ParseFloat(n.String(), 64)
	if e != nil && math.IsInf(f, 0) {
		return 0, false
	}
	return f + 0, true
}
func answer(body []byte, id any) (string, error) {
	root, e := typesafe.Response(body, scalarQuestions("Is the supplied proposition true?"))
	unreadable := bad(4, "the service's answer is not the documented one")
	if e != nil {
		return "", unreadable
	}
	a := object(object(root["answers"])["answer"])
	if a["type"] != "noul" {
		return "", unreadable
	}
	raw, ok := a["noul"].(json.Number)
	if !ok {
		return "", unreadable
	}
	p, ok := probability(raw)
	if !ok {
		return "", unreadable
	}
	model := root["model"]
	if m, ok := model.(string); !ok || !identifier.MatchString(m) {
		return "", unreadable
	}
	modelJSON, _ := json.Marshal(model)
	idJSON, _ := json.Marshal(id)
	number := strconv.FormatFloat(p, 'g', -1, 64)
	if !strings.ContainsAny(number, ".eE") {
		number += ".0"
	}
	return fmt.Sprintf("{\"probability\": %s, \"model\": %s, \"request\": %s}", number, modelJSON, idJSON), nil
}

func jobAnswer(body []byte, id any, criteria map[string]any) (string, error) {
	return typedAnswer(body, id, map[string]any{
		"owned":   map[string]any{"type": "noul", "instructions": "Does the action do a managed job?"},
		"command": map[string]any{"type": "choice", "instructions": "Which catalog command applies?", "criteria": criteria},
	})
}

func scalarQuestions(prompt string) map[string]any {
	return map[string]any{"answer": map[string]any{"type": "noul", "instructions": prompt,
		"criteria": map[string]any{"true": "The proposition in instructions is true for the named state.", "false": "The proposition in instructions is false for the named state."}}}
}

func typedAnswer(body []byte, id any, questions map[string]any) (string, error) {
	result, err := typesafe.Response(body, questions)
	unreadable := bad(4, "the service's answer is not the documented one")
	if err != nil {
		return "", unreadable
	}
	if model, ok := result["model"].(string); !ok || !identifier.MatchString(model) {
		return "", unreadable
	}
	result["request"] = id
	raw, err := json.Marshal(result)
	if err != nil {
		return "", unreadable
	}
	return string(raw), nil
}
func help() string {
	return "usage: typesafe_jev [-h] [--env-file PATH] [--key-name NAME] [--model MODEL]\n                       [--base-url URL] [--timeout SECONDS]\n\nJudge for the laneboss launcher: asks TypeSafe's Jev the typed questions about the named state on standard input. Legacy scalar asks print the probability of yes; typed batches preserve official answers. Exit 2: bad request or options; 3: key file; 4: HTTP error, an answer that cannot be read, or text that held the key; 5: time-out.\n\noptions:\n  -h, --help         show this help and exit\n  --env-file PATH   required: file of NAME=value lines that holds the key; group and others must have no access\n  --key-name NAME   the name of the key's line (default: TYPESAFE_API_KEY)\n  --model MODEL     the model or alias to ask (default: jev-latest)\n  --base-url URL    the service's address; https unless 127.0.0.1 (default: https://api.typesafe.ai)\n  --timeout SECONDS seconds to wait for the service in all (default: 8)"
}
func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) (code int) {
	defer func() {
		if recover() != nil {
			code = fail(1, "internal error: panic")
		}
	}()
	o, e := parse(args)
	if e == nil && o.help {
		_, e = write(1, help())
		if e != nil {
			return fail(1, "cannot write the answer")
		}
		return 0
	}
	if e == nil && !o.hasFile {
		e = bad(2, "--env-file is required (see --help)")
	}
	var prompt string
	var subject map[string]any
	invalid := false
	if e == nil {
		prompt, subject, invalid, e = readRequest()
	}
	if e == nil {
		secret, e = readKey(o.file, o.key)
	}
	if e == nil && invalid {
		e = bad(2, "the request holds text that cannot be sent as UTF-8")
	}
	var result string
	if e == nil {
		body, id, err := ask(o, prompt, subject)
		e = err
		if e == nil {
			if questions, ok := subject["questions"].(map[string]any); ok && (prompt == "laneboss.jobs" || prompt == "laneboss.typed") {
				result, e = typedAnswer(body, id, questions)
			} else {
				result, e = answer(body, id)
			}
		}
	}
	if e != nil {
		var f *failure
		if errors.As(e, &f) {
			return fail(f.code, f.message)
		}
		return fail(1, "internal error: error")
	}
	withheld, e := write(1, result)
	if e != nil {
		return fail(1, "cannot write the answer")
	}
	if withheld {
		return 4
	}
	return 0
}
