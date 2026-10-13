package adapters

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/jsontext"
	"laneboss.io/laneboss/internal/judge"
)

type Result struct {
	Reason string         `json:"reason"`
	Answer map[string]any `json:"answer"`
	Detail string         `json:"detail"`
}
type Refused struct{ Message string }

func (e *Refused) Error() string { return e.Message }

func Call(command any, request map[string]any, seconds any, credentialEnv any) (Result, error) {
	argv := []string{}
	switch list := command.(type) {
	case []string:
		argv = append(argv, list...)
	case []any:
		for _, value := range list {
			text, ok := value.(string)
			if !ok {
				return Result{}, fmt.Errorf("command: not a list of strings")
			}
			argv = append(argv, text)
		}
	default:
		return Result{}, fmt.Errorf("command: not a list of strings")
	}
	if len(argv) == 0 {
		return Result{}, fmt.Errorf("command: needs a program")
	}
	if request == nil {
		return Result{}, fmt.Errorf("request: not an object")
	}
	if _, err := Operation(request["operation"]); err != nil {
		return Result{}, err
	}
	if request["operation"] == "acquire" {
		if _, err := DryRun(request["dry_run"]); err != nil {
			return Result{}, err
		}
	}
	if !whole(seconds, 1, 900) || number(seconds) != number(request["timeout_seconds"]) {
		return Result{}, fmt.Errorf("seconds: not the request's timeout_seconds")
	}
	environment := []string{"PATH=" + FixedPath}
	secret := ""
	if credentialEnv != nil {
		name, ok := credentialEnv.(string)
		if !ok || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`).MatchString(name) || name == "PATH" || strings.HasPrefix(name, "LANEBOSS_") {
			return Result{}, fmt.Errorf("credential_env: not an allowed variable name")
		}
		secret = os.Getenv(name)
		if secret == "" {
			return Result{}, &Refused{"the variable that credential_env names is not set, or is empty, in the launcher's environment: the adapter was not called"}
		}
		environment = append(environment, name+"="+secret)
	}
	data, err := TextFor(request)
	if err != nil {
		return Result{}, err
	}
	program, err := exec.LookPath(argv[0])
	// The adapter contract permits relative entries on the launcher's PATH;
	// resolve the checked result before using the adapter's fixed PATH.
	if errors.Is(err, exec.ErrDot) {
		err = nil
	}
	if err == nil {
		program, err = filepath.Abs(program)
	}
	if err != nil {
		return Result{Reason: "not-found", Detail: "the program was not found or could not be started"}, nil
	}
	argv[0] = program
	reason, status, out, errout := judge.RunAdapter(argv, data, number(seconds), environment)
	var answer map[string]any
	if reason == "" {
		if status != 0 {
			reason = "exit"
		} else {
			answer = ReadAnswer(out, request, secret)
			reason = "answered"
			if answer == nil {
				reason = "output"
			}
		}
	}
	if reason == "answered" {
		return Result{reason, answer, ""}, nil
	}
	detail := "standard output is not one answer object"
	switch reason {
	case "timeout":
		detail = fmt.Sprintf("no answer within %d second(s)", number(seconds))
	case "not-found":
		detail = "the program was not found or could not be started"
	case "exit":
		if status > 0 {
			detail = fmt.Sprintf("exit status %d", status)
		} else {
			detail = "ended by a signal"
		}
	}
	line := judge.Explain(errout)
	if len([]rune(secret)) >= 8 && (bytes.Contains(errout, []byte(secret)) || strings.Contains(line, secret)) {
		line = "[withheld]"
	}
	if line != "" {
		detail += ": " + line
	}
	return Result{Reason: reason, Detail: detail}, nil
}

func ReadAnswer(data []byte, request map[string]any, secret string) map[string]any {
	if len(data) > 64*1024 || !jsontext.ValidUnicode(data) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := uniqueJSON(decoder, 0)
	if err != nil {
		return nil
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil
	}
	answer, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	state, _ := answer["state"].(string)
	var required string
	switch request["operation"] {
	case "acquire":
		if request["dry_run"] == true && state == "quoted" {
			required = "size region price_per_hour_micros currency price_source"
		} else if request["dry_run"] == false && state == "acquired" {
			required = "provider_id started_at"
		} else if state == "failed" {
			required = "reason"
		} else {
			return nil
		}
	case "describe":
		switch state {
		case "running":
			required = "provider_id provider_state started_at"
		case "terminated":
			required = "provider_id provider_state started_at ended_at"
		case "absent":
		default:
			return nil
		}
	case "release":
		if state != "releasing" {
			return nil
		}
	default:
		return nil
	}
	keys := append([]string{"state"}, strings.Fields(required)...)
	if _, exists := answer["request"]; exists {
		keys = append(keys, "request")
	}
	if len(answer) != len(keys) {
		return nil
	}
	for _, key := range keys {
		value, exists := answer[key]
		if !exists {
			return nil
		}
		valid := true
		switch key {
		case "state":
		case "started_at", "ended_at":
			valid = timestamp(value)
		case "price_per_hour_micros":
			valid = value == nil || whole(value, 0, 1000000000)
		case "price_source":
			valid = value == nil || oneOf(value, "adapter", "configured")
		default:
			valid = grammar(key, value, key == "size" || key == "region" || key == "currency" || key == "request")
		}
		if !valid {
			return nil
		}
		if text, ok := value.(string); ok && (judge.HoldsCredential(text) || len([]rune(secret)) >= 8 && strings.Contains(text, secret)) {
			return nil
		}
	}
	if state == "quoted" {
		nulls := 0
		for _, key := range []string{"price_per_hour_micros", "currency", "price_source"} {
			if answer[key] == nil {
				nulls++
			}
		}
		if nulls != 0 && nulls != 3 {
			return nil
		}
	}
	if request["operation"] == "describe" && request["provider_id"] != nil && state != "absent" && answer["provider_id"] != request["provider_id"] {
		return nil
	}
	if _, exists := answer["request"]; !exists {
		answer["request"] = nil
	}
	return answer
}
func timestamp(value any) bool {
	if value == nil {
		return true
	}
	text, ok := value.(string)
	if !ok || strings.HasPrefix(text, "0000-") || !regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`).MatchString(text) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, text)
	return err == nil
}
func uniqueJSON(decoder *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, fmt.Errorf("JSON nesting limit")
	}
	value, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if number, ok := value.(json.Number); ok && strings.ContainsAny(string(number), ".eE") {
		return nil, fmt.Errorf("fraction or exponent")
	}
	if delimiter, ok := value.(json.Delim); ok {
		if delimiter != '{' {
			return nil, fmt.Errorf("object required")
		}
		object := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("key required")
			}
			if _, exists := object[name]; exists {
				return nil, fmt.Errorf("duplicate key")
			}
			item, err := uniqueJSON(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = item
		}
		_, err := decoder.Token()
		return object, err
	}
	return value, nil
}
