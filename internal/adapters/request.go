// Package adapters implements the external resource adapter contract.
package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const RequestVersion = 1
const MaxRequestBytes = 16 * 1024
const FixedPath = "/usr/local/bin:/usr/bin:/bin"

var AcquireMembers = strings.Fields("laneboss_resource operation id lane kind profile purpose size region hard_cap_minutes dry_run timeout_seconds")
var ReadMembers = strings.Fields("laneboss_resource operation id kind profile region provider_id timeout_seconds")

var grammars = map[string]string{
	"id": `rs-[0-9a-f]{24}`, "lane": `[a-z0-9][a-z0-9._-]{0,63}`,
	"profile": `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, "purpose": `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`,
	"size": `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`, "region": `[a-z0-9][a-z0-9-]{0,31}`,
	"provider_id":    `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}`,
	"provider_state": `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, "reason": `[a-z][a-z-]{0,39}`,
	"currency": `[A-Z]{3}`, "request": `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`,
}

func grammar(name string, value any, nullable bool) bool {
	if value == nil {
		return nullable
	}
	text, ok := value.(string)
	return ok && regexp.MustCompile("^(?:"+grammars[name]+")$").MatchString(text)
}
func whole(value any, smallest, largest int64) bool {
	var n int64
	var err error
	switch v := value.(type) {
	case int:
		n = int64(v)
	case int64:
		n = v
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return false
		}
		n, err = v.Int64()
	default:
		return false
	}
	return err == nil && n >= smallest && n <= largest
}
func oneOf(value any, words ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, word := range words {
		if word == text {
			return true
		}
	}
	return false
}
func Operation(value any) (string, error) {
	if !oneOf(value, "acquire", "describe", "release") {
		return "", fmt.Errorf("operation: not an adapter operation")
	}
	return value.(string), nil
}
func DryRun(value any) (bool, error) {
	result, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("dry_run: not true or false")
	}
	return result, nil
}
func Build(form string, arguments map[string]any) (map[string]any, []string, error) {
	acquire := form == "quote_request" || form == "acquire_request"
	operation := strings.TrimSuffix(form, "_request")
	if form == "quote_request" {
		operation = "acquire"
	}
	if _, err := Operation(operation); err != nil {
		return nil, nil, err
	}
	request := map[string]any{"laneboss_resource": RequestVersion, "operation": operation, "id": arguments["resource"]}
	keys := ReadMembers
	if acquire {
		keys = AcquireMembers
	}
	for _, key := range keys {
		switch key {
		case "laneboss_resource", "operation", "id":
		case "dry_run":
			request[key] = form == "quote_request"
		case "region":
			request[key] = arguments[key]
			if form == "quote_request" {
				request[key] = nil
			}
		default:
			request[key] = arguments[key]
		}
	}
	for _, key := range keys {
		value := request[key]
		valid := true
		switch key {
		case "id", "lane", "purpose":
			valid = grammar(key, value, false)
		case "profile", "size", "region", "provider_id":
			valid = grammar(key, value, true)
		case "kind":
			valid = oneOf(value, "machine", "credential")
		case "hard_cap_minutes":
			valid = whole(value, 1, 10080)
		case "timeout_seconds":
			valid = whole(value, 1, 900)
		}
		if !valid {
			return nil, nil, fmt.Errorf("%s: outside the adapter contract's type, grammar or bound", key)
		}
	}
	return request, keys, nil
}

// TextFor emits ASCII-safe JSON in the contract's member order, with one newline.
// Extra caller members are preserved; the byte limit applies to the final text.
func TextFor(request map[string]any) ([]byte, error) {
	keys := ReadMembers
	if request["operation"] == "acquire" {
		keys = AcquireMembers
	}
	order := []string{}
	seen := map[string]bool{}
	for _, key := range keys {
		if _, ok := request[key]; ok {
			order = append(order, key)
			seen[key] = true
		}
	}
	extra := []string{}
	for key := range request {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	order = append(order, extra...)
	var out bytes.Buffer
	out.WriteByte('{')
	for i, key := range order {
		if i > 0 {
			out.WriteByte(',')
		}
		name, err := asciiJSON(key)
		if err != nil {
			return nil, err
		}
		data, err := asciiJSON(request[key])
		if err != nil {
			return nil, err
		}
		out.Write(name)
		out.WriteByte(':')
		out.Write(data)
	}
	out.WriteString("}\n")
	if out.Len() > MaxRequestBytes {
		return nil, fmt.Errorf("a request must not pass MAX_REQUEST_BYTES (%d bytes)", MaxRequestBytes)
	}
	return out.Bytes(), nil
}
func asciiJSON(value any) ([]byte, error) {
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	var out strings.Builder
	for _, r := range strings.TrimSuffix(raw.String(), "\n") {
		if r < 128 {
			out.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&out, "\\u%04x", r)
		} else {
			high, low := utf16.EncodeRune(r)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", high, low)
		}
	}
	return []byte(out.String()), nil
}
func number(value any) int { n, _ := strconv.Atoi(fmt.Sprint(value)); return n }
