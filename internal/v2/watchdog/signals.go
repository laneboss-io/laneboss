package watchdog

// Ported from the wave-0 runnerhome classifier. These are diagnostics, not
// authority: a service must also validate primary capture, the pinned adapter,
// the actual run exit, current grants and outside room evidence.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

type LimitKind string

const (
	UsageLimit   LimitKind = "usage_limit"
	SessionLimit LimitKind = "session_limit"
	RateLimit    LimitKind = "rate_limit"
	AuthExpired  LimitKind = "auth_expired"
)

type OutputFormat string

const (
	JSONLines OutputFormat = "jsonl"
	// HeadlessText is retained for diagnostics only. Text is not swap authority.
	HeadlessText OutputFormat = "headless-text"
)

// Diagnostic locates exact original bytes without copying arbitrary provider
// text into events or messages. Candidate codes need pinned vendor evidence;
// neither Candidate=false nor Structured=true is an authorization receipt.
type Diagnostic struct {
	Kind       LimitKind `json:"kind"`
	Rule       string    `json:"rule"`
	Stream     string    `json:"stream"`
	Line       int       `json:"line"`
	Offset     int64     `json:"offset"`
	Bytes      int       `json:"bytes"`
	SHA256     string    `json:"sha256"`
	Structured bool      `json:"structured"`
	Candidate  bool      `json:"candidate"`
}

type Outcome struct {
	Format           OutputFormat `json:"format"`
	ExitCode         int          `json:"exit_code"`
	Complete         bool         `json:"complete"`
	OversizedRecords uint64       `json:"oversized_records"`
	Signals          []Diagnostic `json:"signals"`
}

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")
var claudeQuota = regexp.MustCompile(`^You['’]ve hit your (limit|usage limit|session limit|weekly limit|Opus limit|Sonnet limit)(?:[.!]| · (?:resets|limit resets) [^\r\n]+)?(?: · progress saved)?$`)
var claudeReached = regexp.MustCompile(`^Usage limit reached(?: · limit resets [^\r\n]+)?$`)
var codexQuota = regexp.MustCompile(`^(?:You['’]ve hit your usage limit|Usage limit reached)(?:[.!](?: .*)?)?$`)
var rateMessage = regexp.MustCompile(`^(?:Rate limit reached|Rate limit exceeded|Too many requests|429 Too Many Requests)(?:[.!]| for .*)?$`)
var expiredMessage = regexp.MustCompile(`^(?:OAuth token has expired|Your authentication token has expired|Your access token has expired)(?:[.!](?: .*)?)?$`)
var apiError = regexp.MustCompile(`^API Error: (401|429) (\{.*\})$`)

func cleanMessage(text string) string {
	return strings.TrimSpace(sgr.ReplaceAllString(text, ""))
}

type detected struct {
	kind      LimitKind
	rule      string
	candidate bool
}

func textSignal(driver api.Driver, message string) detected {
	text := cleanMessage(message)
	if strings.ContainsAny(text, "\r\n\x00") {
		return detected{}
	}
	if driver == api.DriverClaudock {
		if matches := claudeQuota.FindStringSubmatch(text); matches != nil {
			kind := UsageLimit
			if matches[1] == "session limit" {
				kind = SessionLimit
			}
			return detected{kind, "claude-quota", false}
		}
		if claudeReached.MatchString(text) {
			return detected{UsageLimit, "claude-usage-reached", false}
		}
	}
	if driver == api.DriverCodex && codexQuota.MatchString(text) {
		return detected{UsageLimit, "codex-usage-wording", true}
	}
	if rateMessage.MatchString(text) {
		return detected{RateLimit, "rate-wording", true}
	}
	if expiredMessage.MatchString(text) {
		return detected{AuthExpired, "expired-wording", true}
	}
	if driver == api.DriverCodex && strings.HasPrefix(text,
		"Your access token could not be refreshed because your refresh token was already used.") {
		return detected{AuthExpired, "codex-refresh-reused-wording", true}
	}
	return detected{}
}

// Codes are read only from fixed provider-error positions, not recursively
// from user, tool or model content. Generic exit codes are not quota evidence.
func codeSignal(code string) detected {
	switch code {
	case "usage_limit_reached", "usage_limit_exceeded", "UsageLimitExceeded":
		return detected{UsageLimit, "usage-error-code", true}
	case "session_limit_reached":
		return detected{SessionLimit, "session-error-code", true}
	case "rate_limit_exceeded", "rate_limit_error", "rate_limit":
		return detected{RateLimit, "rate-error-code", true}
	case "token_expired", "refresh_token_expired", "refresh_token_reused", "expired_auth_token":
		return detected{AuthExpired, "expired-error-code", true}
	}
	return detected{}
}

func object(value any) map[string]any { out, _ := value.(map[string]any); return out }
func stringValue(value any) string    { out, _ := value.(string); return out }

const maxErrorDepth = 2

// Only structured stdout calls this parser. Plain stderr/headless text is
// never parsed as JSON, even when it prints an entire provider error envelope.
func errorSignals(driver api.Driver, value any, depth int) ([]detected, error) {
	if depth > maxErrorDepth {
		return nil, nil
	}
	if message, ok := value.(string); ok {
		return messageSignals(driver, message, depth)
	}
	doc := object(value)
	// A sourced quota message takes precedence over a generic candidate code.
	out, err := messageSignals(driver, stringValue(doc["message"]), depth)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"code", "type", "codex_error_info"} {
		if signal := codeSignal(stringValue(doc[key])); signal.kind != "" {
			out = append(out, signal)
		}
	}
	if nested, exists := doc["error"]; exists {
		more, err := errorSignals(driver, nested, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
	}
	return out, nil
}

func messageSignals(driver api.Driver, message string, depth int) ([]detected, error) {
	out := []detected{}
	for _, part := range strings.FieldsFunc(message, func(r rune) bool { return r == '\r' || r == '\n' }) {
		line := cleanMessage(part)
		out = append(out, textSignal(driver, line))
		if matches := apiError.FindStringSubmatch(line); matches != nil && depth < maxErrorDepth {
			document, err := decodeObject([]byte(matches[2]))
			if err != nil {
				return nil, errors.New("structured API error is malformed or ambiguous")
			}
			more, err := errorSignals(driver, document["error"], depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, more...)
			if matches[1] == "429" {
				out = append(out, detected{RateLimit, "api-429", true})
			}
		}
	}
	return out, nil
}

func structuredSignals(driver api.Driver, event map[string]any) ([]detected, error) {
	typ := stringValue(event["type"])
	if driver == api.DriverCodex {
		switch typ {
		case "turn.failed":
			return errorSignals(driver, event["error"], 0)
		case "error":
			return errorSignals(driver, event, 0)
		case "item.completed":
			item := object(event["item"])
			if item["type"] == "error" {
				return errorSignals(driver, item, 0)
			}
		}
		return nil, nil
	}
	if typ == "error" {
		return errorSignals(driver, event, 0)
	}
	out := []detected{}
	if typ == "result" && event["is_error"] == true {
		more, err := errorSignals(driver, event["result"], 0)
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
		if list, ok := event["errors"].([]any); ok {
			for _, item := range list {
				more, err := errorSignals(driver, item, 0)
				if err != nil {
					return nil, err
				}
				out = append(out, more...)
			}
		}
	}
	if typ == "assistant" && event["error"] == "rate_limit" {
		blocks, _ := object(event["message"])["content"].([]any)
		for _, block := range blocks {
			item := object(block)
			if item["type"] == "text" {
				more, err := errorSignals(driver, item["text"], 0)
				if err != nil {
					return nil, err
				}
				out = append(out, more...)
			}
		}
		found := false
		for _, signal := range out {
			found = found || signal.kind != ""
		}
		if !found {
			out = append(out, detected{RateLimit, "claude-assistant-rate-error", true})
		}
	}
	if typ == "rate_limit_event" && object(event["rate_limit_info"])["status"] == "rejected" {
		out = append(out, detected{RateLimit, "claude-rejected-rate-event", true})
	}
	return out, nil
}

// Classify consumes outside capture bytes and preserves their raw offsets and
// hashes, including CR/LF. A provider may exit 0 on a limit. Malformed structured
// stdout fails. Records over 1 MiB are skipped without parsing and counted;
// small later provider errors remain visible. Complete means that the selected
// format's scan finished, not that skipped bytes were interpreted. Original
// capture bytes must still be retained. Text diagnostics start no continuation.
func Classify(driver api.Driver, format OutputFormat, stdout, stderr []byte, exitCode int) (Outcome, error) {
	result := Outcome{Format: format, ExitCode: exitCode, Signals: []Diagnostic{}}
	if (driver != api.DriverClaudock && driver != api.DriverCodex) ||
		(format != JSONLines && format != HeadlessText) {
		return result, errors.New("classifier requires a supported driver and output format")
	}
	for index, data := range [][]byte{stdout, stderr} {
		stream := "stdout"
		if index == 1 {
			stream = "stderr"
		}
		line := 0
		for offset := 0; offset < len(data); {
			line++
			start := offset
			if end := bytes.IndexByte(data[offset:], '\n'); end >= 0 {
				offset += end + 1
			} else {
				offset = len(data)
			}
			raw := data[start:offset]
			if len(raw) > 1024*1024 {
				result.OversizedRecords++
				continue
			}
			if !utf8.Valid(raw) {
				return result, errors.New("captured output is not valid UTF-8")
			}
			structured := index == 0 && format == JSONLines
			clean := strings.TrimSpace(string(raw))
			if !structured {
				clean = cleanMessage(clean)
			}
			if clean == "" {
				continue
			}
			var signals []detected
			if structured {
				event, err := decodeObject([]byte(clean))
				if err != nil {
					return result, errors.New("captured structured output is malformed or ambiguous")
				}
				signals, err = structuredSignals(driver, event)
				if err != nil {
					return result, err
				}
			} else {
				message := strings.TrimPrefix(clean, "ERROR: ")
				signals = []detected{textSignal(driver, message)}
				// The HTTP status is a text hint only; never parse the JSON tail
				// on stderr or headless stdout into provider-envelope authority.
				if matches := apiError.FindStringSubmatch(message); matches != nil && matches[1] == "429" {
					signals = append(signals, detected{RateLimit, "api-429", true})
				}
			}
			seen := map[LimitKind]int{}
			for _, signal := range signals {
				if signal.kind == "" {
					continue
				}
				if prior, exists := seen[signal.kind]; exists {
					if result.Signals[prior].Candidate && !signal.candidate {
						result.Signals[prior].Candidate = false
						result.Signals[prior].Rule = signal.rule
					}
					continue
				}
				if len(result.Signals) == 256 {
					return result, errors.New("captured output has too many limit records")
				}
				seen[signal.kind] = len(result.Signals)
				hash := sha256.Sum256(raw)
				result.Signals = append(result.Signals, Diagnostic{
					Kind: signal.kind, Rule: signal.rule, Stream: stream, Line: line,
					Offset: int64(start), Bytes: len(raw), SHA256: hex.EncodeToString(hash[:]),
					Structured: structured, Candidate: signal.candidate,
				})
			}
		}
	}
	result.Complete = true
	return result, nil
}

// encoding/json alone accepts duplicate members, including conflicting error
// markers. Walk bounded tokens first and reject ambiguity at every depth.
func decodeObject(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := uniqueValue(decoder, 0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var event map[string]any
	if err := json.Unmarshal(data, &event); err != nil || event == nil {
		return nil, errors.New("expected JSON object")
	}
	return event, nil
}

func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds capture bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("unexpected JSON delimiter")
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate or invalid JSON member")
			}
			seen[name] = true
		}
		if err := uniqueValue(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
