package eventstore

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Records live in the existing immutable event stream, so its hashes, triggers,
// ownership checks and state verification also protect searchable history.
var recordKinds = []string{"lane-report", "decision", "owner-word", "ledger-row", "receipt"}
var recordAssignment = regexp.MustCompile(`(?i)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*([:=])[ \t]*(.*)$`)
var recordNumber = regexp.MustCompile(`^[0-9][0-9/.,%]*$`)

func RecordKind(kind string) bool { return contains(recordKinds, kind) }

// RecordPayload screens the exact bytes before building a record. Private
// sources keep only their name and hash; their text never reaches SQLite.
func RecordPayload(kind, source string, data []byte, private bool) (Object, error) {
	if !RecordKind(kind) {
		return nil, Refuse("record kind must be lane-report, decision, owner-word, ledger-row or receipt")
	}
	if source == "" || len(source) > 4096 || strings.IndexFunc(source, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return nil, Refuse("record source must be a bounded path or source name")
	}
	if rule := credentialText(source); rule != "" {
		return nil, Refuse("record source looks like a credential (%s); nothing was stored", rule)
	}
	if len(data) > 512*1024 || !utf8.Valid(data) || strings.IndexFunc(string(data), func(r rune) bool { return r < 32 && r != '\n' && r != '\r' && r != '\t' || r == 127 }) >= 0 {
		return nil, Refuse("record must be UTF-8 text of at most 512 KiB; binary data is not stored")
	}
	for i, line := range strings.Split(string(data), "\n") {
		if rule := credentialText(line); rule != "" {
			return nil, Refuse("record line %d looks like a credential (%s); nothing was stored", i+1, rule)
		}
	}
	if rule := credentialText(string(data)); rule != "" {
		return nil, Refuse("record contains a multiline credential shape (%s); nothing was stored", rule)
	}
	text := string(data)
	if private {
		source, text = filepath.Base(source), ""
	} else if RecordSettings(source, data) {
		return nil, Refuse("record contains settings values; keep only the source name and hash with --private")
	}
	return Object{"kind": kind, "source": source, "sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "text": text, "private": private}, nil
}

// RecordSettings is a public-record backstop, not part of the shared credential
// detector. Ordinary commands and code remain text; credential-like names with
// literal values become private when an archive report uses this classifier.
func RecordSettings(source string, data []byte) bool {
	content := string(data)
	if settingsSource(source) || strings.Contains(content, "```toml") || strings.Contains(content, "```json") || strings.Contains(content, "```yaml") {
		return true
	}
	for _, line := range strings.Split(content, "\n") {
		match := recordAssignment.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		value := strings.TrimSpace(match[3])
		// A colon is only a lowercase YAML-style assignment, not a title or
		// numeric result. Go := must not turn its leading = into a literal.
		if strings.HasPrefix(value, "=") || match[2] == ":" && (match[1] != strings.ToLower(match[1]) || recordNumber.MatchString(value)) || !literalAssignment(value) {
			continue
		}
		for _, part := range strings.FieldsFunc(strings.ToLower(match[1]), func(r rune) bool { return r == '_' || r == '.' || r == '-' }) {
			if contains([]string{"pass", "pwd", "pw", "key", "secret", "token", "auth", "cred", "creds"}, part) || strings.HasSuffix(part, "password") || strings.HasSuffix(part, "passwd") {
				return true
			}
		}
	}
	return false
}

func settingsSource(source string) bool {
	name := strings.ToLower(filepath.Base(source))
	switch strings.ToLower(filepath.Ext(name)) {
	case ".toml", ".ini", ".env", ".yaml", ".yml", ".json", ".pem", ".key":
		return true
	}
	return name == ".env" || strings.HasPrefix(name, ".env.") || strings.HasPrefix(name, "settings.")
}

// ValidateRecord checks public event writes and the lane writer used by archive
// and pending flushes; event append cannot evade the store command's policy.
func ValidateRecord(p Object) error {
	if len(p) != 5 || !RecordKind(text(p["kind"])) || !digestGrammar.MatchString(text(p["sha256"])) {
		return Refuse("store.record has an invalid kind, hash or fields")
	}
	private, ok := p["private"].(bool)
	content, textOK := p["text"].(string)
	if !ok || !textOK || private && content != "" {
		return Refuse("store.record private text must be empty")
	}
	checked, err := RecordPayload(text(p["kind"]), text(p["source"]), []byte(content), private)
	if err != nil {
		return err
	}
	if checked["source"] != p["source"] || !private && checked["sha256"] != p["sha256"] {
		return Refuse("store.record source or text hash does not match")
	}
	return nil
}

// SearchRecords performs literal, case-insensitive keyword matching. Every
// query term must occur in the text or source. It never contacts a model.
func SearchRecords(events []Object, query, kind, lane string) ([]Object, error) {
	if strings.TrimSpace(query) == "" || len(query) > 1000 || kind != "" && !RecordKind(kind) || lane != "" && !laneGrammar.MatchString(lane) {
		return nil, Refuse("search needs a bounded query and valid kind/lane filters")
	}
	if rule := credentialText(query); rule != "" {
		return nil, Refuse("search query looks like a credential (%s)", rule)
	}
	matches := []Object{}
	for _, e := range events {
		if e["kind"] != "store.record" || lane != "" && e["lane"] != lane {
			continue
		}
		p := object(e["payload"])
		if err := ValidateRecord(p); err != nil {
			return nil, Integrity("a stored record fails validation")
		}
		if kind != "" && p["kind"] != kind {
			continue
		}
		haystack := strings.ToLower(text(p["text"]) + "\n" + text(p["source"]))
		found := true
		for _, word := range strings.Fields(strings.ToLower(query)) {
			found = found && strings.Contains(haystack, word)
		}
		if found {
			match := Object{}
			for key, value := range p {
				match[key] = value
			}
			match["id"], match["lane"], match["time"], match["seq"] = e["id"], e["lane"], e["recorded_at"], e["seq"]
			matches = append(matches, match)
		}
	}
	return matches, nil
}
