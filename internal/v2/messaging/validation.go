package messaging

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const (
	owner        = "lb-v2-messaging"
	MaxMailBytes = 256 * 1024
	maxCursor    = 4096
	maxExact     = 1<<53 - 1
)

func problem(code api.ErrorCode, message string) *api.Error {
	return &api.Error{
		Code: code, Message: message, Owner: owner,
		Instead: "Use the authentic direct report line, or repair the named prerequisite; retain the request and evidence.",
	}
}

func validID(id api.ID) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validDigest(digest api.Digest) bool {
	if len(digest) != 64 || strings.ToLower(string(digest)) != string(digest) {
		return false
	}
	_, err := hex.DecodeString(string(digest))
	return err == nil
}

func validTimestamp(timestamp api.Timestamp) bool {
	if len(timestamp) == 0 || timestamp[len(timestamp)-1] != 'Z' {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, string(timestamp))
	return err == nil
}

func validContent(ref api.BlobRef) error {
	if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > MaxMailBytes || ref.Class != "report" {
		return problem(api.CodeInvalid, "mail requires a committed report-class blob of 1 to 262144 bytes")
	}
	return nil
}

func validSend(request api.MailSendRequest) error {
	if (request.RecipientLifeID == "") == (request.ChannelGrantID == "") {
		return problem(api.CodeInvalid, "mail requires exactly one recipient life or human channel grant")
	}
	if request.RecipientLifeID != "" && !validID(request.RecipientLifeID) || request.ChannelGrantID != "" && !validID(request.ChannelGrantID) || request.ReplyTo != "" && !validID(request.ReplyTo) {
		return problem(api.CodeInvalid, "mail identifiers are invalid")
	}
	return validContent(request.Content)
}

func validReport(request api.ReportRequest) error {
	if request.Artifacts == nil || len(request.Artifacts) > 200 {
		return problem(api.CodeInvalid, "report artifacts must be an array")
	}
	if request.ChannelGrantID != "" && !validID(request.ChannelGrantID) || request.ReplyTo != "" && !validID(request.ReplyTo) {
		return problem(api.CodeInvalid, "report identifiers are invalid")
	}
	seen := make(map[api.ID]bool)
	for _, artifact := range request.Artifacts {
		if !validID(artifact.ID) || !validDigest(artifact.SHA256) || artifact.Bytes < 0 || artifact.Bytes > api.MaxObjectBytes || artifact.Class != "artifact" {
			return problem(api.CodeInvalid, "report artifact reference is invalid")
		}
		if seen[artifact.ID] {
			return problem(api.CodeInvalid, "report artifact references must be unique")
		}
		seen[artifact.ID] = true
	}
	return validContent(request.Content)
}

func validList(request api.ListRequest) error {
	if request.LifeID != "" && !validID(request.LifeID) || request.Limit < 1 || request.Limit > 200 || len(request.Cursor) > maxCursor || !utf8.ValidString(request.Cursor) {
		return problem(api.CodeInvalid, "mail list requires a valid life, bounded cursor and limit from 1 to 200")
	}
	return nil
}

func validActor(actor api.Actor) bool {
	if !validID(actor.ID) {
		return false
	}
	if actor.Kind == "human" {
		return actor.LifeID == "" && actor.Level == 0 && actor.Role == ""
	}
	return actor.Kind == "lane" && validID(actor.LifeID) && actor.Level >= 3 && actor.Level <= 6 && actor.Role != ""
}

func validStoredMail(mail api.Mail) error {
	if !validID(mail.ID) || !validActor(mail.Sender) || mail.Generation == 0 || mail.Generation > maxExact || mail.QueuedSeq == 0 || mail.QueuedSeq > maxExact || mail.Source != "cli" && mail.Source != "dashboard" {
		return problem(api.CodeIntegrity, "stored mail has invalid provenance")
	}
	if mail.LogicalTurnID != "" && !validID(mail.LogicalTurnID) {
		return problem(api.CodeIntegrity, "stored mail has an invalid logical turn")
	}
	switch mail.Status {
	case "queued", "delivering", "delivered", "returned", "answered":
	default:
		return problem(api.CodeIntegrity, "stored mail has an unknown delivery status")
	}
	if err := validReport(api.ReportRequest{Content: mail.Content, Artifacts: mail.Artifacts}); err != nil {
		return problem(api.CodeIntegrity, "stored mail has invalid artifact references")
	}
	if mail.Status == "answered" {
		if !mail.Ask || mail.Answer == nil || !validID(mail.Answer.DecisionID) || !validID(mail.Answer.Source.ID) || !validDigest(mail.Answer.Source.SHA256) || mail.Answer.Source.Generation == 0 || !validID(mail.Answer.Content.ID) || !validDigest(mail.Answer.Content.SHA256) || mail.Answer.Content.Bytes < 1 || mail.Answer.Content.Bytes > api.MaxObjectBytes || !validID(mail.Answer.Authority.ReceiptID) || mail.Answer.Authority.OrgGeneration == 0 || mail.Answer.Authority.SourceSeq == 0 || mail.Answer.Authority.Kind != "human" && mail.Answer.Authority.Kind != "d6" {
			return problem(api.CodeIntegrity, "answered mail lacks its authoritative decision reference")
		}
	} else if mail.Answer != nil {
		return problem(api.CodeIntegrity, "unanswered mail must not carry a decision answer")
	}
	if err := validSend(api.MailSendRequest{
		RecipientLifeID: mail.RecipientLifeID, ChannelGrantID: mail.ChannelGrantID,
		Content: mail.Content, Ask: mail.Ask, ReplyTo: mail.ReplyTo,
	}); err != nil {
		return problem(api.CodeIntegrity, "stored mail has invalid content or destination")
	}
	return nil
}

// DecodeMailSend validates the exact frozen body, including required zero values.
func DecodeMailSend(raw []byte) (api.MailSendRequest, error) {
	var request api.MailSendRequest
	if err := decodeBody(raw, &request); err != nil {
		return request, err
	}
	return request, validSend(request)
}

func DecodeMailList(raw []byte) (api.ListRequest, error) {
	var request api.ListRequest
	if err := decodeBody(raw, &request); err != nil {
		return request, err
	}
	return request, validList(request)
}

func DecodeReport(raw []byte) (api.ReportRequest, error) {
	var request api.ReportRequest
	if err := decodeBody(raw, &request); err != nil {
		return request, err
	}
	return request, validReport(request)
}

func decodeBody(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes || !utf8.Valid(raw) || !jsonUnicodeScalars(raw) {
		return problem(api.CodeInvalid, "messaging input must be bounded UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := uniqueJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return problem(api.CodeInvalid, "messaging input contains trailing JSON")
	}
	if err := exactShape(raw, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return problem(api.CodeInvalid, "messaging request fields have invalid types")
	}
	return nil
}

func uniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return problem(api.CodeInvalid, "messaging JSON is nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return problem(api.CodeInvalid, "messaging JSON is malformed or contains null")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return problem(api.CodeInvalid, "messaging JSON contains duplicate or invalid keys")
			}
			seen[name] = true
			if err := uniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return problem(api.CodeInvalid, "messaging JSON has an unexpected delimiter")
	}
	closing, err := decoder.Token()
	if err != nil || delimiter == '{' && closing != json.Delim('}') || delimiter == '[' && closing != json.Delim(']') {
		return problem(api.CodeInvalid, "messaging JSON has an unclosed object or array")
	}
	return nil
}

// encoding/json deliberately accepts case-insensitive keys and missing fields.
// Neither is permitted by the frozen wire schema.
func exactShape(raw json.RawMessage, kind reflect.Type) error {
	if kind.Kind() == reflect.Pointer {
		return exactShape(raw, kind.Elem())
	}
	if kind.Kind() == reflect.Struct {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return problem(api.CodeInvalid, "messaging request must contain the exact object shape")
		}
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			value, exists := fields[tag[0]]
			if !exists {
				if len(tag) > 1 && tag[1] == "omitempty" {
					continue
				}
				return problem(api.CodeInvalid, "messaging request is missing a required field")
			}
			if err := exactShape(value, field.Type); err != nil {
				return err
			}
			delete(fields, tag[0])
		}
		if len(fields) != 0 {
			return problem(api.CodeInvalid, "messaging request contains an unknown field")
		}
	}
	if kind.Kind() == reflect.Slice {
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil || items == nil {
			return problem(api.CodeInvalid, "messaging arrays must be JSON arrays")
		}
		for _, item := range items {
			if err := exactShape(item, kind.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Preserve the
// source's meaning by rejecting those escapes instead of normalizing them.
// Ordinary escaped backslashes, U+FFFD itself and valid pairs remain valid.
func jsonUnicodeScalars(raw []byte) bool {
	quoted := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		unit, ok := jsonHexUnit(raw, i+1)
		if !ok {
			return false
		}
		i += 4
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, ok := jsonHexUnit(raw, i+3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func jsonHexUnit(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	var result uint16
	for _, digit := range raw[start : start+4] {
		result <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			result |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			result |= uint16(digit - 'a' + 10)
		case digit >= 'A' && digit <= 'F':
			result |= uint16(digit - 'A' + 10)
		default:
			return 0, false
		}
	}
	return result, true
}
