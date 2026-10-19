package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

type jsonRawEnvelope struct {
	X json.RawMessage `json:"x"`
}

func TestRawJSONDiagnostic(t *testing.T) {
	for _, sample := range []struct {
		name, reason string
		data         []byte
	}{
		{"empty", "empty", nil},
		{"limit", "frame_limit", []byte(`{"x":"` + strings.Repeat("x", MaxFrameBytes) + `"}`)},
		{"utf8", "utf8", []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}},
		{"surrogate", "surrogate", []byte(`{"x":"\ud800"}`)},
		{"duplicate", "duplicate", []byte(`{"x":1,"x":2}`)},
		{"depth", "depth", []byte(`{"x":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}")},
		{"syntax", "syntax", []byte(`{"x":`)},
		{"trailing", "trailing", []byte(`{} {}`)},
		{"nonfinite", "nonfinite", []byte(`{"x":1e999}`)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var result jsonRawEnvelope
			err := DecodeObjectFrame(sample.data, &result, JSONFrameHelperResponse)
			var typed *Error
			frame, reason := JSONFailureFacts(err)
			if !errors.As(err, &typed) || typed.Code != CodeInvalid || frame != JSONFrameHelperResponse || reason != sample.reason || !utf8.ValidString(typed.Message) {
				t.Fatal("acceptance: raw JSON refusal lost its actual frame kind or parser reason")
			}
		})
	}
}

func TestCanonicalJSONDiagnostic(t *testing.T) {
	bad := []byte(`{"x":1,"x":2}`)
	for _, reader := range []struct {
		name  string
		frame JSONFrameKind
		call  func([]byte) error
	}{
		{"canonical", JSONFrameCanonical, func(raw []byte) error { _, err := CanonicalJSON(raw); return err }},
		{"object", JSONFrameCanonicalObject, func(raw []byte) error { _, err := CanonicalObjectJSON(raw); return err }},
		{"stored", JSONFrameStoredObject, ValidateObjectJSON},
	} {
		t.Run(reader.name, func(t *testing.T) {
			err := reader.call(bad)
			frame, reason := JSONFailureFacts(err)
			if frame != reader.frame || reason != "duplicate" {
				t.Fatal("acceptance: canonical JSON refusal lost its frame and raw parser reason")
			}
		})
	}
}

func TestJSONFailureFactPrivacy(t *testing.T) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	private := "private-" + hex.EncodeToString(random[:])
	for _, message := range []string{private,
		"invalid JSON object or field shape (frame=" + private + "; object=object; field=$; reason=utf8)",
		"invalid JSON object or field shape (frame=helper_response; object=object; field=$; reason=" + private + ")"} {
		frame, reason := JSONFailureFacts(&Error{Code: CodeInvalid, Message: message})
		if frame != "" || reason != "" {
			t.Fatal("acceptance: private JSON failure text became an allowed journal fact")
		}
	}
	var empty Empty
	err := DecodeObjectFrame(nil, &empty, JSONFrameKind(private))
	frame, reason := JSONFailureFacts(err)
	if frame != JSONFrameObject || reason != "empty" || strings.Contains(err.Error(), private) {
		t.Fatal("acceptance: caller frame text escaped the closed diagnostic vocabulary")
	}
}
