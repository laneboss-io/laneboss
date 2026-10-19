package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type jsonDiagnosticReply struct {
	Limits [][2]string     `json:"limits"`
	Count  uint8           `json:"count"`
	Note   *string         `json:"note,omitempty"`
	Raw    json.RawMessage `json:"raw,omitempty"`
}

type jsonDiagnosticEnvelope struct {
	Reply jsonDiagnosticReply `json:"reply"`
}

func TestFixedArrayJSON(t *testing.T) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	private := hex.EncodeToString(random[:])
	want := jsonDiagnosticEnvelope{Reply: jsonDiagnosticReply{Limits: [][2]string{{"name-" + private, "value-" + private}, {"other", ""}}, Count: 7}}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got jsonDiagnosticEnvelope
	if err := DecodeObject(raw, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("acceptance: strict JSON lost the producer's fixed pair array")
	}
	type zeroArray struct {
		Empty [0]string `json:"empty"`
	}
	var empty zeroArray
	if err := DecodeObject([]byte(`{"empty":[]}`), &empty); err != nil {
		t.Fatal("acceptance: strict JSON rejected an exact zero-length array")
	}
}

func TestShapeDiag(t *testing.T) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	private := "private-" + hex.EncodeToString(random[:])
	valid := `{"reply":{"limits":[["a","b"]],"count":7}}`
	for _, sample := range []struct{ name, raw, path, reason string }{
		{"missing", `{"reply":{"count":7}}`, "$.reply.limits", "missing"},
		{"null", `{"reply":{"limits":null,"count":7}}`, "$.reply.limits", "null"},
		{"null-optional", `{"reply":{"limits":[],"count":7,"note":null}}`, "$.reply.note", "null"},
		{"type", `{"reply":{"limits":"` + private + `","count":7}}`, "$.reply.limits", "type"},
		{"empty-pair", `{"reply":{"limits":[[]],"count":7}}`, "$.reply.limits[]", "length"},
		{"short-pair", `{"reply":{"limits":[["a"]],"count":7}}`, "$.reply.limits[]", "length"},
		{"long-pair", `{"reply":{"limits":[["a","b","c"]],"count":7}}`, "$.reply.limits[]", "length"},
		{"null-pair", `{"reply":{"limits":[null],"count":7}}`, "$.reply.limits[]", "null"},
		{"null-member", `{"reply":{"limits":[["a",null]],"count":7}}`, "$.reply.limits[][]", "null"},
		{"member-type", `{"reply":{"limits":[["a",2]],"count":7}}`, "$.reply.limits[][]", "type"},
		{"unknown", `{"reply":{"limits":[],"count":7,"` + private + `":"` + private + `"}}`, "$.reply.*", "unknown"},
		{"duplicate", `{"reply":{"limits":[],"count":7,"co\u0075nt":8}}`, "$.reply.count", "duplicate"},
		{"duplicate-private", `{"reply":{"limits":[],"count":7,"` + private + `":1,"` + private + `":2}}`, "$.reply.*", "duplicate"},
		{"duplicate-raw", `{"reply":{"limits":[],"count":7,"raw":{"` + private + `":1,"` + private + `":2}}}`, "$.reply.raw.*", "duplicate"},
		{"range", `{"reply":{"limits":[],"count":256}}`, "$.reply.count", "range"},
		{"trailing", valid + ` {}`, "$", "trailing"},
		{"surrogate", `{"reply":{"limits":[["\ud800","b"]],"count":7}}`, "$", "surrogate"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var got jsonDiagnosticEnvelope
			err := DecodeObject([]byte(sample.raw), &got)
			var typed *Error
			want := "invalid JSON object or field shape (frame=object; object=jsonDiagnosticEnvelope; field=" + sample.path + "; reason=" + sample.reason + ")"
			if !errors.As(err, &typed) || typed.Code != CodeInvalid || typed.Message != want || strings.Contains(err.Error(), private) || strings.Contains(typed.Instead, private) {
				t.Fatal("acceptance: JSON refusal lost its closed object, field path, reason or privacy")
			}
		})
	}
}
