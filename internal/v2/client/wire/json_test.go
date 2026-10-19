package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func digestOf(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func TestEnrollmentDecodeFields(t *testing.T) {
	nonce, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	base := api.AdminEnrollmentFrame{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision,
		Config: "native-enroll", Generation: 2, ArtifactSHA256: digestOf([]byte(nonce)), Nonce: nonce,
		Method: "enroll_begin", Params: json.RawMessage("{}")}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var control api.AdminEnrollmentFrame
	if err := DecodeAdminEnrollmentFrame(raw, &control); err != nil || control.Nonce != nonce || AdminEnrollmentNonce(raw) != nonce {
		t.Fatal("valid helper codec changed correlation", err)
	}
	for _, field := range []string{"protocol", "contract_revision", "config", "generation", "artifact_sha256", "nonce", "method", "params"} {
		t.Run(field, func(t *testing.T) {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			delete(object, field)
			changed, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			var decoded api.AdminEnrollmentFrame
			if Decode(changed, &decoded) == nil {
				t.Fatal("strict decoder accepted a missing field")
			}
			if err := DecodeAdminEnrollmentFrame(changed, &decoded); err == nil || api.AdminEnrollmentFailedField(err) != field {
				t.Fatal("enrollment refusal lost its actual known field")
			}
		})
	}
	quoted, err := json.Marshal(nonce)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := []byte(strings.TrimSuffix(string(raw), "}") + ",\"nonce\":" + string(quoted) + "}")
	var decoded api.AdminEnrollmentFrame
	if err := DecodeAdminEnrollmentFrame(duplicate, &decoded); err == nil || api.AdminEnrollmentFailedField(err) != "frame" || AdminEnrollmentNonce(duplicate) != "" {
		t.Fatal("duplicate JSON acquired correlation or escaped the strict decoder")
	}
}

func makeRequest(t *testing.T, method api.Method, params any) api.Request {
	t.Helper()
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: "wire-fixture", RequestID: id, IdempotencyKey: key, Method: method, Params: data}
	request.RequestSHA256, err = RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestRejectJSONAmbiguity(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"a":1,"a":2}`),
		[]byte(`{"a":{"b":1,"\u0062":2}}`),
		[]byte(`{} {}`), []byte(`{"x":NaN}`),
		[]byte(`{"x":1e999}`), []byte(`{"x":"\ud800"}`),
		[]byte(`{"x":"\udc00"}`),
		{'"', 0xff, '"'},
		[]byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)),
	}
	for i, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Fatalf("ambiguous JSON case %d accepted", i)
		}
	}
	if _, err := Parse([]byte(`{"x":"\ud834\udd1e","y":"\\uD800"}`)); err != nil {
		t.Fatal("valid Unicode control refused:", err)
	}
}

func TestRequiredAndClosedFields(t *testing.T) {
	cases := []string{
		`{"object_id":"object","offset":0,"limit":1,"host_path":"x"}`,
		`{"object_id":"object","offset":0}`,
		`{"object_id":"object","offset":null,"limit":1}`,
		`{"Object_ID":"object","offset":0,"limit":1}`,
		`{"object_id":"object","offset":1e0,"limit":1}`,
		`{"object_id":"object","offset":9007199254740992,"limit":1}`,
		`{"object_id":"object","offset":-1,"limit":1}`,
	}
	for i, data := range cases {
		var input api.BlobReadRequest
		if err := Decode([]byte(data), &input); err == nil {
			t.Fatalf("invalid typed case %d accepted", i)
		}
	}
	var valid api.BlobReadRequest
	if err := Decode([]byte(`{"object_id":"object","offset":0,"limit":1}`), &valid); err != nil || valid.Limit != 1 {
		t.Fatal("valid zero integer control refused:", err)
	}
	var appendRequest api.RecordAppendRequest
	data, err := json.Marshal(api.RecordAppendRequest{Collection: "observations",
		Content: api.BlobRef{ID: "blob", SHA256: digestOf(nil), Class: "record"}, RelatedIDs: nil})
	if err != nil {
		t.Fatal(err)
	}
	if err := Decode(data, &appendRequest); err == nil {
		t.Fatal("null array accepted")
	}
}

func TestCanonicalJCS(t *testing.T) {
	cases := []struct{ input, expected string }{
		{`{"z":1,"a":2}`, `{"a":2,"z":1}`},
		{`[1E30,4.50,2e-3,0.000000000000000000000000001]`,
			`[1e+30,4.5,0.002,1e-27]`},
		{`[-0,1e-6,1e-7,1e20,1e21]`, `[` +
			`0,0.000001,1e-7,100000000000000000000,1e+21]`},
		{`{"\ue000":1,"\ud800\udc00":2}`, "{\"𐀀\":2,\"\ue000\":1}"},
		{`{"x":"<>&\u2028\u000f\n"}`, "{\"x\":\"<>&\u2028\\u000f\\n\"}"},
	}
	for _, test := range cases {
		actual, err := Canonical([]byte(test.input))
		if err != nil || string(actual) != test.expected {
			t.Fatalf("JCS mismatch: %q, %v", actual, err)
		}
	}
}

func TestDigestAndVersion(t *testing.T) {
	request := makeRequest(t, "blob.read", api.BlobReadRequest{ObjectID: "object", Limit: 1})
	if err := ValidateRequest(request); err != nil {
		t.Fatal(err)
	}
	original := request.RequestSHA256
	request.RequestID, request.IdempotencyKey = request.IdempotencyKey, request.RequestID
	request.Proof = &api.ProofRef{ID: "proof", RequestSHA256: original}
	next, err := RequestDigest(request)
	if err != nil || next != original {
		t.Fatal("identity/proof altered intent digest", err)
	}
	request.Proof = nil
	request.Params = json.RawMessage(`{"limit":1,"offset":0,"object_id":"object"}`)
	if err := ValidateRequest(request); err != nil {
		t.Fatal("member order changed digest", err)
	}
	request.Params = json.RawMessage(`{"limit":2,"offset":0,"object_id":"object"}`)
	requireCode(t, ValidateRequest(request), api.CodeInvalid)
	request.Schema++
	requireCode(t, ValidateRequest(request), api.CodeVersion)
}

func TestFrameBounds(t *testing.T) {
	for _, header := range [][]byte{{0, 0, 0, 0}, {0, 16, 0, 1}, {0, 0, 0, 2, 'x'}} {
		if _, err := ReadFrame(bytes.NewReader(header)); err == nil {
			t.Fatal("invalid or truncated frame accepted")
		}
	}
	var encoded bytes.Buffer
	data := []byte(`{"value":"frame"}`)
	if err := WriteFrame(&encoded, data); err != nil {
		t.Fatal(err)
	}
	actual, err := ReadFrame(&encoded)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("framing control failed", err)
	}
}

func TestResponseUnion(t *testing.T) {
	request := makeRequest(t, "blob.read", api.BlobReadRequest{ObjectID: "object", Limit: 1})
	result, err := json.Marshal(api.BlobChunk{ObjectID: "object", Data: []byte{}, SHA256: digestOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID, Result: result}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(data, request); err != nil {
		t.Fatal(err)
	}
	response.Error = &api.Error{Code: api.CodeForbidden, Message: "denied", Instead: "use parent"}
	data, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(data, request); err == nil {
		t.Fatal("result and error accepted together")
	}
}

func TestChunkHashAndEnum(t *testing.T) {
	request := makeRequest(t, "blob.chunk", api.BlobChunk{ObjectID: "blob", Data: []byte("actual"), SHA256: digestOf([]byte("different"))})
	requireCode(t, ValidateRequest(request), api.CodeInvalid)
	request = makeRequest(t, "records.query", api.RecordQuery{Collection: "invented", SearchMode: "keyword", Limit: 1})
	requireCode(t, ValidateRequest(request), api.CodeInvalid)
	request = makeRequest(t, "blob.chunk", api.BlobChunk{ObjectID: "blob", Data: []byte("actual"), SHA256: digestOf([]byte("actual"))})
	if err := ValidateRequest(request); err != nil {
		t.Fatal("valid chunk control refused", err)
	}
}

func TestWrongSchema(t *testing.T) {
	request := makeRequest(t, "blob.read", api.BlobReadRequest{ObjectID: "object", Limit: 1})
	request.Schema++
	var err error
	// Keep the digest correct for the wrong schema so a different validation
	// error cannot accidentally satisfy the version gate.
	request.RequestSHA256, err = RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeRequest(data)
	if err == nil {
		t.Fatal("wrong schema reached request dispatch")
	}
	requireCode(t, err, api.CodeVersion)
}
