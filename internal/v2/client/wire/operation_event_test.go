package wire

import (
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestOperationEventOptionalDigest(t *testing.T) {
	for _, digest := range []api.Digest{"", digestOf([]byte("actual request"))} {
		input := api.OperationEvent{Operation: api.Operation{ID: "operation-fixture", Status: "succeeded"}, RequestSHA256: digest}
		raw, err := EncodeOperationEvent(input)
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatal(err)
		}
		_, present := members["request_sha256"]
		if present != (digest != "") {
			t.Fatal("operation encoder confused missing and actual request digest")
		}
		var output api.OperationEvent
		if err := Decode(raw, &output); err != nil || output != input {
			t.Fatal("optional operation digest did not round trip", err)
		}
		members["request_sha256"] = json.RawMessage(`""`)
		invalid, err := json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		if err := Decode(invalid, &output); err == nil {
			t.Fatal("explicit invalid operation digest bypassed strict validation")
		}
		delete(members, "request_sha256")
		members["intent_digest"] = json.RawMessage(`"unrecognized"`)
		invalid, err = json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		if err := Decode(invalid, &output); err == nil {
			t.Fatal("optional operation schema admitted an unknown digest field")
		}
	}
}
