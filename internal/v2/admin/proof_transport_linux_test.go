//go:build linux

package admin

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Exercise the real producer DTO, helper envelope/frame and strict readers.
// This is a transport regression with adversarial synthetic proof values,
// not a new installed kernel measurement or a successful lane launch.
func TestIsolationProofTransport(t *testing.T) {
	proof, runtimeRef, binding, now := isolationShape(t)
	proof.Observation.Handle.Target = api.LifeRef{LifeID: proof.Observation.Handle.ID, Run: 1}
	proof.Observation.PromptStatus = "unknown"
	proof.Observation.ObservedAt = proof.ObservedAt
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	pin := api.BlobRef{ID: proof.Observation.Handle.ID, Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	packet, err := json.Marshal(isolationPacket{Reference: pin, Bytes: raw})
	if err != nil {
		t.Fatal(err)
	}
	response := helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: proof.Nonce, Result: packet}
	var stream bytes.Buffer
	if err := writeFrame(&stream, response); err != nil {
		t.Fatal(err)
	}
	encoded := stream.Bytes()
	if len(encoded) < 4 || int(binary.BigEndian.Uint32(encoded)) != len(encoded)-4 {
		t.Fatal("helper producer did not retain its actual bounded frame length")
	}
	for _, reader := range []struct {
		name   string
		decode func([]byte, any) error
	}{{"helper", decodeStrict}, {"wire", wire.Decode}} {
		t.Run(reader.name, func(t *testing.T) {
			var received helperResponse
			if err := reader.decode(encoded[4:], &received); err != nil || !reflect.DeepEqual(received, response) {
				t.Fatal("acceptance: isolation helper envelope lost the producer's exact payload")
			}
			var retained isolationPacket
			if err := reader.decode(received.Result, &retained); err != nil || retained.Reference != pin || !bytes.Equal(retained.Bytes, raw) {
				t.Fatal("acceptance: isolation packet lost its exact proof pin or bytes")
			}
			var decoded isolationProof
			if err := reader.decode(retained.Bytes, &decoded); err != nil || !reflect.DeepEqual(decoded, proof) {
				t.Fatal("acceptance: isolation proof transport rejected or changed the producer's limit pairs", err)
			}
			capabilities, err := isolationCapabilities(decoded, pin, binding, runtimeRef, now)
			if err != nil || !capabilities.Available || len(capabilities.Checks) != 9 {
				t.Fatal("acceptance: transported isolation proof lost its existing measured-evidence validation")
			}
		})
	}
}

func TestIsolationProofShapeRefusal(t *testing.T) {
	proof, _, _, _ := isolationShape(t)
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct{ name, value, path, reason string }{
		{"short", `[["pids.max"]]`, "$.Limits[]", "length"},
		{"long", `[["pids.max","1","extra"]]`, "$.Limits[]", "length"},
		{"null", `null`, "$.Limits", "null"},
		{"member", `[["pids.max",1]]`, "$.Limits[][]", "type"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			object["Limits"] = json.RawMessage(sample.value)
			changed, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			var decoded isolationProof
			err = decodeStrict(changed, &decoded)
			var typed *api.Error
			want := "invalid JSON object or field shape (frame=isolation_proof; object=isolationProof; field=" + sample.path + "; reason=" + sample.reason + ")"
			if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Message != want || strings.Contains(err.Error(), string(proof.Nonce)) {
				t.Fatal("acceptance: isolation proof refusal lost its exact private-safe schema location")
			}
		})
	}
}
