package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPrepareRetainsIntent(t *testing.T) {
	raw := json.RawMessage("{ \"record_id\" : \"one\" }")
	request := api.Request{Config: "demo", Method: "records.get", Params: raw}
	first, err := PrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Params, raw) || first.RequestSHA256 != second.RequestSHA256 || len(first.RequestID) != 32 || first.RequestID == second.RequestID || first.IdempotencyKey == second.IdempotencyKey {
		t.Fatal("input bytes, intent digest or random correlation domain changed")
	}
	replayed, err := PrepareRequest(first)
	if err != nil || replayed.RequestID != first.RequestID || replayed.IdempotencyKey != first.IdempotencyKey {
		t.Fatal("preparation changed a retained retry identity")
	}
	raw[0] = '['
	if first.Params[0] != '{' {
		t.Fatal("prepared request retained mutable caller storage")
	}
}

func TestMutationRetainsCallerKey(t *testing.T) {
	request := api.Request{Config: "demo", Method: "blob.begin", Params: json.RawMessage(`{"class":"record","bytes":12,"sha256":"fixture"}`)}
	var typed *api.Error
	if _, err := PrepareRequest(request); !errors.As(err, &typed) || typed.Code != api.CodeInvalid || !strings.Contains(typed.Instead, "--idempotency-key") {
		t.Fatal("mutation silently minted a new retry key")
	}
	request.IdempotencyKey = api.ID(strings.Repeat("k", 32))
	first, err := PrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.IdempotencyKey != request.IdempotencyKey || second.IdempotencyKey != first.IdempotencyKey || second.RequestSHA256 != first.RequestSHA256 || first.RequestID == second.RequestID {
		t.Fatal("retry changed the mutation identity or reused correlation IDs")
	}
}

func TestPrepareRejectsMismatch(t *testing.T) {
	request := api.Request{Config: "demo", Method: "records.get", Params: json.RawMessage(`{"record_id":"one"}`)}
	sealed, err := PrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	sealed.Params = json.RawMessage(`{"record_id":"two"}`)
	if _, err := PrepareRequest(sealed); err == nil {
		t.Fatal("changed content retained an old digest")
	}
	request.Proof = &api.ProofRef{RequestSHA256: api.Digest(strings.Repeat("0", 64))}
	if _, err := PrepareRequest(request); err == nil {
		t.Fatal("wrong operation proof was accepted")
	}
}

func TestClientBindingIsFixed(t *testing.T) {
	client := &Client{Options: Options{Config: "demo"}}
	request := api.Request{Config: "another", Method: "records.get", Params: json.RawMessage(`{"record_id":"one"}`)}
	if _, err := client.PrepareRequest(request); err == nil {
		t.Fatal("request changed the client's binding")
	}
	request.Config = ""
	prepared, err := client.PrepareRequest(request)
	if err != nil || prepared.Config != "demo" || client.Options.Config != "demo" {
		t.Fatal("bound configuration was not retained")
	}
}
