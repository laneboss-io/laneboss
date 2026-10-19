package wire

import (
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCredentialEvidenceClass(t *testing.T) {
	content := []byte(makeRequest(t, "health", api.HealthRequest{}).RequestID)
	ref := api.BlobRef{ID: "protected-profile-evidence", Class: "credential_evidence", Bytes: int64(len(content)), SHA256: digestOf(content)}
	raw, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	var actual api.BlobRef
	if err := Decode(raw, &actual); err != nil || actual != ref {
		t.Fatal("retained credential evidence class was rejected", err)
	}
	raw, err = json.Marshal(api.BlobBeginRequest{Class: ref.Class, Bytes: ref.Bytes, SHA256: ref.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	var upload api.BlobBeginRequest
	if err := Decode(raw, &upload); err == nil {
		t.Fatal("public upload accepted protected credential evidence")
	}
}
