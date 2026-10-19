package wire

import (
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAPIKeySlot(t *testing.T) {
	data, err := json.Marshal(api.CredentialSlot{ID: "key-slot", Mode: "claude-api-key", ProfileGrantID: "key-grant",
		ProfileID: "key-profile", LeaseID: "key-lease", ExpiresAt: "2100-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	var slot api.CredentialSlot
	if err := Decode(data, &slot); err != nil || slot.Mode != "claude-api-key" {
		t.Fatal("API key slot wire kind refused", err)
	}
}
