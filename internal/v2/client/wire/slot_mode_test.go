package wire

import (
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestSlotModeReason(t *testing.T) {
	slot := api.CredentialSlot{ID: "slot-one", ProfileID: "profile-one", ProfileGrantID: "grant-one",
		Mode: "helper", LeaseID: "lease-one", ExpiresAt: "2100-01-01T00:00:00Z"}
	raw, err := json.Marshal(slot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded api.CredentialSlot
	err = Decode(raw, &decoded)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || api.HelperReason(err) != "plan_slot_mode" {
		t.Fatal("private credential mode lost its frozen-schema refusal check", api.HelperReason(err), err)
	}
}
