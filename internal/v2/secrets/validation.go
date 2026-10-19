package secrets

import (
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// These typed validators are shared by the service and both CLI input forms.
// Exact object shape (including the empty object) is checked before calling them.
func ValidateKeyInput(api.Empty) error                      { return nil }
func ValidateListInput(api.Empty) error                     { return nil }
func ValidateStageInput(input api.SecretStageRequest) error { return validateStage(input) }

func ValidateImportInput(input api.SecretImportRequest) error {
	if !wire.Name(input.Name) || !wire.Name(input.Version) || !wire.ID(string(input.SealedUploadID)) {
		return wire.Error(api.CodeInvalid, "import request requires exact sealed source metadata")
	}
	return nil
}

func ValidateRotateInput(input api.SecretRotateRequest) error {
	if !wire.Name(input.Name) || !wire.Name(input.ExpectedVersion) || !wire.ID(string(input.SealedUploadID)) {
		return wire.Error(api.CodeInvalid, "rotate request requires exact sealed source metadata")
	}
	return nil
}

func ValidateRevokeInput(input api.SecretRevokeRequest) error {
	if !wire.Name(input.Name) || !wire.Name(input.ExpectedVersion) {
		return wire.Error(api.CodeInvalid, "revoke request requires exact source metadata")
	}
	return nil
}
