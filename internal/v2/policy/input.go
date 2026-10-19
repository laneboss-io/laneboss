package policy

import (
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func inputInvalid(message string) *api.Error {
	err := invalid(message)
	err.Owner = "lb-v2-policy"
	return err
}

// ValidateGetInput is shared by the service and all CLI forms. An empty life
// selects the authenticated policy; a supplied life must be a valid identifier.
func ValidateGetInput(request api.PolicyGetRequest) error {
	if request.LifeID != "" && !validID(request.LifeID) {
		return inputInvalid("invalid policy life ID")
	}
	return nil
}

// ValidateConfigReadInput checks request data only. The service separately
// resolves the caller's authority and the selected approved role/source set.
func ValidateConfigReadInput(request api.ConfigReadRequest) error {
	if request.Context != nil && !validRole(*request.Context) {
		return inputInvalid("invalid configuration role context")
	}
	switch request.View {
	case "path", "list", "show", "settings", "roles", "plugins", "channels":
		return nil
	default:
		return inputInvalid("unknown configuration view")
	}
}

// ValidateConfigValidateInput admits exactly the Empty wire object. Checking
// raw bytes keeps extra fields, duplicates, nulls and non-objects from being
// discarded before the shared CLI and service handler validate this method.
func ValidateConfigValidateInput(raw json.RawMessage) error {
	var request api.Empty
	return api.DecodeObject(raw, &request)
}
