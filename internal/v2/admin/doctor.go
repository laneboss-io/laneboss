package admin

import (
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateDoctorInput is shared by the CLI input hook and service handler.
// Doctor accepts exactly an empty JSON object, with optional JSON whitespace.
func ValidateDoctorInput(raw json.RawMessage) error {
	var request api.Empty
	return decodeStrict(raw, &request)
}

// ParseDoctorHealth validates the frozen service result, including required
// false/zero fields and readiness consistency. It grants no local authority.
func ParseDoctorHealth(data []byte) (api.Health, error) {
	var result api.Health
	if err := decodeStrict(data, &result); err != nil {
		return api.Health{}, failure(api.CodeIntegrity, "doctor health JSON does not match the frozen result")
	}
	if result.Protocol != api.Protocol || result.Schema != api.SchemaVersion ||
		!versionPattern.MatchString(result.ServiceVersion) || !validDigest(result.ArtifactSHA256) {
		return api.Health{}, failure(api.CodeIntegrity, "doctor health metadata is invalid")
	}
	ready := len(result.Capabilities) > 0
	names := map[string]bool{}
	for _, check := range result.Capabilities {
		if check.Name == "" || names[check.Name] {
			return api.Health{}, failure(api.CodeIntegrity, "doctor capabilities are unnamed or duplicated")
		}
		names[check.Name] = true
		ready = ready && check.Available
	}
	if ready != result.Ready {
		return api.Health{}, failure(api.CodeIntegrity, "doctor readiness contradicts its capability results")
	}
	return result, nil
}
