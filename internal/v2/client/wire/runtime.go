package wire

import (
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only ResolvedRuntime's complete zero network view represents offline
// execution. It conveys no namespace or egress authority. Validate every field
// through the shared strict DTO reader before recognizing this exact absence;
// other network values retain ordinary ID, digest and timestamp validation.
func shapeOfflineNetwork(value any) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, Invalid("offline network view cannot be encoded")
	}
	var network api.NetworkLease
	if err := api.DecodeObject(data, &network); err != nil {
		return false, err
	}
	return network.ID == "" && network.GrantSetID == "" && network.NamespaceID == "" &&
		network.EndpointIDs != nil && len(network.EndpointIDs) == 0 && network.Generation == 0 &&
		network.PolicySHA256 == "" && network.ExpiresAt == "", nil
}
