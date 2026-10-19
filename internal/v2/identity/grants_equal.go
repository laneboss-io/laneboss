package identity

import (
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
)

// A store projection may represent an empty repeated field as nil. Compare all
// actual grant facts, including digest/generations and nonempty slice order,
// without making that representation an authority difference. Never rewrite
// either stored projection or recompute the producer's authoritative digest.
func equalLaunchGrants(left, right api.GrantSet) bool {
	return reflect.DeepEqual(normalizeGrantSlices(left), normalizeGrantSlices(right))
}

func normalizeGrantSlices(grants api.GrantSet) api.GrantSet {
	grants.Resources = slices.Clone(emptyGrantSlice(grants.Resources))
	for i := range grants.Resources {
		resource := &grants.Resources[i]
		resource.Regions = emptyGrantSlice(resource.Regions)
		resource.ImageIDs = emptyGrantSlice(resource.ImageIDs)
		resource.MachineTypes = emptyGrantSlice(resource.MachineTypes)
	}
	grants.Data = emptyGrantSlice(grants.Data)
	grants.Secrets = emptyGrantSlice(grants.Secrets)
	grants.Profiles = emptyGrantSlice(grants.Profiles)
	grants.Network = emptyGrantSlice(grants.Network)
	grants.Channels = emptyGrantSlice(grants.Channels)
	return grants
}

func emptyGrantSlice[T any](value []T) []T {
	if len(value) == 0 {
		return nil
	}
	return value
}
