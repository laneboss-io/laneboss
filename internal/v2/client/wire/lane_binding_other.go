//go:build !linux

package wire

import "laneboss.io/laneboss/internal/v2/api"

func LaneEndpointBinding(api.InstalledBinding, api.LaunchSpec, api.HelperLease) (api.InstalledBinding, error) {
	return api.InstalledBinding{}, api.NotImplemented("lb-v2-admin", "native lane endpoint projection on this platform")
}

func NamespaceServiceIDs() (uint32, uint32, error) {
	return 0, 0, api.NotImplemented("lb-v2-admin", "native namespace server identity on this platform")
}
