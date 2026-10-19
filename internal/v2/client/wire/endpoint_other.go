//go:build !linux

package wire

import "laneboss.io/laneboss/internal/v2/api"

func PinEndpoint(_ string, binding api.InstalledBinding) (*Endpoint, error) {
	return &Endpoint{path: binding.Socket}, nil
}
