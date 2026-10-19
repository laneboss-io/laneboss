//go:build !linux

package wire

import "laneboss.io/laneboss/internal/v2/api"

func readProjectedBinding(string, string, string) (api.InstalledBinding, bool, error) {
	return api.InstalledBinding{}, false, nil
}

func validateRegularProjection(api.InstalledBinding) error { return nil }

func ReadWorkerInput(api.BlobRef) ([]byte, error) {
	return nil, api.NotImplemented("lb-v2-grants", "native inherited worker input on this platform")
}
