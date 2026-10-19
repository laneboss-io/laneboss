package secrets

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

// Shared with the root helper without coupling either owning component to the
// other's service implementation (the store also imports admin).
type APIKeyScanResult = rscan.APIKeyScanResult
type APIKeyReleaseScanner = rscan.APIKeyReleaseScanner
type APIKeyReleaseScanFunc = rscan.APIKeyReleaseScanFunc
type APIKeyScanInputs = rscan.APIKeyScanInputs

var reusePlaces = rscan.APIKeyScanPlaces()

func unreadableAPIKeyScan() APIKeyScanResult { return rscan.UnreadableAPIKeyScan() }

func ScanAPIKeyReleaseInputs(ctx context.Context, material api.SecretMaterial, inputs APIKeyScanInputs) APIKeyScanResult {
	return rscan.ScanAPIKeyReleaseInputs(ctx, material, inputs)
}
