//go:build !linux

package identity

import (
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

func checkWorkerFiles(input, endpoint *os.File, ref api.BlobRef, expected api.InstalledBinding) error {
	return api.NotImplemented("lb-v2-identity", "native immutable worker descriptor verification for this platform")
}
