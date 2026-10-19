//go:build !linux

package wire

import "laneboss.io/laneboss/internal/v2/api"

func ReadReviewInput(api.BlobRef) ([]byte, error) {
	return nil, api.NotImplemented("lb-v2-grants", "native inherited review worker input on this platform")
}
