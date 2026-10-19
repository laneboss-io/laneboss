//go:build !linux

package wire

import "laneboss.io/laneboss/internal/v2/api"

func RetainLaneDescriptors(string, string) ([]InheritedFile, error) {
	return nil, api.NotImplemented("lb-v2-admin", "native child lane descriptor handoff on this platform")
}
