//go:build !linux

package client

import "laneboss.io/laneboss/internal/v2/api"

func inheritedCloseOnExec() error {
	return api.NotImplemented("lb-v2-client", "native child descriptor isolation on this platform")
}
