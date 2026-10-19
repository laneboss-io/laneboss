//go:build !linux

package linux

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func probeHost(context.Context) (api.IsolationCapabilities, error) {
	return api.IsolationCapabilities{Backend: backendName},
		failure(api.CodeUnsupported, "Linux isolation requires a Linux kernel")
}

func BootstrapMain() (bool, error) { return false, nil }
