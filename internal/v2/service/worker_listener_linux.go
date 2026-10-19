//go:build linux

package service

import (
	"context"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

// The socket is reachable only through a helper-pinned namespace projection;
// its host parent is 0700. Native identity is still mandatory for every frame.
func listenWorker(ctx context.Context, binding api.InstalledBinding) (net.Listener, error) {
	return listenMode(ctx, binding, 0666)
}
