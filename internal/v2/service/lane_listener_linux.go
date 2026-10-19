//go:build linux

package service

import (
	"context"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

func listenLane(ctx context.Context, binding api.InstalledBinding) (net.Listener, error) {
	if err := recoverLaneSocket(ctx, binding); err != nil {
		return nil, err
	}
	return listenMode(ctx, binding, 0666)
}
