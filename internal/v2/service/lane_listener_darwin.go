//go:build darwin

package service

import (
	"context"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

func listenLane(context.Context, api.InstalledBinding) (net.Listener, error) {
	return nil, api.NotImplemented("lb-v2-admin", "native Darwin lane endpoint projection")
}
