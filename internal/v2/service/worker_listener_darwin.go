//go:build darwin

package service

import (
	"context"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

func listenWorker(context.Context, api.InstalledBinding) (net.Listener, error) {
	return nil, serviceError(api.CodePrerequisite, "native Darwin worker writer evidence is unavailable")
}
