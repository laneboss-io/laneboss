//go:build darwin

package service

import (
	"context"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

func listenInstalled(context.Context, api.InstalledBinding) (net.Listener, error) {
	return nil, serviceError(api.CodePrerequisite, "native Darwin per-message writer evidence is unavailable")
}
func listenAdministrator(context.Context, api.InstalledBinding) (net.Listener, error) {
	return nil, api.NotImplemented("lb-v2-admin", "administrator native Darwin endpoint")
}
