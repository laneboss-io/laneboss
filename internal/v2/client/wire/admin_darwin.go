//go:build darwin

package wire

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"net"
)

func VerifyAdministrator(context.Context, api.AdminEnrollmentEndpoint, api.ConnectionContext, api.FrameContext) error {
	return api.NotImplemented("lb-v2-admin", "administrator helper audit-token and mapped-artifact verification")
}
func NewAdministratorPeer(context.Context, *net.UnixConn) (api.VerifiedPeer, error) {
	return nil, api.NotImplemented("lb-v2-admin", "administrator native audit-token peer")
}
