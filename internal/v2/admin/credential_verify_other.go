//go:build !linux

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) verifyCredentialNativePeer(context.Context, CredentialPeerVerification) (api.Empty, error) {
	return api.Empty{}, failure(api.CodeUnsupported, "native credential peers require Linux")
}
