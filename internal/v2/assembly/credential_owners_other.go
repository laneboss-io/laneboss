//go:build !linux

package assembly

import (
	"context"
	"io"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/service"
)

func installedCredentialPeers(peers api.PeerVerifier, _ *admin.Service, _ Installation) api.PeerVerifier {
	return peers
}
func startInstalledCredentialOwners(context.Context, Installation, *admin.Service, *identity.Service, api.StateStore, *grants.Service, *service.Server) (io.Closer, error) {
	return nil, api.NotImplemented("lb-v2-admin", "installed native credential owners")
}
func RunCredentialBroker(context.Context, string, string, string) error {
	return api.NotImplemented("lb-v2-admin", "installed native credential owner")
}
