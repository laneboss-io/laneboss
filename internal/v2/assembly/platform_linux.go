package assembly

import (
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/isolation/linux"
	peer "laneboss.io/laneboss/internal/v2/peer/linux"
)

func platformPeers(registry api.ContainmentRegistry) (api.PeerVerifier, error) {
	return peer.New(registry)
}

func platformLauncher(helper api.HelperControl, manifest api.BlobRef, backend string, controls api.LaunchControlSource) (api.Launcher, error) {
	if backend == "darwin-seatbelt" {
		return unavailablePlatform(backend, "lb-v2-darwin"), nil
	}
	return linux.New(linux.Dependencies{Helper: helper, RuntimeManifest: manifest, Controls: controls})
}
