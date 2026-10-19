package assembly

import (
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/isolation/mac"
	peer "laneboss.io/laneboss/internal/v2/peer/darwin"
)

func platformPeers(registry api.ContainmentRegistry) (api.PeerVerifier, error) {
	return peer.New(registry)
}

func platformLauncher(helper api.HelperControl, manifest api.BlobRef, backend string, controls api.LaunchControlSource) (api.Launcher, error) {
	if backend == "linux-bwrap-landlock" {
		return unavailablePlatform(backend, "lb-v2-linux"), nil
	}
	return mac.New(mac.Dependencies{Helper: helper, RuntimeManifest: manifest, Controls: controls})
}
