//go:build !linux

package dataworker

import (
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

func openNativeMaterializationRoots(api.WorkerPrincipal, api.StorageProjection) ([3]*os.Root, error) {
	return [3]*os.Root{}, api.NotImplemented("lb-v2-grants", "native materialization projected-root bridge on this platform")
}

func openNativeMaterializationCopies(api.WorkerPrincipal, api.StorageProjection) (map[api.ID]MaterializationCopyRoots, error) {
	return nil, api.NotImplemented("lb-v2-grants", "native materialization copy projections on this platform")
}
