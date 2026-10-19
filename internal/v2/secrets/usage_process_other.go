//go:build !linux

package secrets

import (
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
	"os"
)

func snapshotUsageExecutable(*os.File, int64) (*os.File, error) {
	return nil, wire.Error(api.CodeUnsupported, "outside usage executable snapshot requires Linux")
}

func verifyUsageProcess(api.WorkerPrincipal) error {
	return wire.Error(api.CodeUnsupported, "outside usage command requires the installed Linux worker runtime")
}
