//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// laneEndpointMounts supplies the three fixed lane-side projections. The gate
// owner appends these to its existing mount inventory before startNativeGate;
// it retains only the binding and socket as inherited descriptors. This helper
// grants no new control RPC and never accepts a caller-selected host path.
func (m *leaseManager) laneEndpointMounts(ctx context.Context, record leaseRecord) (mounts []*nativeMount, resultErr error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if record.Spec == nil {
		return nil, failure(api.CodeIntegrity, "lane endpoint requires its retained full spec")
	}
	installed, err := workerServiceBinding(m.binding)
	if err != nil {
		return nil, err
	}
	binding, err := wire.LaneEndpointBinding(installed, record.Spec.Handoff.Spec, record.Lease)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			for _, mount := range mounts {
				resultErr = errors.Join(resultErr, mount.file.Close())
			}
			mounts = nil
		}
	}()
	sealed, err := sealedBootstrap(binding)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, &nativeMount{file: sealed, target: wire.LaneBindingPath, sealed: true})
	if err := sealed.Chmod(0444); err != nil {
		return mounts, err
	}
	input, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(sealed.Fd())))
	if err != nil {
		return mounts, err
	}
	mounts[0].file = input
	if err := sealed.Close(); err != nil {
		return mounts, err
	}
	socket, err := pinWorkerSocket(filepath.Join(filepath.Dir(installed.Socket), "lanes"), m.binding.Service, binding.LaunchID)
	if err != nil {
		return mounts, err
	}
	socket.target = wire.LaneSocketPath
	mounts = append(mounts, socket)
	client, err := pinLaneClient(m.binding.binaryPath(), m.binding.Artifact)
	if err != nil {
		return mounts, err
	}
	mounts = append(mounts, client)
	return mounts, nil
}

func pinLaneClient(path string, artifact api.ReleaseArtifact) (_ *nativeMount, resultErr error) {
	if err := protectedPath(path, false); err != nil {
		return nil, err
	}
	client, err := pinNativeMount(path, wire.LaneClientPath, false, false, true, 0, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, client.file.Close())
		}
	}()
	reader, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(client.file.Fd())))
	if err != nil {
		return nil, err
	}
	if err := errors.Join(verifyExecutableFile(reader, artifact), reader.Close()); err != nil {
		return nil, err
	}
	return client, nil
}

func checkLaneMountTargets(mounts []*nativeMount) error {
	for _, mount := range mounts {
		if mount == nil || !filepath.IsAbs(mount.target) || filepath.Clean(mount.target) != mount.target {
			return failure(api.CodeIntegrity, "lane projection has an invalid existing mount")
		}
		for _, target := range []string{wire.LaneBindingPath, wire.LaneSocketPath, wire.LaneClientPath} {
			if mount.target == target || mount.target == "/" || strings.HasPrefix(mount.target, target+"/") || strings.HasPrefix(target, mount.target+"/") {
				return failure(api.CodeIntegrity, "lane projection collides with an existing mount target")
			}
		}
	}
	return nil
}
