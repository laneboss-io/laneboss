//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package admin

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
)

func usageFixtureRuntime(manifest api.RuntimeManifest, mounts []*nativeMount, executable api.Executable, config string) (bool, error) {
	for _, object := range manifest.Objects {
		if object.Role != "serve-fixture-config" {
			continue
		}
		for _, mount := range mounts {
			if mount.target != nativeRuntimeTarget(object) {
				continue
			}
			reader, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(mount.file.Fd())))
			if err != nil {
				return false, err
			}
			data, err := io.ReadAll(io.NewSectionReader(reader, 0, object.Content.Bytes+1))
			closeErr := reader.Close()
			if err != nil {
				return false, err
			}
			if closeErr != nil {
				return false, closeErr
			}
			if int64(len(data)) != object.Content.Bytes || digestBytes(data) != object.Content.SHA256 {
				return false, failure(api.CodeIntegrity, "declared usage fixture bytes changed")
			}
			var declared struct {
				Schema        string         `json:"schema"`
				Config        string         `json:"config"`
				VendorStoodIn bool           `json:"vendor_stood_in"`
				Executable    api.Executable `json:"executable"`
			}
			if json.Unmarshal(data, &declared) != nil {
				return false, failure(api.CodeIntegrity, "declared usage fixture is malformed")
			}
			return declared.Schema == "laneboss.serve-agent.v1" && declared.Config == config && declared.VendorStoodIn && declared.Executable == executable, nil
		}
	}
	return false, nil
}

// A declared fixture's outside provider uses the real service UID and a held
// socket inode. The model cannot select a host path, peer or restore method.
func (m *leaseManager) watchdogProviderMount(manifest api.RuntimeManifest, mounts []*nativeMount) (*nativeMount, error) {
	declared := false
	for _, object := range manifest.Objects {
		declared = declared || object.ID == "wd-run" && object.Role == "watchdog-fixture" && object.Mode == 0444
	}
	if !declared {
		return nil, nil
	}
	service, err := workerServiceBinding(m.binding)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(filepath.Dir(service.Socket), "workers")
	if _, err := os.Lstat(filepath.Join(base, "wd-provider.sock")); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	result, err := pinWorkerSocket(base, m.binding.Service, "wd-provider")
	if err != nil {
		return nil, err
	}
	result.target = "/runtime/wd-provider.sock"
	return result, nil
}
