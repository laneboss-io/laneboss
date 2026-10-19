//go:build laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"encoding/json"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
)

func dashboardPolicySource(installed Installation, actual api.ScopedJudge) (api.ScopedJudge, int64, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, 0, err
	}
	directory := filepath.Join(filepath.Dir(executable), "runtime", installed.Config)
	raw, err := readProtected(filepath.Join(directory, "manifest.json"), api.MaxFrameBytes)
	if err != nil {
		return nil, 0, err
	}
	if runDigest(raw) != installed.RuntimeManifest.SHA256 || int64(len(raw)) != installed.RuntimeManifest.Bytes {
		return nil, 0, installError("dashboard runtime pin differs")
	}
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(raw, &runtime); err != nil {
		return nil, 0, err
	}
	var selected *api.RuntimeObject
	for _, object := range runtime.Objects {
		if object.Role == "dashboard-fake-judge" {
			if selected != nil {
				return nil, 0, installError("dashboard fake judge enrollment is ambiguous")
			}
			value := object
			selected = &value
		}
	}
	if selected == nil {
		return actual, installed.PolicyMaxCostMicros, nil
	}
	rootsRaw, err := readProtected(filepath.Join(directory, "roots.json"), api.MaxFrameBytes)
	if err != nil {
		return nil, 0, err
	}
	var roots []runtimeRoot
	if json.Unmarshal(rootsRaw, &roots) != nil {
		return nil, 0, installError("dashboard runtime roots differ")
	}
	root := ""
	for _, candidate := range roots {
		if candidate.ID == selected.RootID {
			if root != "" {
				return nil, 0, installError("dashboard runtime root is ambiguous")
			}
			root = candidate.Path
		}
	}
	if !filepath.IsAbs(root) || !filepath.IsLocal(selected.RelativePath) || selected.RelativePath == "." || selected.Mode != 0444 {
		return nil, 0, installError("dashboard fake judge is not a protected runtime object")
	}
	body, err := readProtected(filepath.Join(root, selected.RelativePath), 4096)
	if err != nil {
		return nil, 0, err
	}
	source, err := dashboardJudgeObject(*selected, body)
	if err != nil {
		return nil, 0, err
	}
	return source, source.spec.MaxCostMicros, nil
}
