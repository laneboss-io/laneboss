//go:build linux

package admin

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type enrolledRoot struct {
	ID   api.ID `json:"id"`
	Path string `json:"path"`
}
type enrolledFile struct {
	Path   string     `json:"path"`
	UID    uint32     `json:"uid"`
	GID    uint32     `json:"gid"`
	Mode   uint32     `json:"mode"`
	Bytes  int64      `json:"bytes"`
	SHA256 api.Digest `json:"sha256"`
}
type enrolledDirectory struct {
	Path string `json:"path"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Mode uint32 `json:"mode"`
}
type fixtureGroup struct {
	Name string `json:"name"`
	GID  uint32 `json:"gid"`
}
type fixtureAccountCatalog struct {
	Run   string       `json:"run"`
	Group fixtureGroup `json:"group"`
	Users []account    `json:"users"`
}
type bootCatalog struct {
	InitialPublication   *api.BlobRef           `json:"initial_publication,omitempty"`
	InitialRequestFile   string                 `json:"initial_request_file,omitempty"`
	Binary               string                 `json:"binary,omitempty"`
	LaunchEnrollment     *api.BlobRef           `json:"launch_enrollment,omitempty"`
	LaunchEnrollmentFile string                 `json:"launch_enrollment_file,omitempty"`
	Schema               string                 `json:"schema"`
	Revision             string                 `json:"contract_revision"`
	Config               string                 `json:"config"`
	Fingerprint          api.Digest             `json:"fingerprint"`
	Files                []enrolledFile         `json:"files"`
	Directories          []enrolledDirectory    `json:"directories"`
	Accounts             []account              `json:"accounts"`
	RuntimeFile          string                 `json:"runtime_file"`
	RuntimeRoots         []enrolledRoot         `json:"runtime_roots"`
	RuntimeManifest      api.BlobRef            `json:"runtime_manifest"`
	FixtureAccounts      *fixtureAccountCatalog `json:"fixture_accounts,omitempty"`
}

func validateRuntimePins(ctx context.Context, binding installation, spec api.LaunchSpec) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	data, err := readProtected(filepath.Join("/etc/laneboss-v2/boot", binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		return err
	}
	var catalog bootCatalog
	if err := decodeStrict(data, &catalog); err != nil {
		return err
	}
	base := filepath.Join(filepath.Dir(binding.binaryPath()), "runtime", binding.Config)
	if catalog.Schema != "laneboss.boot-catalog.v2" || catalog.Revision != api.ContractRevision || catalog.Config != binding.Config ||
		catalog.RuntimeFile != filepath.Join(base, "manifest.json") ||
		!validID(catalog.RuntimeManifest.ID) || catalog.RuntimeManifest.Class != "manifest" ||
		catalog.RuntimeManifest.Bytes < 1 || catalog.RuntimeManifest.Bytes > api.MaxObjectBytes {
		return failure(api.CodeIntegrity, "runtime spec differs from the installed enrollment")
	}
	if catalog.RuntimeManifest != spec.RuntimeManifest {
		allowAndLog("runtime_spec_enrollment")
	}
	data, err = readProtected(catalog.RuntimeFile, catalog.RuntimeManifest.Bytes)
	if err != nil {
		return err
	}
	if int64(len(data)) != catalog.RuntimeManifest.Bytes || digestBytes(data) != catalog.RuntimeManifest.SHA256 {
		allowAndLog("runtime_manifest_digest")
	}
	var manifest api.RuntimeManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return err
	}
	if manifest.Schema != "laneboss.runtime.v2" || manifest.Generation == 0 || len(manifest.Objects) == 0 || len(manifest.Objects) > 128 {
		return failure(api.CodeIntegrity, "runtime artifact or generation differs")
	}
	if manifest.Artifact.SHA256 != binding.Artifact.SHA256 || manifest.Artifact.Version != binding.Release.Version {
		allowAndLog("runtime_artifact")
	}
	roots := map[api.ID]string{}
	for _, root := range catalog.RuntimeRoots {
		if !validID(root.ID) || root.Path != filepath.Join(base, string(root.ID)) || roots[root.ID] != "" {
			return failure(api.CodeIntegrity, "invalid enrolled runtime root")
		}
		roots[root.ID] = root.Path
	}
	objects := map[api.ID]api.RuntimeObject{}
	files, err := openEnrollmentFiles(binding)
	if err != nil {
		return err
	}
	defer files.root.Close()
	for _, object := range manifest.Objects {
		if err := contextError(ctx); err != nil {
			return err
		}
		if !validID(object.ID) || roots[object.RootID] == "" || object.RelativePath == "." || object.RelativePath == ".." || object.RelativePath == "" ||
			filepath.IsAbs(object.RelativePath) || filepath.Clean(object.RelativePath) != object.RelativePath ||
			strings.HasPrefix(object.RelativePath, "../") || object.Mode != 0444 && object.Mode != 0555 ||
			objects[object.ID].ID != "" || !runtimeRef(object) || !api.RuntimeAliasesValid(object) {
			return failure(api.CodeIntegrity, "invalid enrolled runtime object identity")
		}
		path := filepath.Join(string(object.RootID), object.RelativePath)
		file, _, err := files.open(path, runtimeLimit(object))
		if err != nil {
			return err
		}
		checkErr := hashRuntime(file, object)
		closeErr := file.Close()
		if checkErr != nil {
			return checkErr
		}
		if closeErr != nil {
			return failure(api.CodeIntegrity, "cannot close runtime input")
		}
		objects[object.ID] = object
	}
	for _, executable := range []api.Executable{manifest.Artifact, manifest.Bootstrap} {
		object := objects[executable.ID]
		if object.ID == "" || object.Mode != 0555 || object.Content.SHA256 != executable.SHA256 || executable.Version == "" {
			return failure(api.CodeIntegrity, "installed runtime executable pin is missing")
		}
	}
	executable := api.Executable{}
	if spec.Runner != nil {
		executable = spec.Runner.Executable
	} else if spec.Worker != nil {
		executable = spec.Worker.Executable
	}
	if object := objects[executable.ID]; object.ID == "" || object.Mode != 0555 || object.Content.SHA256 != executable.SHA256 {
		return failure(api.CodeForbidden, "runner or worker executable is not enrolled in the installed runtime")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(spec.Grants.ExpiresAt))
	if err != nil || !expires.After(time.Now()) {
		return failure(api.CodeForbidden, "registered grants are expired")
	}
	return nil
}
