package assembly

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// A fixture enrollment identifies pinned runtime bytes, never an actor, proof,
// ticket, launch permit, credential lease or successful execution.
type fixtureEnrollment struct {
	Schema         string         `json:"schema"`
	Program        string         `json:"program"`
	Version        string         `json:"version"`
	VendorStoodIn  bool           `json:"vendor_stood_in"`
	CanaryAPIKey   bool           `json:"canary_api_key,omitempty"`
	Driver         api.Driver     `json:"driver"`
	Drivers        []api.Driver   `json:"drivers,omitempty"`
	Mode           string         `json:"mode,omitempty"`
	Config         string         `json:"config"`
	Challenge      string         `json:"challenge"`
	Executable     api.Executable `json:"executable"`
	Client         api.Executable `json:"client"`
	ClientPath     string         `json:"client_path"`
	BindingPath    string         `json:"binding_path"`
	TaskObject     api.ID         `json:"task_object"`
	Output         string         `json:"output"`
	executablePath string         `json:"-"`
}

type runtimeRoot struct {
	ID   api.ID `json:"id"`
	Path string `json:"path"`
}

var fixtureChallenge = regexp.MustCompile(`^[a-f0-9]{32}$`)
var fixtureObjectID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func loadFixture(installed Installation) (*fixtureEnrollment, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, installError("fixture release cannot resolve")
	}
	directory := filepath.Join(filepath.Dir(executable), "runtime", installed.Config)
	manifest, err := readProtected(filepath.Join(directory, "manifest.json"), api.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(manifest)
	if installed.RuntimeManifest.SHA256 != api.Digest(hex.EncodeToString(sum[:])) ||
		installed.RuntimeManifest.Bytes != int64(len(manifest)) || installed.RuntimeManifest.Class != "manifest" {
		return nil, installError("fixture runtime manifest pin differs")
	}
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(manifest, &runtime); err != nil {
		return nil, err
	}
	rootsBytes, err := readProtected(filepath.Join(directory, "roots.json"), api.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	var roots []runtimeRoot
	// The administrator roots inventory is a JSON array, not an RPC body.
	value, err := wire.Parse(rootsBytes)
	if err != nil {
		return nil, err
	}
	array, ok := value.([]any)
	if !ok {
		return nil, installError("fixture roots must be an array")
	}
	for _, item := range array {
		data, err := json.Marshal(item)
		if err != nil {
			return nil, installError("fixture root cannot decode")
		}
		var root runtimeRoot
		if err := api.DecodeObject(data, &root); err != nil {
			return nil, err
		}
		roots = append(roots, root)
	}
	byID := make(map[api.ID]string)
	for _, root := range roots {
		if root.ID == "" || byID[root.ID] != "" || !filepath.IsAbs(root.Path) || filepath.Clean(root.Path) != root.Path {
			return nil, installError("fixture roots inventory differs")
		}
		if err := protectedParents(root.Path, 0); err != nil {
			return nil, err
		}
		byID[root.ID] = root.Path
	}
	var executablePath string
	declared, err := fixtureFromRuntime(runtime, installed, func(object api.RuntimeObject) ([]byte, error) {
		root := byID[object.RootID]
		if root == "" || !filepath.IsLocal(object.RelativePath) || object.RelativePath == "." ||
			filepath.Clean(object.RelativePath) != object.RelativePath {
			return nil, installError("fixture object root differs")
		}
		path := filepath.Join(root, object.RelativePath)
		if object.Role == "serve-fixture-agent" {
			// The helper verifies the protected host bytes above, then exposes
			// this basename-only runtime object at its fixed namespace path.
			executablePath = filepath.Join("/runtime", string(object.ID))
		}
		data, err := readProtected(path, api.MaxObjectBytes)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil || uint32(info.Mode().Perm()) != object.Mode {
			return nil, installError("fixture runtime mode differs")
		}
		return data, nil
	})
	if err != nil {
		return nil, err
	}
	if declared != nil {
		declared.executablePath = executablePath
	}
	return declared, nil
}

func fixtureFromRuntime(runtime api.RuntimeManifest, installed Installation, read func(api.RuntimeObject) ([]byte, error)) (*fixtureEnrollment, error) {
	if runtime.Schema != "laneboss.runtime.v2" || runtime.Generation == 0 ||
		runtime.Artifact.SHA256 != installed.ArtifactSHA256 {
		return nil, installError("fixture runtime release differs")
	}
	objects := make(map[api.ID]api.RuntimeObject)
	var config, agent, task api.RuntimeObject
	for _, object := range runtime.Objects {
		if !fixtureObjectID.MatchString(string(object.ID)) || objects[object.ID].ID != "" {
			return nil, installError("fixture runtime object repeats")
		}
		objects[object.ID] = object
		switch object.Role {
		case "serve-fixture-config":
			if config.ID != "" {
				return nil, installError("fixture configuration repeats")
			}
			config = object
		case "serve-fixture-agent":
			if agent.ID != "" {
				return nil, installError("fixture executable repeats")
			}
			agent = object
		case "serve-fixture-task":
			if task.ID != "" {
				return nil, installError("fixture task repeats")
			}
			task = object
		}
	}
	if config.ID == "" && agent.ID == "" && task.ID == "" {
		return nil, nil
	}
	if config.ID == "" || agent.ID == "" || task.ID == "" || config.Mode != 0444 || task.Mode != 0444 || agent.Mode != 0555 ||
		agent.RelativePath == "" || agent.RelativePath == "." || filepath.Base(agent.RelativePath) != agent.RelativePath {
		return nil, installError("fixture enrollment is incomplete")
	}
	load := func(object api.RuntimeObject) ([]byte, error) {
		data, err := read(object)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if object.Content.Class != "artifact" || object.Content.Bytes != int64(len(data)) ||
			object.Content.SHA256 != api.Digest(hex.EncodeToString(sum[:])) {
			return nil, installError("fixture object byte pin differs")
		}
		return data, nil
	}
	data, err := load(config)
	if err != nil {
		return nil, err
	}
	var declared fixtureEnrollment
	if err := api.DecodeObject(data, &declared); err != nil {
		return nil, err
	}
	if declared.Mode != "" && declared.Mode != "state" && declared.Mode != "lifecycle" {
		return nil, installError("unknown fixture mode")
	}
	seenDrivers := map[api.Driver]bool{}
	for _, driver := range declared.Drivers {
		if driver != api.DriverCodex && driver != api.DriverClaudock || seenDrivers[driver] {
			return nil, installError("invalid fixture drivers")
		}
		seenDrivers[driver] = true
	}
	if len(declared.Drivers) > 0 && !seenDrivers[declared.Driver] {
		return nil, installError("fixture default driver is not enrolled")
	}
	client := objects[declared.Client.ID]
	if declared.Schema != "laneboss.serve-agent.v1" || declared.Program != "laneboss-serve-fixture" ||
		!declared.VendorStoodIn || declared.Version == "" || declared.Driver != api.DriverCodex ||
		declared.Config != installed.Config || !fixtureChallenge.MatchString(declared.Challenge) ||
		declared.Executable.ID != agent.ID || declared.Executable.SHA256 != agent.Content.SHA256 ||
		declared.Executable.Version != declared.Version || declared.TaskObject != task.ID ||
		client.ID == "" || client.Mode != 0555 || declared.Client.Version != runtime.Artifact.Version ||
		declared.Client.SHA256 != installed.ArtifactSHA256 ||
		declared.Client.SHA256 != client.Content.SHA256 || declared.Output != "/home/lane/serve-state" ||
		declared.ClientPath != "/run/laneboss/client" || declared.BindingPath != "/run/laneboss/binding.json" {
		return nil, installError("fixture descriptor differs")
	}
	for _, object := range []api.RuntimeObject{agent, client, task} {
		if _, err := load(object); err != nil {
			return nil, err
		}
	}
	return &declared, nil
}
