package assembly

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func runtimeFixture(t *testing.T) (api.RuntimeManifest, Installation, map[api.ID][]byte) {
	t.Helper()
	values := make(map[api.ID][]byte)
	object := func(id api.ID, role string, mode uint32, data []byte) api.RuntimeObject {
		sum := sha256.Sum256(data)
		values[id] = data
		return api.RuntimeObject{ID: id, Role: role, RootID: "runtime", RelativePath: string(id), Mode: mode,
			Content: api.BlobRef{ID: id, Class: "artifact", SHA256: api.Digest(hex.EncodeToString(sum[:])), Bytes: int64(len(data))}}
	}
	clientBytes, agentBytes, nonce := make([]byte, 32), make([]byte, 39), make([]byte, 16)
	for _, data := range [][]byte{clientBytes, agentBytes, nonce} {
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
	}
	client := object("client", "bootstrap", 0555, clientBytes)
	agent := object("agent", "serve-fixture-agent", 0555, agentBytes)
	task := object("task", "serve-fixture-task", 0444, []byte("fixture task"))
	declared := fixtureEnrollment{Schema: "laneboss.serve-agent.v1", Program: "laneboss-serve-fixture",
		Version: "1.0.0", VendorStoodIn: true, Driver: api.DriverCodex, Config: "fixture-case",
		Drivers:   []api.Driver{api.DriverClaudock, api.DriverCodex},
		Challenge: hex.EncodeToString(nonce), Executable: api.Executable{ID: agent.ID, SHA256: agent.Content.SHA256, Version: "1.0.0"},
		Client:     api.Executable{ID: client.ID, SHA256: client.Content.SHA256, Version: "2.0.0-dev.1"},
		ClientPath: "/run/laneboss/client", BindingPath: "/run/laneboss/binding.json", TaskObject: task.ID, Output: "/home/lane/serve-state"}
	metadata, err := json.Marshal(declared)
	if err != nil {
		t.Fatal(err)
	}
	config := object("descriptor", "serve-fixture-config", 0444, metadata)
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact: declared.Client, Bootstrap: declared.Client,
		Objects: []api.RuntimeObject{client, agent, task, config}, Bindings: []api.InstalledBinding{}}
	return runtime, Installation{Config: declared.Config, ArtifactSHA256: client.Content.SHA256}, values
}

func TestFixtureEnrollmentPinsActualBytes(t *testing.T) {
	runtime, installed, values := runtimeFixture(t)
	reads := make(map[api.ID]int)
	declared, err := fixtureFromRuntime(runtime, installed, func(object api.RuntimeObject) ([]byte, error) {
		reads[object.ID]++
		return values[object.ID], nil
	})
	if err != nil || declared == nil || !declared.VendorStoodIn || declared.Config != installed.Config ||
		declared.Executable.SHA256 != runtime.Objects[1].Content.SHA256 {
		t.Fatal("enrolled fixture was not resolved", err)
	}
	for id := range values {
		if reads[id] != 1 {
			t.Fatal("runtime object was not read once")
		}
	}
}

func TestFixtureEnrollmentRejectsDrift(t *testing.T) {
	for _, kind := range []string{"bytes", "mode", "missing", "duplicate", "config", "release", "output"} {
		t.Run(kind, func(t *testing.T) {
			runtime, installed, values := runtimeFixture(t)
			switch kind {
			case "bytes":
				values[runtime.Objects[1].ID][0] ^= 1
			case "mode":
				runtime.Objects[1].Mode = 0755
			case "missing":
				runtime.Objects = runtime.Objects[:3]
			case "duplicate":
				runtime.Objects = append(runtime.Objects, runtime.Objects[1])
			case "config":
				installed.Config = "different-case"
			case "release":
				installed.ArtifactSHA256 = runtime.Objects[1].Content.SHA256
			case "output":
				object := &runtime.Objects[3]
				var declared fixtureEnrollment
				if err := json.Unmarshal(values[object.ID], &declared); err != nil {
					t.Fatal(err)
				}
				declared.Output = "serve-state"
				raw, err := json.Marshal(declared)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(raw)
				object.Content.SHA256, object.Content.Bytes = api.Digest(hex.EncodeToString(sum[:])), int64(len(raw))
				values[object.ID] = raw
			}
			declared, err := fixtureFromRuntime(runtime, installed, func(object api.RuntimeObject) ([]byte, error) {
				return values[object.ID], nil
			})
			if err == nil || declared != nil {
				t.Fatal("drifted fixture was accepted")
			}
		})
	}
}

func TestFixtureReadErrorIsKept(t *testing.T) {
	runtime, installed, _ := runtimeFixture(t)
	sentinel := errors.New("runtime input read failed")
	declared, err := fixtureFromRuntime(runtime, installed, func(api.RuntimeObject) ([]byte, error) { return nil, sentinel })
	if !errors.Is(err, sentinel) || declared != nil {
		t.Fatal("fixture read error was hidden")
	}
}
