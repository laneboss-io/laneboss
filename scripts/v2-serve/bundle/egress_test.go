package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/policy"
)

// Assemble shipped source bytes and real test-binary pins, then inspect the
// hashed publication. This unit test exercises enrollment JSON, not execution.
func TestEgressEnrollmentJSON(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	executable := api.Executable{ID: "bundle-test", SHA256: digest(binary), Version: identity.Version}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable,
		Bootstrap: executable, Objects: []api.RuntimeObject{{ID: executable.ID, Role: "bootstrap", RootID: "assets",
			RelativePath: "laneboss", Mode: 0555, Content: ref(executable.ID, "artifact", binary)},
			{ID: "bundle-agent", Role: "serve-fixture-agent", RootID: "assets", RelativePath: "agent", Mode: 0555,
				Content: ref("bundle-agent", "artifact", binary)}}, Bindings: []api.InstalledBinding{}}
	runtimeRaw, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("..", "..", "..")
	var sources []sourceInput
	for _, row := range []struct{ id, relative, logical, kind string }{
		{"org-prompt", "org/default.md", ".laneboss/shared/templates/default.md", "prompt"},
		{"org-drivers", "org/drivers.toml", ".laneboss/shared/templates/drivers.toml", "drivers"},
		{"workflow", "org/workflow.toml", ".laneboss/shared/workflow.toml", "policy"},
		{"l5-prompt", "roles/L5/supervisor.md", ".laneboss/L5/roles/supervisor.md", "prompt"},
		{"l5-drivers", "roles/L5/supervisor.toml", ".laneboss/L5/roles/supervisor.toml", "drivers"},
	} {
		data, err := os.ReadFile(filepath.Join(root, "templates", "v2", row.relative))
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, sourceInput{ID: api.ID(row.id), Path: row.logical, Kind: row.kind, Data: data})
	}
	project, err := os.ReadFile(filepath.Join(root, "scripts", "v2-serve", "fixtures", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	in := input{Config: "egress-json", Runtime: ref("runtime", "manifest", runtimeRaw), RuntimeRaw: runtimeRaw,
		Sources: sources, Project: project, Task: project, Model: "claude-sonnet-5-5",
		ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)),
		Judge:     policy.DefaultJudgeConfig(digest(binary), digest(project), 256)}
	var prior api.BlobRef
	for _, enabled := range []bool{false, true} {
		in.Egress = enabled
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var wire input
		if err := api.DecodeObject(raw, &wire); err != nil {
			t.Fatal("assembler input JSON:", err)
		}
		out, err := assemble(wire)
		if err != nil {
			t.Fatal("assemble shipped sources:", err)
		}
		objects := map[api.ID]document{}
		for _, doc := range out.Documents {
			if doc.Ref.SHA256 != digest(doc.Data) || doc.Ref.Bytes != int64(len(doc.Data)) {
				t.Fatal("enrollment object hash differs from its actual JSON")
			}
			objects[doc.Ref.ID] = doc
		}
		var launch api.LaunchEnrollment
		if err := api.DecodeObject(objects[out.Initial.Launch.ID].Data, &launch); err != nil {
			t.Fatal("enrollment JSON:", err)
		}
		if err := api.ValidateLaunchEnrollment(launch, in.Config, in.Runtime); err != nil {
			t.Fatal("invalid published launch enrollment:", err)
		}
		var approved api.RootGrantManifest
		if err := api.DecodeObject(objects[out.Initial.Profiles.ID].Data, &approved); err != nil {
			t.Fatal("root capability JSON:", err)
		}
		if err := manifest.Root(approved, time.Now()); err != nil {
			t.Fatal("invalid root capability:", err)
		}
		if out.Root.Manifest != out.Initial.Profiles || out.Ref != ref(out.Ref.ID, "manifest", out.Raw) {
			t.Fatal("endpoint or approved grants escaped publication hashing")
		}
		if !enabled {
			if len(launch.Network) != 0 || len(approved.Network) != 0 {
				t.Fatal("default bundle silently enabled network")
			}
			prior = out.Initial.Launch
			t.Log("RED control: default enrollment cannot authorize the API; network is absent")
			continue
		}
		if len(launch.Network) != 1 || len(approved.Network) != 1 || prior == out.Initial.Launch {
			t.Fatal("egress option did not change the hashed endpoint and approved grant")
		}
		endpoint, grant := launch.Network[0], approved.Network[0]
		if endpoint.ID != "anthropic-api" || endpoint.Host != "api.anthropic.com" || endpoint.Protocol != "tcp" || endpoint.Port != 443 ||
			grant.EndpointID != endpoint.ID || grant.Mode != "internet" || grant.ExpiresAt != in.ExpiresAt || grant.Delegate || grant.ID != "" || grant.ParentGrantID != "" {
			t.Fatal("egress option widened scope or invented an issued grant")
		}
		for _, lane := range out.Lanes {
			if len(lane.Grants.Network) != 0 {
				t.Fatal("unissued network member appeared before grants.root")
			}
		}
		launch.Network[0].Host = "example.com"
		if err := api.ValidateLaunchEnrollment(launch, in.Config, in.Runtime); err == nil {
			t.Fatal("foreign public endpoint passed administrator enrollment validation")
		}
		t.Log("GREEN: exact API endpoint and unissued root capability are hashed into the opt-in bundle")
	}
}
