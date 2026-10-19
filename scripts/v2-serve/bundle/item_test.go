package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
)

// These are assembler units. No declaration below attests an installed actor.
func itemInput(t *testing.T) input {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	executable := api.Executable{ID: "item-test", SHA256: digest(raw), Version: identity.Version}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact: executable, Bootstrap: executable, Bindings: []api.InstalledBinding{},
		Objects: []api.RuntimeObject{
			{ID: executable.ID, Role: "bootstrap", RootID: "assets", RelativePath: "client", Mode: 0555,
				Content: ref(executable.ID, "artifact", raw)},
			{ID: "item-agent", Role: "serve-fixture-agent", RootID: "assets", RelativePath: "agent", Mode: 0555,
				Content: ref("item-agent", "artifact", raw)},
		}}
	runtimeRaw, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	project, err := os.ReadFile(filepath.Join("..", "fixtures", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	in := input{Config: "item-json", Runtime: ref("runtime", "manifest", runtimeRaw), RuntimeRaw: runtimeRaw,
		Project: project, Task: project, Model: "1.0.0",
		ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)),
		Judge:     policy.DefaultJudgeConfig(digest(raw), digest(project), 256),
		Contexts:  []api.RoleContext{{Level: 3, Role: "executor"}}}
	for _, row := range []struct{ id, relative, logical, kind string }{
		{"org-prompt", "org/default.md", ".laneboss/shared/templates/default.md", "prompt"},
		{"org-drivers", "org/drivers.toml", ".laneboss/shared/templates/drivers.toml", "drivers"},
		{"workflow", "org/workflow.toml", ".laneboss/shared/workflow.toml", "policy"},
		{"l5-prompt", "roles/L5/supervisor.md", ".laneboss/L5/roles/supervisor.md", "prompt"},
		{"l5-drivers", "roles/L5/supervisor.toml", ".laneboss/L5/roles/supervisor.toml", "drivers"},
		{"l3-prompt", "roles/L3/executor.md", ".laneboss/L3/roles/executor.md", "prompt"},
		{"l3-drivers", "roles/L3/executor.toml", ".laneboss/L3/roles/executor.toml", "drivers"},
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", row.relative))
		if err != nil {
			t.Fatal(err)
		}
		in.Sources = append(in.Sources, sourceInput{ID: api.ID(row.id), Path: row.logical, Kind: row.kind, Data: data})
	}
	content := ref("item-content", "artifact", project)
	treeRaw, err := json.Marshal(api.ObjectManifest{Schema: "laneboss.objects.v2",
		Entries: []api.ObjectEntry{{Path: "input.txt", Kind: "file", Mode: 0444, Content: &content}}})
	if err != nil {
		t.Fatal(err)
	}
	tree := ref("item-tree", "manifest", treeRaw)
	in.Documents = []document{{content, project}, {tree, treeRaw}}
	in.Projects = []api.ProjectEnrollment{{ID: "item-project-enrollment", Generation: 1,
		ProjectID: "item-project", Object: tree, Base: string(tree.SHA256), HistoryScope: "tree"}}
	in.RootGrants = &api.RootGrantManifest{Schema: "laneboss.root-grants.v2",
		Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Resources: []api.ResourceGrant{{SourceHandle: "item-resource", Provider: "gcp",
			Regions: []string{"region-a"}, ImageIDs: []string{"image-a"}, MachineTypes: []string{"small"},
			MaxActive: 1, Delegate: true, ExpiresAt: in.ExpiresAt}},
		Data: []api.DataGrant{{SourceObjectID: tree.ID, SourceSHA256: tree.SHA256, RelativePath: ".",
			Access: "ro", Delivery: "copy", Destination: "/data/item", Delegate: true,
			ExpiresAt: in.ExpiresAt, HistoryScope: "snapshot"}}, Profiles: []api.ProfileGrant{}}
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		in.RootGrants.Profiles = append(in.RootGrants.Profiles, api.ProfileGrant{ProfileID: api.ID("serve-profile-" + string(driver)),
			Driver: driver, Provider: "serve-fixture", Delegate: true, ExpiresAt: in.ExpiresAt})
	}
	return in
}

func TestItemBundle(t *testing.T) {
	t.Run("shared-role", func(t *testing.T) {
		in := itemInput(t)
		in.Contexts = append(in.Contexts, api.RoleContext{Level: 6, Role: "supervisor"})
		for _, suffix := range []string{"md", "toml"} {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", "roles", "L6", "supervisor."+suffix))
			if err != nil {
				t.Fatal(err)
			}
			kind := "prompt"
			if suffix == "toml" {
				kind = "drivers"
			}
			in.Sources = append(in.Sources, sourceInput{ID: api.ID("l6-" + kind),
				Path: ".laneboss/L6/roles/supervisor." + suffix, Kind: kind, Data: data})
		}
		out, err := assemble(in)
		if err != nil {
			t.Fatal("shared role scope is invalid", err)
		}
		var p api.EffectivePolicy
		for _, doc := range out.Documents {
			if doc.Ref == out.Initial.Policy {
				if err := api.DecodeObject(doc.Data, &p); err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(p.Rules) == 0 || !slices.Contains(p.Rules[0].Scope.Levels, 6) || len(p.Rules[0].Scope.Roles) != 2 {
			t.Fatal("shared role scope lost an enabled level")
		}
	})
	t.Run("document-pin", func(t *testing.T) {
		in := itemInput(t)
		in.Documents[0].Data = append([]byte("changed input\n"), in.Documents[0].Data...)
		if _, err := assemble(in); err == nil {
			t.Fatal("document pin was not enforced")
		}
	})
	t.Run("invalid-inputs", func(t *testing.T) {
		for _, field := range []string{"role", "resource", "budget", "duplicate"} {
			in := itemInput(t)
			switch field {
			case "role":
				in.Sources = in.Sources[:len(in.Sources)-1]
			case "resource":
				in.RootGrants.Resources[0].MaxActive = 0
			case "budget":
				in.Budget = &api.Budget{Currency: "USD"}
			case "duplicate":
				in.Documents = append(in.Documents, in.Documents[0])
			}
			if _, err := assemble(in); err == nil {
				t.Fatal("invalid case input accepted", field)
			}
		}
	})
	t.Run("extras", func(t *testing.T) {
		in := itemInput(t)
		out, err := assemble(in)
		if err != nil {
			t.Fatal(err)
		}
		docs := map[api.ID]document{}
		for _, row := range out.Documents {
			if row.Ref != ref(row.Ref.ID, row.Ref.Class, row.Data) {
				t.Fatal("case bytes were repinned incorrectly")
			}
			docs[row.Ref.ID] = row
		}
		for _, row := range in.Documents {
			if !bytes.Equal(docs[row.Ref.ID].Data, row.Data) {
				t.Fatal("case document was omitted")
			}
		}
		var p api.EffectivePolicy
		if err := api.DecodeObject(docs[out.Initial.Policy.ID].Data, &p); err != nil {
			t.Fatal(err)
		}
		for _, rule := range p.Rules {
			if !slices.Contains(rule.Scope.Levels, 3) || !slices.Contains(rule.Scope.Levels, 5) ||
				!slices.Contains(rule.Scope.Roles, "executor") || !slices.Contains(rule.Scope.Roles, "supervisor") {
				t.Fatal("case role scope was omitted")
			}
		}
		var root api.RootGrantManifest
		if err := api.DecodeObject(docs[out.Initial.Profiles.ID].Data, &root); err != nil {
			t.Fatal(err)
		}
		a, aerr := json.Marshal(root.Resources)
		b, berr := json.Marshal(in.RootGrants.Resources)
		if aerr != nil || berr != nil || !bytes.Equal(a, b) {
			t.Fatal("case root scope was omitted")
		}
		if len(root.Data) != 2 || root.Data[1].SourceSHA256 != in.RootGrants.Data[0].SourceSHA256 ||
			root.Data[0].Destination != "/work/main" {
			t.Fatal("case or baseline data scope was omitted")
		}
		if out.Initial.L5.Level != 5 || out.Root.Manifest != out.Initial.Profiles || out.Ref != ref(out.Ref.ID, "manifest", out.Raw) {
			t.Fatal("case changed the initial root or descriptor pins")
		}
	})
}

// Mutate only this lane's assembler through a Go overlay, and require its
// deciding assertion to fail before the unchanged package passes. The source
// checkout is never edited by these controls.
func TestItemControls(t *testing.T) {
	path, err := filepath.Abs("main.go")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, before, after, target, diagnostic string }{
		{"document", "doc.Ref != ref(doc.Ref.ID, doc.Ref.Class, doc.Data) ||", "",
			"document-pin", "document pin was not enforced"},
		{"context", "for _, role := range in.Contexts {", "for _, role := range []api.RoleContext{} {",
			"extras", "case role scope was omitted"},
		{"root", "if in.RootGrants != nil {", "if in.RootGrants != nil && len(in.RootGrants.Resources) == 0 {",
			"extras", "case root scope was omitted"},
		{"shared-role", "if !slices.Contains(roles, role.Role) {", "if role.Role != \"\" {",
			"shared-role", "shared role scope is invalid"},
	} {
		if bytes.Count(raw, []byte(row.before)) != 1 {
			t.Fatal("control anchor is missing or ambiguous", row.name)
		}
		mutated := bytes.Replace(raw, []byte(row.before), []byte(row.after), 1)
		dir := t.TempDir()
		file := filepath.Join(dir, "main.go")
		if err := os.WriteFile(file, mutated, 0600); err != nil {
			t.Fatal(err)
		}
		overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{path: file}})
		if err != nil {
			t.Fatal(err)
		}
		mapping := filepath.Join(dir, "overlay.json")
		if err := os.WriteFile(mapping, overlay, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("go", "test", "-count=1", "-overlay", mapping,
			"-run", "^TestItemBundle$/^"+row.target+"$", "-v", ".")
		output, err := command.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
			!strings.Contains(string(output), row.diagnostic) || !strings.Contains(string(output), "--- FAIL: TestItemBundle/") {
			t.Fatalf("control %s missed its deciding assertion: %v\n%s", row.name, err, output)
		}
		t.Logf("RED %s source=%s before=%q after=%q diagnostic=%s", row.name, digest(raw), row.before, row.after, row.diagnostic)
	}
	command := exec.Command("go", "test", "-count=1", "-run", "^TestItemBundle$", "-v", ".")
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "\nPASS\n") {
		t.Fatalf("candidate failed: %v\n%s", err, output)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, unchanged) {
		t.Fatal("candidate source changed during controls")
	}
	t.Logf("GREEN unchanged source=%s", digest(unchanged))
}
