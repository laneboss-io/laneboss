package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/templates"
)

const bundleTestBinary = "unexecuted release bytes"

func bundleInput(t *testing.T) input {
	t.Helper()
	tool := ref("tool-bytes", "artifact", []byte("declared tool bytes"))
	agent := ref("agent-bytes", "artifact", []byte("declared agent bytes"))
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact:  api.Executable{ID: "tool", SHA256: tool.SHA256, Version: "fixture-v1"},
		Bootstrap: api.Executable{ID: "tool", SHA256: tool.SHA256, Version: "fixture-v1"},
		Objects: []api.RuntimeObject{
			{ID: "tool", Role: "artifact", RootID: "runtime", RelativePath: "tool", Content: tool, Mode: 0555},
			{ID: "agent", Role: "serve-fixture-agent", RootID: "runtime", RelativePath: "agent", Content: agent, Mode: 0555}},
		Bindings: []api.InstalledBinding{}}
	raw, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	in := input{Config: "bundle-case", Runtime: ref("runtime", "manifest", raw), RuntimeRaw: raw,
		Project: []byte("test project\n"), Task: []byte("test task\n"), Model: "declared-fixture-model",
		ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)),
		Judge:     policy.DefaultJudgeConfig(digest([]byte("deployment")), digest([]byte("tokenizer")), 32768),
		Contexts:  []api.RoleContext{{Level: 3, Role: "executor"}}}
	for i, source := range []struct{ path, kind, name string }{
		{templates.OrgTemplatePath, "prompt", "org/default.md"}, {templates.OrgDriversPath, "drivers", "org/drivers.toml"},
		{templates.WorkflowPath, "policy", "org/workflow.toml"},
		{".laneboss/L5/roles/supervisor.md", "prompt", "roles/L5/supervisor.md"},
		{".laneboss/L5/roles/supervisor.toml", "drivers", "roles/L5/supervisor.toml"},
		{".laneboss/L3/roles/executor.md", "prompt", "roles/L3/executor.md"},
		{".laneboss/L3/roles/executor.toml", "drivers", "roles/L3/executor.toml"},
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", source.name))
		if err != nil {
			t.Fatal(err)
		}
		in.Sources = append(in.Sources, sourceInput{ID: api.ID("source-" + string(rune('a'+i))), Path: source.path, Kind: source.kind, Data: data})
	}
	return in
}

type bundleReader struct {
	org  api.OrgSnapshot
	docs map[api.ID][]byte
}

func (r bundleReader) Source(_ context.Context, scope api.Scope, source api.SourceRef) (api.RetainedSource, error) {
	return templates.SelectSource(scope, r.org, source)
}

func (r bundleReader) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	raw, found := r.docs[request.ObjectID]
	if !found || request.Offset < 0 || request.Offset > int64(len(raw)) || request.Limit <= 0 {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound, Message: "declared bundle object is absent"}
	}
	part := raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: digest(part)}, nil
}

func TestBundleCanonicalEnrollment(t *testing.T) {
	in := bundleInput(t)
	// bundleInput enrolls the actual L3 and L5 role sources once. Both role
	// views below must resolve the same approved canonical policy.
	out, err := assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	reader := bundleReader{docs: map[api.ID][]byte{}}
	for _, document := range out.Documents {
		reader.docs[document.Ref.ID] = document.Data
	}
	if err := json.Unmarshal(reader.docs[out.Initial.Sources.ID], &reader.org); err != nil {
		t.Fatal(err)
	}
	if !policy.HasCanonical(reader.org) {
		t.Fatal("installed bundle omits canonical policy enrollment")
	}
	var approved api.EffectivePolicy
	if err := json.Unmarshal(reader.docs[out.Initial.Policy.ID], &approved); err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: out.Initial.Config, Actor: api.Actor{Kind: "service", ID: "bundle-reader"}, PolicyGeneration: approved.Generation}
	for _, role := range []api.RoleContext{out.Initial.L5, {Level: 3, Role: "executor"}} {
		view, err := policy.ReadCanonical(context.Background(), reader, scope, approved, reader.org, role)
		if err != nil || len(approved.Rules) == 0 || len(view.Policy.Rules) != len(approved.Rules) || len(view.Policy.Rules) != 12 || view.Policy.Context != role {
			t.Fatal("installed bundle cannot resolve its approved policy for an actual role", err)
		}
	}
}

func bundleTestInput(t *testing.T) input {
	t.Helper()
	binary := ref("laneboss", "artifact", []byte(bundleTestBinary))
	executable := api.Executable{ID: "laneboss", SHA256: binary.SHA256, Version: "fixture"}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable,
		Bindings: []api.InstalledBinding{}, Objects: []api.RuntimeObject{
			{ID: "laneboss", Role: "serve-fixture-agent", RootID: "objects", RelativePath: "laneboss", Mode: 0555, Content: binary},
		}}
	for _, name := range []string{"claudock", "claude"} {
		runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: api.ID(name), Role: name, RootID: "objects", RelativePath: name, Mode: 0555,
			Content: api.BlobRef{ID: api.ID(name), Class: "artifact", Bytes: 65 << 20, SHA256: digest([]byte(name))}})
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	in := input{Config: "vendor", RuntimeRaw: raw, Runtime: ref("runtime", "manifest", raw), Project: []byte("project"), Task: []byte("task"), Model: "fixture",
		RealClaudock: &api.Executable{ID: "claudock", SHA256: runtime.Objects[1].Content.SHA256, Version: "0.1.0"},
		RealClaude:   &api.Executable{ID: "claude", SHA256: runtime.Objects[2].Content.SHA256, Version: "enrolled-history-release"},
		ExpiresAt:    api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)),
		Judge: api.JudgeConfig{Provider: "clef-sglang", Model: "Cloudflare/clef-flash", DeploymentSHA256: digest([]byte("deployment")), TokenizerSHA256: digest([]byte("tokenizer")),
			ContextTokens: 256, MaxBytes: 256, MaxQuestions: 1, CommandDeadlineMS: 1000, GuidanceDeadlineMS: 1000, OutagePolicy: "critical-only"}}
	for _, row := range []struct{ id, path, logical, kind string }{
		{"org-prompt", "org/default.md", ".laneboss/shared/templates/default.md", "prompt"},
		{"org-drivers", "org/drivers.toml", ".laneboss/shared/templates/drivers.toml", "drivers"},
		{"workflow", "org/workflow.toml", ".laneboss/shared/workflow.toml", "policy"},
		{"l5-prompt", "roles/L5/supervisor.md", ".laneboss/L5/roles/supervisor.md", "prompt"},
		{"l5-drivers", "roles/L5/supervisor.toml", ".laneboss/L5/roles/supervisor.toml", "drivers"},
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", row.path))
		if err != nil {
			t.Fatal(err)
		}
		in.Sources = append(in.Sources, sourceInput{ID: api.ID(row.id), Path: row.logical, Kind: row.kind, Data: data})
	}
	return in
}

func TestVendorBundle(t *testing.T) {
	in := bundleTestInput(t)
	out, err := assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Raw) > api.MaxFrameBytes || len(out.Initial.Objects) == 0 {
		t.Fatal("bundle lost its bounded publication inventory")
	}
	for _, object := range out.Initial.Objects {
		if object.ID == "claudock" || object.ID == "claude" {
			t.Error("vendor file entered publication inventory", object.ID)
		}
	}
	checked := false
	for _, document := range out.Documents {
		if document.Ref != out.Initial.Launch {
			continue
		}
		var enrollment api.LaunchEnrollment
		if err := api.DecodeObject(document.Data, &enrollment); err != nil {
			t.Fatal(err)
		}
		for _, selected := range enrollment.Runtimes {
			if selected.Driver == api.DriverClaudock {
				checked = selected.SessionExecutable == *in.RealClaude && selected.Executable == *in.RealClaudock
			}
		}
	}
	if !checked {
		t.Fatal("bundle lost the exact enrolled Claude session executable")
	}
	for _, fault := range []string{"missing", "digest", "wrapper"} {
		broken := in
		pin := *in.RealClaude
		broken.RealClaude = &pin
		switch fault {
		case "missing":
			broken.RealClaude = nil
		case "digest":
			pin.SHA256 = digest([]byte("different vendor"))
		case "wrapper":
			pin = *in.RealClaudock
		}
		if _, err := assemble(broken); err == nil {
			t.Fatal("bundle accepted missing or mismatched Claude enrollment", fault)
		}
	}
}
