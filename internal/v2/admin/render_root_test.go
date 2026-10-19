//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/orgrender"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestOrgRenderNative(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native org rendering requires the disposable root Linux box")
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "renderer")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "../../../cmd/laneboss")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("renderer build failed", err, string(output))
	}
	program, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(program)
	stage := orgrender.Stage{ID: "native-render", ClaimID: "native-claim", Generation: 1, Change: api.ChangeRequest{Config: "render-demo", Renderer: api.Executable{ID: "renderer", SHA256: api.Digest(hex.EncodeToString(digest[:])), Version: "native"}},
		Sources: []orgrender.File{{Path: templates.OrgTemplatePath, Mode: 0600, Data: []byte("# Org rules\n" + "@extra.md\n@../protocol/base.md\n")}, {Path: ".laneboss/shared/templates/extra.md", Mode: 0600, Data: []byte("Native render source update.\n")}}, Derived: []orgrender.File{}}
	asset := []byte(`{"hooks":{"PreToolUse":[]}}`)
	stage.Sources = append(stage.Sources, orgrender.File{Path: ".laneboss/shared/hooks/codex.json", Mode: 0444, Data: asset},
		orgrender.File{Path: "plugins/demo/start.sh", Mode: 0500, Data: []byte("#!/bin/sh\necho native-plugin\n")},
		orgrender.File{Path: ".laneboss/shared/protocol/base.md", Mode: 0600, Data: []byte("Native protocol rule.\n")})
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result, err := runOrgRender(context.Background(), stage, 12051, 12051, "/runtime/renderer", []*nativeMount{{file: file, target: "/runtime/renderer", executable: true}})
	if err != nil {
		t.Fatal("actual pinned native org render failed", err)
	}
	if result.UID != 12051 || result.PID <= 1 || result.InputSHA256 != orgrender.Digest(stage) {
		t.Fatal("native render did not report its actual worker and original inputs")
	}
	reached := false
	for _, output := range result.Files {
		if output.Path == "AGENTS.md" {
			reached = bytes.Contains(output.Data, []byte("Native render source update.")) && bytes.Count(output.Data, []byte("Native protocol rule.")) == 1
		}
	}
	if !reached {
		t.Fatal("actual source edit did not reach generated agent rules")
	}
	assets := map[string]orgrender.File{}
	for _, output := range result.Files {
		assets[output.Path] = output
	}
	if !bytes.Equal(assets["rendered/.codex/hooks.json"].Data, asset) || assets["rendered/plugins/demo/start.sh"].Mode != 0500 {
		t.Fatal("native render omitted approved hook/plugin output")
	}
	stage.Derived = result.Files
	stage.Sources = []orgrender.File{{Path: templates.OrgTemplatePath, Mode: 0600, Data: []byte("# Replacement org rules\n")}}
	stage.ClaimID = "next-native-claim"
	next, err := runOrgRender(context.Background(), stage, 12051, 12051, "/runtime/renderer", []*nativeMount{{file: file, target: "/runtime/renderer", executable: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range next.Files {
		if output.Path == "rendered/shared/templates/extra.md" {
			t.Fatal("deleted source left an obsolete generated output")
		}
	}
}
