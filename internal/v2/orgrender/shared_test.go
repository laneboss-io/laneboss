package orgrender

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/templates"
)

func TestSharedRuleOnce(t *testing.T) {
	root := t.TempDir()
	var seed [12]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	marker := []byte("Retain rule " + hex.EncodeToString(seed[:]))
	files := map[string][]byte{
		templates.OrgTemplatePath:            []byte("# Org rules\n@../protocol/base.md\n"),
		".laneboss/shared/protocol/base.md":  marker,
		".laneboss/shared/protocol/extra.md": []byte("Retain the unreferenced shared rule.\n"),
	}
	input := Input{Sources: []string{}, Derived: []string{}}
	for name, raw := range files {
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources = append(input.Sources, name)
	}
	file := filepath.Join(t.TempDir(), "input.json")
	assetInput(t, file, input)
	if err := RenderTree(context.Background(), root, file); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AGENTS.md", "CLAUDE.md"} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || bytes.Count(raw, marker) != 1 || !bytes.Contains(raw, files[".laneboss/shared/protocol/extra.md"]) {
			t.Fatal("shared rule was duplicated or an unreferenced rule was lost", name, err)
		}
	}
	cycle := filepath.Join(root, ".laneboss/shared/protocol/base.md")
	if err := os.WriteFile(cycle, []byte("@../templates/default.md\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RenderTree(context.Background(), root, file); err == nil {
		t.Fatal("shared rule deduplication hid an actual import cycle")
	}
}
