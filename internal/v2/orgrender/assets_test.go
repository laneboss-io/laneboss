package orgrender

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestRenderAssets(t *testing.T) {
	root := t.TempDir()
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	marker := hex.EncodeToString(token[:])
	manifest := []byte(`{"name":"demo","description":"` + marker + `"}`)
	hook := []byte(`{"hooks":{"PreToolUse":[]},"sandbox":{"enabled":false},"description":"` + marker + `"}`)
	files := []File{
		{Path: "plugins/demo/manifest.json", Mode: 0444, Data: manifest},
		{Path: "plugins/demo/run.sh", Mode: 0500, Data: []byte("#!/bin/sh\nprintf '%s\\n' '" + marker + "'\n")},
		{Path: ".laneboss/shared/hooks/claude.json", Mode: 0444, Data: hook},
		{Path: ".laneboss/shared/hooks/codex.json", Mode: 0444, Data: []byte(`{"hooks":{"PreToolUse":[]}}`)},
	}
	input := Input{Sources: []string{}, Derived: []string{}}
	for _, file := range files {
		name := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, file.Data, fs.FileMode(file.Mode)); err != nil {
			t.Fatal(err)
		}
		input.Sources = append(input.Sources, file.Path)
	}
	inputFile := filepath.Join(t.TempDir(), "input.json")
	assetInput(t, inputFile, input)
	if err := RenderTree(context.Background(), root, inputFile); err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]File{
		"rendered/plugins/demo/manifest.json": {Data: manifest, Mode: 0444},
		"rendered/plugins/demo/run.sh":        {Data: files[1].Data, Mode: 0500},
		"rendered/.claude/settings.json":      {Data: hook, Mode: 0444},
		"rendered/.codex/hooks.json":          {Data: files[3].Data, Mode: 0444},
	} {
		name := filepath.Join(root, filepath.FromSlash(name))
		raw, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(raw, expected.Data) {
			t.Fatal("render omitted or changed approved plugin/hook bytes", filepath.Base(name), err)
		}
		info, err := os.Stat(name)
		if err != nil || uint32(info.Mode().Perm()) != expected.Mode {
			t.Fatal("render changed the approved asset mode", err)
		}
	}
	if err := filepath.WalkDir(filepath.Join(root, "rendered"), func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			input.Derived = append(input.Derived, filepath.ToSlash(relative))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "plugins/demo/run.sh")); err != nil {
		t.Fatal(err)
	}
	input.Sources = []string{files[0].Path, files[2].Path, files[3].Path}
	assetInput(t, inputFile, input)
	if err := RenderTree(context.Background(), root, inputFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "rendered/plugins/demo/run.sh")); !os.IsNotExist(err) {
		t.Fatal("deleted plugin source left a stale generated executable", err)
	}
}

func assetInput(t *testing.T, file string, input Input) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
