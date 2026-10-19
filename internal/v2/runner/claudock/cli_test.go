package claudock

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPathPreference(t *testing.T) {
	f := runnerSetup(t)
	name := filepath.Join(f.home.path, ".config/claudock/preferences.json")
	data := get(t, name)
	var prefs struct {
		Claude string `json:"claudeExecutable"`
	}
	if err := json.Unmarshal(data, &prefs); err != nil || prefs.Claude != f.service.deps.ClaudePath {
		t.Fatal("private preference does not select the declared CLI", err)
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("executable preference is not read-only", err)
	}
	projections, err := f.home.GeneratedProjections()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range projections {
		found = found || item.Path == ".config/claudock/preferences.json" && item.SHA256 == contentDigest(data)
	}
	if !found {
		t.Fatal("executable preference is outside protected generated projections")
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	put(t, name, []byte("{\"claudeExecutable\":\"/bin/false\"}"))
	if err := os.Chmod(name, 0400); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.Start(context.Background(), f.request)
	wantCode(t, err, api.CodeIntegrity)
}

func TestDeclaredPathGuard(t *testing.T) {
	for _, fault := range []string{"missing", "digest"} {
		t.Run(fault, func(t *testing.T) {
			f := runnerReady(t, nil)
			f.service.deps.RuntimePath = "/runtime/claudock"
			for _, path := range []string{f.service.deps.ExecutablePath, f.service.deps.ClaudePath} {
				if err := os.Chmod(path, 0555); err != nil {
					t.Fatal(err)
				}
			}
			installed, err := NewInstalled(f.service.deps)
			if err != nil {
				t.Fatal(err)
			}
			f.service = installed
			path := f.service.deps.ClaudePath
			if fault == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
				put(t, path, []byte("another CLI"))
				if err := os.Chmod(path, 0555); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := f.service.Start(context.Background(), f.request)
			wantCode(t, err, api.CodeIntegrity)
			want := "pinned executable path is missing or linked"
			if fault == "digest" {
				want = "pinned executable digest differs from retained bytes"
			}
			if err == nil || !strings.Contains(err.Error(), want) || len(plan.Argv) != 0 {
				t.Fatal("declared CLI failure was unclear or returned an executable plan", err)
			}
		})
	}
}
