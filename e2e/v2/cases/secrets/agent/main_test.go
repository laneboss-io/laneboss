package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func random(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestActualInjection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("injection checks require the authorized nonroot Linux step")
	}
	env, file, baseline := random(t), random(t), random(t)
	t.Setenv("TASK_TOKEN", base64.StdEncoding.EncodeToString(env))
	t.Setenv("TZDIR", base64.StdEncoding.EncodeToString(baseline))
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(os.Getenv("HOME"), "task.key")
	if err := os.WriteFile(path, file, 0400); err != nil {
		t.Fatal(err)
	}
	plan := task{EnvName: "TASK_TOKEN", EnvSHA: digest([]byte(base64.StdEncoding.EncodeToString(env))),
		FilePath: "task.key", FileSHA: digest(file), ReservedName: "TZDIR", ReservedSHA: digest([]byte(base64.StdEncoding.EncodeToString(baseline))),
		HiddenEnv: []string{"UNDELEGATED_TOKEN"}, HiddenFiles: []string{filepath.Join(t.TempDir(), "outside")}}
	if err := os.Unsetenv("UNDELEGATED_TOKEN"); err != nil {
		t.Fatal(err)
	}
	for _, control := range []string{"env", "file", "reserved", "undelegated"} {
		wrong := plan
		switch control {
		case "env":
			wrong.EnvSHA = digest(random(t))
		case "file":
			wrong.FileSHA = digest(random(t))
		case "reserved":
			wrong.ReservedSHA = digest(random(t))
		case "undelegated":
			t.Setenv("UNDELEGATED_TOKEN", base64.StdEncoding.EncodeToString(random(t)))
		}
		if injection(wrong)[control] {
			t.Fatal("native probe ignored its actual boundary", control)
		}
		if err := os.Unsetenv("UNDELEGATED_TOKEN"); err != nil {
			t.Fatal(err)
		}
	}
	for name, ok := range injection(plan) {
		if !ok {
			t.Fatal("native probe did not compare actual selected bytes", name)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if injection(plan)["file"] {
		t.Fatal("native probe accepted a writable selected file")
	}
}

func TestSelectedStandIn(t *testing.T) {
	selected := api.ProfileGrant{ID: "actual-grant", ProfileID: "actual-profile", Driver: api.DriverClaudock}
	in := options{Config: "agent-test", Challenge: digest(random(t))[:32], Driver: string(selected.Driver)}
	sha := digest(random(t))
	raw, err := json.Marshal(map[string]any{"program": "laneboss-e2e-authenticator", "config": in.Config,
		"challenge": in.Challenge, "profile_id": selected.ProfileID, "driver": selected.Driver, "vendor_stood_in": true,
		"runtime": api.Executable{ID: "runtime", SHA256: api.Digest(sha), Version: "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", string(raw))
	foreign := selected
	foreign.ProfileID = "other-profile"
	if ownProfile(in, foreign, sha) {
		t.Fatal("stand-in turn accepted another enrolled profile")
	}
	if ownProfile(in, selected, digest(random(t))) {
		t.Fatal("stand-in turn accepted another runtime")
	}
	if !ownProfile(in, selected, sha) {
		t.Fatal("stand-in turn rejected its actual selected source")
	}
	if err := os.Unsetenv("CLAUDE_CODE_OAUTH_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if ownProfile(in, selected, sha) {
		t.Fatal("stand-in turn succeeded without an injected source")
	}
}

func TestSelectedCodexStandIn(t *testing.T) {
	selected := api.ProfileGrant{ID: "codex-grant", ProfileID: "codex-profile", Driver: api.DriverCodex}
	in := options{Config: "agent-test", Challenge: digest(random(t))[:32], Driver: string(selected.Driver)}
	sha := digest(random(t))
	material, err := json.Marshal(map[string]any{"program": "laneboss-e2e-authenticator", "config": in.Config,
		"challenge": in.Challenge, "profile_id": selected.ProfileID, "driver": selected.Driver, "vendor_stood_in": true,
		"runtime": api.Executable{ID: "runtime", SHA256: api.Digest(sha), Version: "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	login, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{
		"access_token": base64.StdEncoding.EncodeToString(material)}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(login)
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	if err := os.WriteFile(filepath.Join(root, "auth.json"), login, 0400); err != nil {
		t.Fatal(err)
	}
	foreign := selected
	foreign.ProfileID = "other-codex-profile"
	if ownProfile(in, foreign, sha) {
		t.Fatal("stand-in codex turn accepted another enrolled profile")
	}
	if !ownProfile(in, selected, sha) {
		t.Fatal("stand-in codex turn ignored its actual injected auth file")
	}
	if ownProfile(in, selected, digest(random(t))) {
		t.Fatal("stand-in codex turn accepted another runtime")
	}
	t.Setenv("CODEX_HOME", t.TempDir())
	if ownProfile(in, selected, sha) {
		t.Fatal("stand-in codex turn succeeded without its auth file")
	}
}

func TestAbsentSource(t *testing.T) {
	for _, path := range []string{"", ".", "relative", "/"} {
		if absent(path) {
			t.Fatal("absent source control accepted a missing absolute target")
		}
	}
	path := filepath.Join(t.TempDir(), "outside")
	if !absent(path) {
		t.Fatal("absent source control rejected an actual absent path")
	}
	if err := os.WriteFile(path, random(t), 0400); err != nil {
		t.Fatal(err)
	}
	if absent(path) {
		t.Fatal("absent source control accepted readable outside bytes")
	}
}
