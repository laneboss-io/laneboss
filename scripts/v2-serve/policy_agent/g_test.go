package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Synthetic scope data checks session formatting. The installed CLI is still
// the sole startup identity source in serve; this test grants no authority.
func TestPolicySession(t *testing.T) {
	id := func() string {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw[:])
	}
	o := options{Config: "policy-session", Life: id(), Run: 1, Driver: "codex",
		Session: id(), Home: id(), History: id(), VendorSession: id()}
	scope := api.Scope{Config: o.Config, Actor: api.Actor{Kind: "lane", ID: api.ID(id()),
		LifeID: api.ID(o.Life), Level: 5, Role: "supervisor"}, LaunchID: api.ID(id())}
	frame, err := sessionFrame(o, scope)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{"session_id": o.Session, "home_id": o.Home,
		"history_id": o.History, "vendor_session_id": o.VendorSession, "driver": o.Driver,
		"type": "serve.session", "vendor_stood_in": true} {
		if frame[key] != value {
			t.Fatalf("actual reserved field was not retained: %s", key)
		}
	}
	raw, err := json.Marshal(frame["identity"])
	var decoded api.Scope
	if err != nil || json.Unmarshal(raw, &decoded) != nil || decoded.Config != scope.Config ||
		decoded.Actor != scope.Actor || decoded.LaunchID != scope.LaunchID {
		t.Fatal("session frame did not retain its actual input scope")
	}
	for _, name := range []string{"foreign-life", "foreign-config", "missing-home", "missing-launch"} {
		t.Run(name, func(t *testing.T) {
			request, identity := o, scope
			switch name {
			case "foreign-life":
				identity.Actor.LifeID = api.ID(id())
			case "foreign-config":
				identity.Config = "another-policy"
			case "missing-home":
				request.Home = ""
			case "missing-launch":
				identity.LaunchID = ""
			}
			if _, err := sessionFrame(request, identity); err == nil {
				t.Fatal("session accepted " + name)
			}
		})
	}
}

// Remove one real deciding guard through an overlay and require the exact
// reached assertion, then verify the original source bytes are untouched.
func TestPolicySessionRed(t *testing.T) {
	path, err := filepath.Abs("main.go")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := "scope.Actor.LifeID != api.ID(o.Life) ||"
	if strings.Count(string(raw), before) != 1 {
		t.Fatal("session mutation anchor is missing or ambiguous")
	}
	directory := t.TempDir()
	mutated := filepath.Join(directory, "main.go")
	if err := os.WriteFile(mutated, []byte(strings.Replace(string(raw), before, "", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(map[string]any{"Replace": map[string]string{path: mutated}})
	if err != nil {
		t.Fatal(err)
	}
	mapFile := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(mapFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "-count=1", "-overlay", mapFile,
		"-run", "^TestPolicySession$/^foreign-life$", "-v", ".")
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
		!strings.Contains(string(output), "session accepted foreign-life") ||
		!strings.Contains(string(output), "--- FAIL: TestPolicySession/foreign-life") {
		t.Fatalf("RED session identity guard did not reach its assertion: %v\n%s", err, output)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || string(unchanged) != string(raw) {
		t.Fatal("session control changed the original source")
	}
	t.Log("RED foreign-life reached its session assertion; candidate source unchanged")
}
