package orghook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

const worktreeBoundaryReason = "refused: lanes may write only inside their recorded worktree; shared message files require the checked message path\nInstead: report up with laneboss report, or use lane send for a permitted peer."
const networkBoundaryReason = "refused: lanes may not request dashboard ports or send outbound messages with a raw network client\nInstead: report up with laneboss report, or use lane send for a permitted peer."

func boundaryFixture(t *testing.T) (*instance, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, ".laneboss")
	directory := filepath.Join(home, "instances", "executor")
	repository := filepath.Join(root, "repository")
	files := [][2]string{
		{filepath.Join(home, "org.toml"), "schema_version = 1\nname = \"fixture\"\n"},
		{filepath.Join(directory, "instance.toml"), fmt.Sprintf("name = \"executor\"\nlevel = 3\nrole = \"executor\"\nwritable_repos = [%q]\nallowed_tools = []\nsecret_names = []\n", repository)},
		{filepath.Join(home, "shared", "hooks", "rules.toml"), "schema_version = 1\nrules = []\n"},
		{filepath.Join(home, "L3", "hooks", "rules.toml"), "schema_version = 1\n[[rules]]\nid = \"no-push\"\nkind = \"command-pattern\"\npatterns = [[\"git\", \"push\"]]\n"},
		{filepath.Join(home, "L3", "refusals", "no-push.toml"), "id = \"no-push\"\nrefuses = \"Publishing from the fixture executor.\"\nwhy = \"Publication requires supervisor review.\"\ninstead = \"Leave the changes local.\"\nexamples_allowed = []\nexamples_refused = []\n[applies_to]\nlevels = [3]\nidentities = [\"*\"]\n"},
	}
	for _, file := range files {
		path, text := file[0], file[1]
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(repository, 0700); err != nil {
		t.Fatal(err)
	}
	inst, err := loadInstance(directory)
	if err != nil {
		t.Fatal(err)
	}
	// These tests are isolated hook processes with no lane identity. The CLI rows
	// exercise the same decisions from a real running lane and its process record.
	for _, name := range []string{"LANEBOSS_CONFIG", "LANEBOSS_INSTANCE", "LANEBOSS_LANE", "LANEBOSS_ROLE"} {
		t.Setenv(name, "")
	}
	return inst, root
}

func TestInstalledPolicyBeforeLaneBoundary(t *testing.T) {
	inst, _ := boundaryFixture(t)
	orgPath := filepath.Join(inst.home, "org.toml")
	orgBytes, err := os.ReadFile(orgPath)
	if err != nil {
		t.Fatal(err)
	}
	strict := append(append([]byte{}, orgBytes...), []byte("\n[hooks]\nmode = \"strict\"\n")...)
	if err := os.WriteFile(orgPath, strict, 0600); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		tool, field := "Bash", "command"
		if runner == "codex" {
			tool, field = "exec_command", "cmd"
		}
		event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": map[string]any{field: "git push"}}
		allowed, reason, err := decide(event, runner, filepath.Join(inst.directory, "instance.toml"))
		if err != nil || allowed || !strings.HasPrefix(reason, "[no-push] Refuses: Publishing from the fixture executor.\nWhy: Publication requires supervisor review.\n") {
			t.Fatalf("strict installed refusal must retain its format: allow=%v reason=%q err=%v", allowed, reason, err)
		}
	}
	if err := os.WriteFile(orgPath, append(append([]byte{}, orgBytes...), []byte("\n[hooks]\nmode = \"blacklist\"\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		tool, field := "Bash", "command"
		if runner == "codex" {
			tool, field = "exec_command", "cmd"
		}
		event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": map[string]any{field: "git push"}}
		allowed, reason, err := decide(event, runner, filepath.Join(inst.directory, "instance.toml"))
		if err != nil || allowed || !strings.HasPrefix(reason, "[no-push] Refuses: Publishing from the fixture executor.\nWhy: Publication requires supervisor review.\n") {
			t.Fatalf("blacklist installed refusal must retain its blacklist format: allow=%v reason=%q err=%v", allowed, reason, err)
		}
	}
}

func authenticatedLaneFixture(t *testing.T) (*instance, string, string) {
	t.Helper()
	return authenticatedLaneLevelFixture(t, 3)
}

func authenticatedLaneLevelFixture(t *testing.T, level int) (*instance, string, string) {
	t.Helper()
	return authenticatedLaneFixtureFull(t, level, level, "human")
}

func authenticatedLaneRecordFixture(t *testing.T, level, recordedLevel int) (*instance, string, string) {
	t.Helper()
	return authenticatedLaneFixtureFull(t, level, recordedLevel, "human")
}

func authenticatedLaneStarterFixture(t *testing.T, level int, starter string) (*instance, string, string) {
	t.Helper()
	return authenticatedLaneFixtureFull(t, level, level, starter)
}

func authenticatedLaneFixtureFull(t *testing.T, level, recordedLevel int, starter string) (*instance, string, string) {
	t.Helper()
	inst, root := boundaryFixture(t)
	if level != 3 {
		text := fmt.Sprintf("name = \"executor\"\nlevel = %d\nrole = \"supervisor\"\nwritable_repos = [%q]\nallowed_tools = []\nsecret_names = []\n", level, inst.worktree)
		if err := os.WriteFile(filepath.Join(inst.directory, "instance.toml"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(inst.home, fmt.Sprintf("L%d", level), "hooks", "rules.toml")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("schema_version = 1\nrules = []\n"), 0600); err != nil {
			t.Fatal(err)
		}
		var err error
		inst, err = loadInstance(inst.directory)
		if err != nil {
			t.Fatal(err)
		}
	}
	worktree := filepath.Join(root, "repository-lane")
	if err := os.Mkdir(worktree, 0700); err != nil {
		t.Fatal(err)
	}
	home, states := filepath.Join(root, "configuration"), filepath.Join(root, "state")
	directory := filepath.Join(home, "configs", "boundary")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	text := "schema_version = 1\nname = \"boundary\"\n[runners.fixture]\ncommand = [\"true\", \"{brief}\"]\n"
	if err := os.WriteFile(filepath.Join(directory, "config.toml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEBOSS_HOME", home)
	t.Setenv("LANEBOSS_STATE_HOME", states)
	t.Setenv("LANEBOSS_CONFIG", "boundary")
	if err := os.Unsetenv("LANEBOSS_LANE"); err != nil {
		t.Fatal(err)
	}
	configuration, err := config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	ec := &eventstore.Configuration{Name: configuration.Name, Home: home, StateHome: states, Directory: directory, StatePath: configuration.StateDir}
	dir, err := ec.OpenDirectory(true)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	store, err := eventstore.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lane, launch, hash := "executor", strings.Repeat("a", 32), strings.Repeat("b", 64)
	payload := map[string]any{"run": 1, "how": "start", "launch": launch, "runner": "fixture", "model": "fixture-model-1", "effort": nil, "account": nil, "chosen_by": map[string]any{"runner": "supervisor", "model": "supervisor", "effort": nil, "account": nil}, "difficulty": nil, "project": nil, "worktree": worktree, "branch": nil, "base": nil, "repository": nil, "budget_minutes": 10, "quiet_seconds": 900, "brief": map[string]any{"path": filepath.Join(configuration.StateDir, "lanes", lane, "rendered", hash+".md"), "sha256": hash}, "log": filepath.Join(configuration.StateDir, "lanes", lane, "output.log"), "session": map[string]any{"socket": ec.Socket(configuration.StateDir), "name": lane}, "touches": []any{}, "claims": nil, "level": 3, "level_source": "protocol", "starter": "human"}
	payload["level"] = recordedLevel
	payload["starter"] = starter
	if recordedLevel != 3 {
		payload["level_source"] = "org"
	}
	if recordedLevel == 0 {
		delete(payload, "level")
		delete(payload, "level_source")
	}
	if _, err := store.Append(map[string]any{"kind": "lane.started", "lane": lane, "actor": "human", "protocol_version": "1.3.0", "payload": payload}); err != nil {
		t.Fatal(err)
	}
	start, err := caller.ProcessStart(os.Getpid())
	if err != nil || start == "" {
		t.Fatalf("the actual test process must have a recorded start identity: %v", err)
	}
	record := map[string]any{"config": configuration.Name, "lane": lane, "launch": launch, "run": 1, "supervisor": map[string]any{"pid": os.Getpid(), "start": start}, "runner": nil, "processes": []any{}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configuration.StateDir, "lanes", lane, "runs", launch+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	principal, resolved, err := caller.ResolveWithLane(configuration)
	if err != nil || principal.ID != "lane:"+lane || principal.Level != recordedLevel || resolved == nil || resolved.Payload["worktree"] != worktree {
		t.Fatalf("the real process record must resolve without a lane label: %+v, %v", principal, err)
	}
	return inst, root, worktree
}

func TestLaneHookUsesRecordedWorktree(t *testing.T) {
	inst, root, worktree := authenticatedLaneFixture(t)
	for _, row := range []struct {
		tool    string
		input   map[string]any
		allowed bool
		reason  string
	}{
		{"Write", map[string]any{"file_path": "inside.txt"}, true, "org policy permits this tool call"},
		{"Bash", map[string]any{"command": "touch inside.txt"}, true, "org policy permits this tool call"},
		{"Write", map[string]any{"file_path": filepath.Join(inst.worktree, "outside.txt")}, false, worktreeBoundaryReason},
		{"Write", map[string]any{"file_path": filepath.Join(root, "outside.txt")}, false, worktreeBoundaryReason},
		{"Bash", map[string]any{"command": "curl http://127.0.0.1:12345/api/messages"}, false, networkBoundaryReason},
	} {
		event := map[string]any{"hook_event_name": "PreToolUse", "cwd": worktree, "tool_name": row.tool, "tool_input": row.input}
		allowed, reason, err := decide(event, "claude", filepath.Join(inst.directory, "instance.toml"))
		if err != nil || allowed != row.allowed || reason != row.reason {
			t.Fatalf("an authenticated lane must use its recorded worktree: tool=%s allow=%v reason=%q err=%v", row.tool, allowed, reason, err)
		}
	}
}

func TestRecordedLaneWorktreeBoundary(t *testing.T) {
	inst, root := boundaryFixture(t)
	worktree := filepath.Join(root, "repository-lane")
	if err := os.Mkdir(worktree, 0700); err != nil {
		t.Fatal(err)
	}
	record := &caller.LaneRecord{Principal: caller.Principal{ID: "lane:executor", Level: 3}, Open: true, Payload: map[string]any{"worktree": worktree}}
	recorded, err := recordedLaneWorktree(record)
	if err != nil || recorded != worktree || recorded == inst.worktree {
		t.Fatal("the boundary must use the recorded sibling worktree, never the repository")
	}
	for _, path := range []string{"inside.txt", filepath.Join(worktree, "absolute.txt")} {
		for _, act := range []action{{writes: []string{path}}, {commands: []command{{argv: []string{"touch", path}, writes: []string{path}, directory: worktree}}}} {
			if reason, err := laneBoundary(act, inst, worktree, recorded); err != nil || reason != "" {
				t.Fatalf("a write in the recorded lane worktree must be allowed: %q, %v", reason, err)
			}
		}
	}
	for _, path := range []string{filepath.Join(inst.worktree, "outside.txt"), filepath.Join(root, "repository-lane-other", "outside.txt"), filepath.Join(inst.home, "shared", "message.txt")} {
		if reason, err := laneBoundary(action{writes: []string{path}}, inst, worktree, recorded); err != nil || reason != worktreeBoundaryReason {
			t.Fatalf("a write outside the recorded lane worktree must retain the boundary refusal: %q, %v", reason, err)
		}
	}
	if err := os.Symlink(inst.worktree, filepath.Join(worktree, "alias")); err != nil {
		t.Fatal(err)
	}
	if reason, err := laneBoundary(action{writes: []string{"alias/escaped.txt"}}, inst, worktree, recorded); err != nil || reason != worktreeBoundaryReason {
		t.Fatal("a symlink must not escape the recorded worktree")
	}
	// Shared messages stay protected even when they fall within the recorded root.
	if reason, err := laneBoundary(action{writes: []string{filepath.Join(inst.home, "shared", "message.txt")}}, inst, root, root); err != nil || reason != worktreeBoundaryReason {
		t.Fatal("a broad recorded root must not permit direct shared-message writes")
	}
}

func TestRecordedLaneWorktreeFailsClosed(t *testing.T) {
	for _, record := range []*caller.LaneRecord{
		nil,
		{Principal: caller.Principal{ID: "lane:executor"}, Open: false, Payload: map[string]any{"worktree": t.TempDir()}},
		{Principal: caller.Principal{ID: "human"}, Open: true, Payload: map[string]any{"worktree": t.TempDir()}},
		{Principal: caller.Principal{ID: "lane:executor"}, Open: true, Payload: map[string]any{}},
		{Principal: caller.Principal{ID: "lane:executor"}, Open: true, Payload: map[string]any{"worktree": "relative"}},
		{Principal: caller.Principal{ID: "lane:executor"}, Open: true, Payload: map[string]any{"worktree": "/invalid\npath"}},
	} {
		if path, err := recordedLaneWorktree(record); err == nil || path != "" {
			t.Fatal("an invalid lane record must fail closed without guessing a worktree")
		}
	}
}

func TestLaneNetworkBoundaryAfterPolicy(t *testing.T) {
	inst, _ := boundaryFixture(t)
	event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.directory, "tool_name": "Bash", "tool_input": map[string]any{"command": "curl http://127.0.0.1:12345/api/messages"}}
	allowed, reason, err := decide(event, "claude", filepath.Join(inst.directory, "instance.toml"))
	if err != nil || allowed || reason != networkBoundaryReason {
		t.Fatalf("a raw network client must retain the boundary reason before the generic opaque-command error: allow=%v reason=%q err=%v", allowed, reason, err)
	}
}

func TestNoLaneKeepsInstanceBoundary(t *testing.T) {
	inst, _ := boundaryFixture(t)
	for _, row := range []struct {
		path    string
		allowed bool
	}{
		{filepath.Join(inst.worktree, "inside.txt"), true},
		{filepath.Join(inst.directory, "outside.txt"), false},
	} {
		event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.directory, "tool_name": "Write", "tool_input": map[string]any{"file_path": row.path}}
		allowed, reason, err := decide(event, "claude", filepath.Join(inst.directory, "instance.toml"))
		if err != nil || allowed != row.allowed || !allowed && reason != worktreeBoundaryReason {
			t.Fatalf("without a lane the instance's repository boundary must stay in force: allow=%v reason=%q err=%v", allowed, reason, err)
		}
	}
}
