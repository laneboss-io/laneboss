package orgtree

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/orghook"
)

func TestRawPackArgvWords(t *testing.T) {
	for _, name := range []string{"LANEBOSS_CONFIG", "LANEBOSS_INSTANCE", "LANEBOSS_LANE", "LANEBOSS_ROLE"} {
		t.Setenv(name, "")
	}
	root := filepath.Join(t.TempDir(), "word-pack")
	name := "word-pack"
	if _, err := initOrg(root, "3", &name); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "worktrees", "words")
	git := exec.Command("git", "init", "-q", workspace)
	git.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if output, err := git.CombinedOutput(); err != nil {
		t.Fatalf("initialize the private control repository: %s %v", output, err)
	}
	directory := filepath.Join(root, home, "instances", "L3-lane-example")
	instance := filepath.Join(directory, "instance.toml")
	raw, err := os.ReadFile(instance)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "writable_repos = []") != 1 {
		t.Fatal("fixture must replace exactly one workspace source field")
	}
	writeRawpackSource(t, instance, strings.Replace(string(raw), "writable_repos = []", "writable_repos = [\"worktrees/words\"]", 1))
	if _, err := renderOrg(root); err != nil {
		t.Fatal(err)
	}
	vectors, err := os.ReadFile(filepath.Join("..", "..", "e2e-rows", "rawpack.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		ID      string   `json:"id"`
		Refused []string `json:"refused"`
		Allowed []string `json:"allowed"`
		Instead string   `json:"instead"`
	}
	if err := json.Unmarshal(vectors, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 12 {
		t.Fatal("every installed entry needs independent flag and allowed controls")
	}
	invoke := func(t *testing.T, runner, command string) map[string]any {
		t.Helper()
		tool, field := "Bash", "command"
		if runner == "codex" {
			tool, field = "exec_command", "cmd"
		}
		event, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": workspace,
			"tool_name": tool, "tool_input": map[string]any{field: command}})
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := orghook.Run("hook", []string{"--runner", runner, "--instance", instance}, bytes.NewReader(event), &stdout, &stderr); code != 0 {
			t.Fatalf("hook failed: %s", stderr.String())
		}
		var result struct {
			Output map[string]any `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Output
	}
	// Mutation controls: position-0-only matching turns the flag-first cases
	// red; substring matching turns git commit -m "codex exec" red. Vector
	// commands are inspected only, including git commit; none is executed.
	for _, row := range rows {
		t.Run(row.ID, func(t *testing.T) {
			if len(row.Refused) < 2 || len(row.Allowed) < 2 {
				t.Fatal("each entry needs its flag-first case and allowed controls")
			}
			for _, runner := range []string{"claude", "codex"} {
				for i, command := range row.Refused {
					t.Run(runner+"/refused/"+strconv.Itoa(i), func(t *testing.T) {
						output := invoke(t, runner, command)
						reason, _ := output["permissionDecisionReason"].(string)
						if output["permissionDecision"] != "deny" || !strings.HasPrefix(reason, "["+row.ID+"] Refuses:") || !strings.HasSuffix(reason, "\nInstead: "+row.Instead) {
							t.Fatalf("the installed word matcher lost its refusal or route: %v", output)
						}
					})
				}
				for i, command := range row.Allowed {
					t.Run(runner+"/allowed/"+strconv.Itoa(i), func(t *testing.T) {
						output := invoke(t, runner, command)
						if output["permissionDecision"] != "allow" || output["permissionDecisionReason"] != "org policy permits this tool call" {
							t.Fatalf("a read or quoted non-runner control was refused: %v", output)
						}
					})
				}
			}
		})
	}
}
