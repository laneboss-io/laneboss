package orghook

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaneWritesUseRecordedLevel(t *testing.T) {
	for _, row := range []struct {
		instanceLevel, recordedLevel int
		allowed                      bool
	}{{3, 3, false}, {4, 4, true}, {5, 5, true}, {6, 6, true}, {4, 0, false}, {4, 3, false}, {3, 4, true}} {
		for _, runner := range []string{"claude", "codex"} {
			t.Run(fmt.Sprintf("%s/instance-%d/recorded-%d", runner, row.instanceLevel, row.recordedLevel), func(t *testing.T) {
				inst, root, worktree := authenticatedLaneRecordFixture(t, row.instanceLevel, row.recordedLevel)
				inst.worktree = worktree
				target := filepath.Join(root, "artifacts", "issue", "x.md")
				tool, field := "Bash", "command"
				if runner == "codex" {
					tool, field = "exec_command", "cmd"
				}
				event := map[string]any{"hook_event_name": "PreToolUse", "cwd": worktree, "tool_name": tool, "tool_input": map[string]any{field: "printf x > " + target}}
				pinned := filepath.Join(inst.directory, "instance.toml")
				allowed, reason, err := decide(event, runner, pinned)
				wantReason := worktreeBoundaryReason
				if row.allowed {
					wantReason = "org policy permits this tool call"
				}
				if err != nil || allowed != row.allowed || reason != wantReason {
					t.Fatalf("recorded level must select only the write boundary: allow=%v reason=%q err=%v", allowed, reason, err)
				}
				if err := recordCallback(event, runner, pinned, allowed, reason, nil); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Join(inst.directory, "hooks", "callbacks.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				var receipt map[string]any
				if err := json.Unmarshal(data, &receipt); err != nil {
					t.Fatal(err)
				}
				decision := "deny"
				if row.allowed {
					decision = "allow"
				}
				if receipt["decision"] != decision || receipt["reason"] != wantReason || receipt["runner"] != runner || receipt["inspection_complete"] != true {
					t.Fatalf("the real decision must retain its ordinary receipt: %s", data)
				}
			})
		}
	}
}

func TestSupervisorBackstopsRemain(t *testing.T) {
	for _, level := range []int{4, 5, 6} {
		for _, runner := range []string{"claude", "codex"} {
			t.Run(fmt.Sprintf("%s/L%d", runner, level), func(t *testing.T) {
				inst, _, worktree := authenticatedLaneLevelFixture(t, level)
				inst.worktree = worktree
				for _, row := range []struct{ text, reason string }{
					{"curl https://example.invalid", networkBoundaryReason},
					{"nohup true", "refused: lanes may not detach their process identity with setsid or nohup\nInstead: report up with laneboss report, or use lane send for a permitted peer."},
					{"setsid true", "refused: lanes may not detach their process identity with setsid or nohup\nInstead: report up with laneboss report, or use lane send for a permitted peer."},
					{"tmux -S " + filepath.Join(worktree, "socket") + " list-sessions", "refused: lanes may not access a lane tmux socket directly\nInstead: report up with laneboss report, or use lane send for a permitted peer."},
				} {
					allowed, reason, err := compatibilityDecision(t, inst, runner, row.text, nil)
					if err != nil || allowed || reason != row.reason {
						t.Fatalf("supervisor process/network backstop changed: %q: %q %v", row.text, reason, err)
					}
				}
				allowed, reason, err := compatibilityDecision(t, inst, runner, "printf x > "+filepath.Join(inst.home, "org.toml"), nil)
				if err != nil || allowed || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
					t.Fatalf("supervisors must retain protected-file refusal: %q %v", reason, err)
				}
			})
		}
	}
}

func TestSupervisorGitSiblingWrite(t *testing.T) {
	for _, runner := range []string{"claude", "codex"} {
		t.Run(runner, func(t *testing.T) {
			inst, root, worktree := authenticatedLaneLevelFixture(t, 4)
			inst.worktree = worktree
			sibling := filepath.Join(root, "worker")
			if output, err := exec.Command("git", "init", "--quiet", sibling).CombinedOutput(); err != nil {
				t.Fatalf("initialize the disposable sibling worktree: %s %v", output, err)
			}
			if err := os.WriteFile(filepath.Join(sibling, "f"), []byte("worker output\n"), 0600); err != nil {
				t.Fatal(err)
			}
			allowed, reason, err := compatibilityDecision(t, inst, runner, "git -C "+sibling+" add f", nil)
			if err != nil || !allowed || reason != "org policy permits this tool call" {
				t.Fatalf("L4 must be able to review a worker worktree: %q %v", reason, err)
			}
		})
	}
}
