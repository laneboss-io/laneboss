package orghook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func minimumHookArgs(node *hookSyntax, path []string, worktree string) []string {
	return hookArgsForPath(node, path, worktree, "", "")
}

func hookArgsForPath(node *hookSyntax, path []string, worktree, selected, target string) []string {
	args := append([]string{}, path...)
	for _, arg := range node.Args {
		if !arg.Required && arg.Name != "--config" && arg.Name != selected {
			continue
		}
		if strings.HasPrefix(arg.Name, "-") {
			args = append(args, arg.Name)
		}
		if arg.Flag {
			continue
		}
		value := "fixture"
		if arg.Type != "" {
			value = "1"
		}
		if len(arg.Choices) > 0 {
			value = fmt.Sprint(arg.Choices[0])
		}
		if arg.Name == "--config" {
			value = "boundary"
		}
		if arg.Path != nil {
			value = filepath.Join(worktree, "ordinary.txt")
			if arg.Path.Write && arg.Name == "org_dir" {
				value = filepath.Join(worktree, "new-org")
			}
			if arg.Name == selected {
				value = target
			}
			if arg.Path.Named {
				value = "sample=" + value
			}
		}
		args = append(args, value)
	}
	return args
}

func TestEveryPlainLanebossVerb(t *testing.T) {
	compatibilitySyntax(t)
	inst, _, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	if err := os.WriteFile(filepath.Join(worktree, "ordinary.txt"), []byte("ordinary input\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var walk func(*hookSyntax, []string)
	walk = func(node *hookSyntax, path []string) {
		for index := range node.Commands {
			child := &node.Commands[index]
			walk(child, append(append([]string{}, path...), child.Name))
		}
		if len(node.Commands) > 0 || len(path) == 0 {
			return
		}
		args := minimumHookArgs(node, path, worktree)
		for _, runner := range []string{"claude", "codex"} {
			t.Run(runner+"/"+strings.Join(path, "-"), func(t *testing.T) {
				// Mutant: require a hook annotation or restore strict allowlists.
				allowed, reason, err := compatibilityDecision(t, inst, runner, "laneboss "+strings.Join(args, " "), nil)
				if err != nil || !allowed {
					t.Fatalf("every plain declared verb must reach CLI authority: allow=%v reason=%q err=%v", allowed, reason, err)
				}
				for _, argument := range node.Args {
					if argument.Path == nil || !argument.Path.Write {
						continue
					}
					// Mutant: lose declared writes or skip the protected-file gate.
					changed := hookArgsForPath(node, path, worktree, argument.Name, filepath.Join(inst.home, "hooks", "output"))
					allowed, reason, err := compatibilityDecision(t, inst, runner, "laneboss "+strings.Join(changed, " "), nil)
					if err != nil || allowed || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
						t.Fatalf("%s must retain protected effects: allow=%v reason=%q err=%v", argument.Name, allowed, reason, err)
					}
				}
			})
		}
	}
	walk(lanebossSyntax.root, nil)
}

func TestUnsupportedProgramAndToolDeny(t *testing.T) {
	inst, _ := boundaryFixture(t)
	for _, mode := range []string{"blacklist", "strict"} {
		if err := os.WriteFile(filepath.Join(inst.home, "org.toml"), []byte(fmt.Sprintf("schema_version = 1\nname = \"fixture\"\n[hooks]\nmode = %q\n", mode)), 0600); err != nil {
			t.Fatal(err)
		}
		for _, runner := range []string{"claude", "codex"} {
			// Mutant: restore the unsupported-program adapter gate.
			allowed, reason, err := compatibilityDecision(t, inst, runner, "ordinary-unsupported-program argument", nil)
			if err != nil || !allowed {
				t.Fatalf("unsupported programs must allow: %q %v", reason, err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(inst.home, "settings.toml"), []byte("tool_deny_add = [\"Write\"]\ntool_allow_add = [\"Write\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": "Write", "tool_input": map[string]any{"file_path": filepath.Join(inst.worktree, "ordinary")}}
	allowed, reason, err := decide(event, "claude", filepath.Join(inst.directory, "instance.toml"))
	if err != nil || allowed || !strings.Contains(reason, "resolved settings deny this tool") {
		t.Fatalf("tool denials must survive ignored additions: %q %v", reason, err)
	}
}

func TestUnannotatedLanebossReceipt(t *testing.T) {
	compatibilitySyntax(t)
	inst, _ := boundaryFixture(t)
	event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": "Bash", "tool_input": map[string]any{"command": "laneboss decisions init --db " + filepath.Join(inst.worktree, "new.sqlite")}}
	allowed, reason, err := decide(event, "claude", filepath.Join(inst.directory, "instance.toml"))
	if err != nil || !allowed {
		t.Fatalf("plain unannotated call must allow: %q %v", reason, err)
	}
	if err := recordCallback(event, "claude", filepath.Join(inst.directory, "instance.toml"), allowed, reason, nil); err != nil {
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
	if receipt["inspection_complete"] != false || receipt["inspection_notice"] == nil {
		t.Fatalf("unannotated calls must retain an incomplete receipt: %s", data)
	}
	tools, err := DelegableTools("", "", nil, []string{"Write"}, []string{"Read", "Write", "Other"})
	if err != nil || !reflect.DeepEqual(tools, []string{"Read", "Other"}) {
		t.Fatalf("only explicit denies restrict delegable tools: %v %v", tools, err)
	}
}
