package orghook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/config"
)

func TestSymlinkedProtectedState(t *testing.T) {
	inst, root, worktree := authenticatedLaneFixture(t)
	inst.worktree = worktree
	alias := filepath.Join(root, "state-alias")
	if err := os.Symlink(filepath.Join(root, "state"), alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEBOSS_STATE_HOME", alias)
	configuration, err := config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{filepath.Join(configuration.StateDir, "direct"), filepath.Join(root, "state", "boundary", "direct")} {
		// Mutant: compare unresolved protected roots with physical write targets.
		event := map[string]any{"hook_event_name": "PreToolUse", "cwd": worktree, "tool_name": "Write", "tool_input": map[string]any{"file_path": target}}
		allowed, reason, err := decide(event, "claude", filepath.Join(inst.directory, "instance.toml"))
		if err != nil || allowed || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
			t.Fatalf("state aliases must retain the protected-file reason: allow=%v reason=%q err=%v", allowed, reason, err)
		}
	}
	allowed, reason, err := compatibilityDecision(t, inst, "claude", "touch "+filepath.Join(worktree, "ordinary"), nil)
	if err != nil || !allowed {
		t.Fatalf("the ordinary-worktree control must allow: %q %v", reason, err)
	}
	// A missing state root still resolves through the same existing alias.
	t.Setenv("LANEBOSS_STATE_HOME", filepath.Join(alias, "not-created"))
	configuration, err = config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	physical := filepath.Join(root, "state", "not-created", "boundary", "direct")
	reason, err = builtInWriteRefusal(inst, []fileEffect{{word: physical, directory: worktree}})
	if err != nil || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
		t.Fatalf("a missing root below an alias must remain protected: %q %v", reason, err)
	}
}

func TestGrammarPathInventory(t *testing.T) {
	compatibilitySyntax(t)
	checkGrammarPathGolden(t)
	inst, _, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	files := map[string]string{
		filepath.Join(worktree, "ordinary.txt"):                                 "ordinary input\n",
		filepath.Join(worktree, "classified.txt"):                               "harmless secret-name canary\n",
		filepath.Join(inst.home, "shared", "hooks", "rules.toml"):               "schema_version = 1\n[[rules]]\nid = \"inventory-secret\"\nkind = \"secret-read\"\nnames = [\"classified.txt\"]\n",
		filepath.Join(inst.home, "shared", "refusals", "inventory-secret.toml"): "id = \"inventory-secret\"\nrefuses = \"Protected inventory input.\"\nwhy = \"Keep secret reads denied.\"\ninstead = \"Use ordinary input.\"\nexamples_allowed = []\nexamples_refused = []\n[applies_to]\nlevels = [4]\nidentities = [\"*\"]\n",
	}
	for path, data := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var walk func(*hookSyntax, []string)
	walk = func(node *hookSyntax, path []string) {
		for _, argument := range node.Args {
			if argument.Path == nil {
				continue
			}
			for _, runner := range []string{"claude", "codex"} {
				t.Run(runner+"/"+strings.Join(path, "-")+"/"+argument.Name, func(t *testing.T) {
					ordinary := hookArgsForPath(node, path, worktree, argument.Name, filepath.Join(worktree, "ordinary.txt"))
					allowed, reason, err := compatibilityDecision(t, inst, runner, "laneboss "+strings.Join(ordinary, " "), nil)
					if err != nil || !allowed {
						t.Fatalf("ordinary path control must allow: %q %v", reason, err)
					}
					if argument.Path.Write {
						// Mutant: omit any grammar-declared write effect.
						target := filepath.Join(inst.home, "hooks", "inventory-output")
						args := hookArgsForPath(node, path, worktree, argument.Name, target)
						cmd, err := lanebossCommand(append([]string{"laneboss"}, args...), worktree)
						if err != nil || !contains(cmd.writes, target) {
							t.Fatalf("the declared write must be recorded independently of the raw backstop: writes=%v err=%v", cmd.writes, err)
						}
						allowed, reason, err := compatibilityDecision(t, inst, runner, "laneboss "+strings.Join(args, " "), nil)
						if err != nil || allowed || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
							t.Fatalf("declared protected write must refuse: allow=%v reason=%q err=%v", allowed, reason, err)
						}
					}
					if argument.Path.Read || argument.Path.Metadata {
						// Mutant: omit a read, named-file extraction or metadata effect.
						target := filepath.Join(worktree, "classified.txt")
						args := hookArgsForPath(node, path, worktree, argument.Name, target)
						cmd, err := lanebossCommand(append([]string{"laneboss"}, args...), worktree)
						if err != nil || argument.Path.Read && !contains(cmd.reads, target) || argument.Path.Metadata && !contains(cmd.metadata, target) {
							t.Fatalf("the declared read must record its actual path: reads=%v metadata=%v err=%v", cmd.reads, cmd.metadata, err)
						}
						allowed, reason, err := compatibilityDecision(t, inst, runner, "laneboss "+strings.Join(args, " "), nil)
						if err != nil || allowed || !strings.HasPrefix(reason, "[inventory-secret] Refuses:") {
							t.Fatalf("declared secret read must retain its row: allow=%v reason=%q err=%v", allowed, reason, err)
						}
					}
				})
			}
		}
		for index := range node.Commands {
			child := &node.Commands[index]
			walk(child, append(append([]string{}, path...), child.Name))
		}
	}
	walk(lanebossSyntax.root, nil)
}

func TestDelegableToolsBoundPolicyIntegrity(t *testing.T) {
	inst, root := boundaryFixture(t)
	if err := os.WriteFile(filepath.Join(inst.home, "shared", "hooks", "rules.toml"), []byte("not valid TOML ["), 0600); err != nil {
		t.Fatal(err)
	}
	// Mutant: skip loadRules for a bound instance and return candidate tools.
	tools, err := DelegableTools(root, inst.name, nil, nil, []string{"Read"})
	if err == nil || tools != nil || !strings.Contains(err.Error(), "TOML") {
		t.Fatalf("bound malformed policy must return its integrity error: tools=%v err=%v", tools, err)
	}
}
