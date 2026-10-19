package orghook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/config"
)

func legacyScopeFixture(t *testing.T, level int) (*instance, string) {
	t.Helper()
	inst, root := boundaryFixture(t)
	files := map[string]string{
		filepath.Join(inst.home, "org.toml"):                               "name = \"legacy\"\nlevels = [3, 4, 5, 6]\n",
		filepath.Join(inst.directory, "instance.toml"):                     fmt.Sprintf("name = \"executor\"\nlevel = %d\nrole = \"executor\"\nwritable_repos = [%q]\nallowed_tools = []\nsecret_names = []\n", level, inst.worktree),
		filepath.Join(inst.home, "shared", "hooks", "rules.toml"):          "schema_version = 1\n[[rules]]\nid = \"scope-check\"\nkind = \"write-scope\"\npaths = [\"{writable_repos}\"]\ndeny_paths = [\"{hook_paths}\"]\n",
		filepath.Join(inst.home, "shared", "refusals", "scope-check.toml"): "id = \"scope-check\"\nrefuses = \"Outside declared scope.\"\nwhy = \"Keep declared writes scoped.\"\ninstead = \"Use the declared workspace.\"\nexamples_allowed = []\nexamples_refused = []\n[applies_to]\nlevels = [3, 4]\nidentities = [\"*\"]\n",
	}
	if level != inst.level {
		files[filepath.Join(inst.home, fmt.Sprintf("L%d", level), "hooks", "rules.toml")] = "schema_version = 1\nrules = []\n"
	}
	for path, data := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	inst, err := loadInstance(inst.directory)
	if err != nil {
		t.Fatal(err)
	}
	return inst, root
}

func compatibilitySyntax(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "cli", "syntax.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := SetLanebossSyntax(data); err != nil {
		t.Fatal(err)
	}
}

func compatibilityDecision(t *testing.T, inst *instance, runner, text string, options map[string]any) (bool, string, error) {
	t.Helper()
	tool, field := "Bash", "command"
	if runner == "codex" {
		tool, field = "exec_command", "cmd"
	}
	input := map[string]any{field: text}
	for key, value := range options {
		input[key] = value
	}
	event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": input}
	return decide(event, runner, filepath.Join(inst.directory, "instance.toml"))
}

func incompleteCompatibilityReceipt(t *testing.T, inst *instance, runner, text string) {
	t.Helper()
	tool, field := "Bash", "command"
	if runner == "codex" {
		tool, field = "exec_command", "cmd"
	}
	event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool,
		"tool_input": map[string]any{field: text}}
	incompleteEventReceipt(t, inst, runner, event)
}

func incompleteEventReceipt(t *testing.T, inst *instance, runner string, event map[string]any) {
	t.Helper()
	pinned := filepath.Join(inst.directory, "instance.toml")
	path := filepath.Join(inst.directory, "hooks", "callbacks.jsonl")
	before, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	allowed, reason, err := decide(event, runner, pinned)
	if err != nil || !allowed || reason != "org policy permits this tool call" {
		t.Fatalf("ordinary observation gaps must allow: allow=%v reason=%q err=%v", allowed, reason, err)
	}
	if err := recordCallback(event, runner, pinned, allowed, reason, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= len(before) || !strings.HasPrefix(string(data), string(before)) {
		t.Fatal("each ordinary gap must append a fresh receipt and preserve earlier callbacks")
	}
	var receipt map[string]any
	if err := json.Unmarshal(data[len(before):], &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["decision"] != "allow" || receipt["runner"] != runner || receipt["inspection_complete"] != false || receipt["inspection_notice"] != "file effects were not fully inspected; blacklist mode allowed the call" {
		t.Fatalf("ordinary gaps must retain an incomplete-inspection receipt and notice: %v", receipt)
	}
}

func TestLegacyLevelFourScope(t *testing.T) {
	inst, root := legacyScopeFixture(t, 4)
	for _, runner := range []string{"claude", "codex"} {
		allowed, reason, err := compatibilityDecision(t, inst, runner, "touch "+filepath.Join(root, "outside"), nil)
		if err != nil || !allowed {
			t.Fatalf("a legacy write allowlist must not restrict L4 writes: allow=%v reason=%q err=%v", allowed, reason, err)
		}
		allowed, reason, err = compatibilityDecision(t, inst, runner, "touch "+filepath.Join(inst.worktree, "inside"), nil)
		if err != nil || !allowed {
			t.Fatalf("an inside L4 write must remain allowed: %q %v", reason, err)
		}
	}
}

func TestLegacyZshClobberReceipt(t *testing.T) {
	inst, _ := legacyScopeFixture(t, 3)
	for _, runner := range []string{"claude", "codex"} {
		for _, form := range []string{">!", ">>!", "&>!", ">&!", ">! "} {
			for _, prefix := range []string{"", "true && "} {
				incompleteCompatibilityReceipt(t, inst, runner, prefix+"printf x "+form+filepath.Join(inst.worktree, "ordinary"))
			}
		}
		allowed, reason, err := compatibilityDecision(t, inst, runner, "printf x > "+filepath.Join(inst.worktree, "inside"), nil)
		if err != nil || !allowed {
			t.Fatalf("the ordinary redirect control must allow: %q %v", reason, err)
		}
	}
}

func TestLegacyWrapperVariable(t *testing.T) {
	inst, _ := legacyScopeFixture(t, 3)
	for _, runner := range []string{"claude", "codex"} {
		incompleteCompatibilityReceipt(t, inst, runner, "env -u \"$UNRESOLVED\" git status")
		allowed, reason, err := compatibilityDecision(t, inst, runner, "env -u UNUSED_FIXTURE git status", nil)
		if err != nil || !allowed {
			t.Fatalf("the literal wrapper value must allow: %q %v", reason, err)
		}
	}
}

func TestOrdinaryR26ObservationGaps(t *testing.T) {
	compatibilitySyntax(t)
	inst, _ := legacyScopeFixture(t, 3)
	for _, runner := range []string{"claude", "codex"} {
		t.Run(runner, func(t *testing.T) {
			for _, text := range []string{
				"npm test $ARGS > " + filepath.Join(inst.worktree, "test.log"),
				"sh -c \"$(cat <<'EOF'\nprintf ordinary-work\nEOF\n)\"",
			} {
				// Restoring the removed generic substitution refusal must fail here.
				incompleteCompatibilityReceipt(t, inst, runner, text)
			}
			for _, text := range []string{
				"laneboss status --config boundary $ARGS",
				"laneboss report --config boundary --file \"$(cat <<'EOF'\nmessage.md\nEOF\n)\"",
			} {
				allowed, _, err := compatibilityDecision(t, inst, runner, text, nil)
				if allowed || err == nil || !strings.Contains(err.Error(), "substitutions and variables") {
					t.Fatalf("obscured Laneboss calls must refuse: allow=%v err=%v", allowed, err)
				}
			}
		})
	}
}

func TestLanebossUninspectedShellCode(t *testing.T) {
	compatibilitySyntax(t)
	inst, _ := legacyScopeFixture(t, 3)
	refused := []string{
		"sh -c 'laneboss status $ARGS'",
		"eval \"laneboss lane start $X\"",
		"bash -c \"cd d && laneboss report $F\"",
		"sh -c './bin/laneboss status $A'",
		"echo \"$(laneboss status $ARGS)\"",
		"echo `laneboss status $ARGS`",
		"echo \"$((1 + $(laneboss status $ARGS)))\"",
		"sh -c 'env FIXTURE=1 command exec /opt/tools/laneboss status $ARGS'",
		"sh -c 'if true; then laneboss status $ARGS; fi'",
		"sh -c 'git commit -F - <<EOF\nlaneboss $MESSAGE\nEOF\nlaneboss status $ARGS'",
	}
	for _, separator := range []string{";", "&&", "||", "|", "\n", "("} {
		body := "printf ordinary " + separator + " command ./tools/laneboss status $ARGS"
		if separator == "(" {
			body += ")"
		}
		refused = append(refused, "sh -c '"+body+"'")
	}
	allowed := []string{
		"git commit -m \"fix laneboss $X\"",
		"echo \"laneboss $V\" > notes.txt",
		"git commit -F - <<EOF\nlaneboss $X\nEOF\n",
		"sh -c 'echo laneboss $X'",
		"git commit -m \"fix; laneboss $X\"",
		"git commit -m \"fix sh -c 'laneboss $X'\"",
		"git commit -m '{' laneboss \"$X\"",
		"git commit -m \"first line\nlaneboss $X\nlast line\"",
		"echo '$(laneboss status)' \"$MESSAGE\"",
		"echo \"\\$(laneboss $X)\"",
		"sh -c 'git commit -F - <<EOF\nlaneboss $X\nEOF\n'",
		"git commit -F - <<-'MESSAGE'\n\tlaneboss $X\n\tMESSAGE\n",
		"git commit -F - <<MESSAGE\n$(laneboss $X)\nMESSAGE\n",
		"git commit -F - <<''\nlaneboss $X\n\n",
		"echo \"$(printf laneboss $X)\"",
		"echo `printf laneboss $X`",
		"echo \"$X\" # laneboss status $ARGS",
		"echo \"$((laneboss + COUNTER))\"",
	}
	for _, runner := range []string{"claude", "codex"} {
		t.Run(runner, func(t *testing.T) {
			oversized := "laneboss status " + strings.Repeat("x", maxCommand)
			if allow, _, err := compatibilityDecision(t, inst, runner, oversized, nil); allow || err == nil {
				t.Fatal("an oversized direct Laneboss call must retain its inspection refusal")
			}
			for index, text := range refused {
				t.Run(fmt.Sprintf("code-%d", index), func(t *testing.T) {
					allowed, _, err := compatibilityDecision(t, inst, runner, text, nil)
					if allowed || err == nil || !strings.Contains(err.Error(), "substitutions and variables") {
						t.Fatalf("a Laneboss command inside uninspected code must retain its refusal: allow=%v err=%v", allowed, err)
					}
				})
			}
			for index, text := range allowed {
				t.Run(fmt.Sprintf("data-%d", index), func(t *testing.T) {
					incompleteCompatibilityReceipt(t, inst, runner, text)
				})
			}
		})
	}
}

func TestObscuredShellInspectionLimits(t *testing.T) {
	inst, _ := legacyScopeFixture(t, 3)
	for _, runner := range []string{"claude", "codex"} {
		t.Run(runner, func(t *testing.T) {
			for _, count := range []int{33, 40} {
				for _, row := range []struct{ body, detail string }{
					{"laneboss decisions export --out /outside/x $Y", "substitutions and variables"},
					{"echo hi", obscuredShellDepthReason},
				} {
					t.Run(fmt.Sprintf("eval-%d/%s", count, strings.Fields(row.body)[0]), func(t *testing.T) {
						text := strings.Repeat("eval ", count) + row.body
						allowed, _, err := compatibilityDecision(t, inst, runner, text, nil)
						if allowed || err == nil || !strings.Contains(err.Error(), row.detail) {
							t.Fatalf("deep obscured shell code must refuse: allow=%v err=%v", allowed, err)
						}
					})
				}
			}
			for name, text := range map[string]string{
				"nul":           "eval 'echo hi\x00'",
				"budget":        strings.Repeat(" ", 4*maxCommand) + "echo hi $X",
				"unclosed-code": "sh -c 'echo \"$X'",
				"unclosed-doc":  "git commit -F - <<EOF\nmessage $X\n",
				"unclosed-sub":  "echo \"$(cat <<EOF)\"",
				"compound-eval": "true && " + strings.Repeat("eval ", 33) + "echo hi",
			} {
				t.Run(name, func(t *testing.T) {
					allowed, _, err := compatibilityDecision(t, inst, runner, text, nil)
					if allowed || err == nil {
						t.Fatalf("an unfinished obscured-shell scan must refuse: allow=%v err=%v", allowed, err)
					}
				})
			}
			incompleteCompatibilityReceipt(t, inst, runner, strings.Repeat("eval ", 5)+"echo hi $X")
		})
	}
}

func TestNohupRunnerParity(t *testing.T) {
	const boundary = "refused: lanes may not detach their process identity with setsid or nohup\nInstead: report up with laneboss report, or use lane send for a permitted peer."
	for _, level := range []int{3, 4} {
		t.Run(fmt.Sprintf("L%d", level), func(t *testing.T) {
			inst, _ := legacyScopeFixture(t, level)
			for _, runner := range []string{"claude", "codex"} {
				tool, field := "Bash", "command"
				if runner == "codex" {
					tool, field = "exec_command", "cmd"
				}
				for _, row := range []struct {
					name, text, detail string
					argv               []string
					laneboss           bool
				}{
					{"plain", "nohup touch ordinary.txt", "output files cannot be inspected", []string{"nohup", "touch", "ordinary.txt"}, false},
					{"variable", "nohup git status \"$WRAPPER_VALUE\"", "substitutions and variables", []string{"nohup", "git", "status", "$WRAPPER_VALUE"}, false},
					{"plain-laneboss", "nohup laneboss status", "output files cannot be inspected", []string{"nohup", "laneboss", "status"}, true},
					{"variable-laneboss", "nohup laneboss status \"$WRAPPER_VALUE\"", "substitutions and variables", []string{"nohup", "laneboss", "status", "$WRAPPER_VALUE"}, true},
				} {
					for _, adapter := range []string{"string", "argv"} {
						value := any(row.text)
						if adapter == "argv" {
							value = row.argv
						}
						inputs := []any{map[string]any{field: value}}
						if runner == "codex" {
							encoded, err := json.Marshal(inputs[0])
							if err != nil {
								t.Fatal(err)
							}
							inputs = append(inputs, string(encoded))
						}
						for index, input := range inputs {
							t.Run(fmt.Sprintf("%s/%s/%s/input-%d", runner, row.name, adapter, index), func(t *testing.T) {
								event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": input}
								_, err := eventAction(event, runner, inst.worktree)
								if !isObservationGap(err) || !strings.Contains(err.Error(), row.detail) {
									t.Fatalf("both runners must classify the ordinary nohup form as an observation gap: %v", err)
								}
								if row.laneboss {
									allowed, _, err := decide(event, runner, filepath.Join(inst.directory, "instance.toml"))
									if allowed || !isObservationGap(err) || !strings.Contains(err.Error(), row.detail) {
										t.Fatalf("a Laneboss gap must still refuse for both runners: allow=%v err=%v", allowed, err)
									}
									return
								}
								if level == 4 {
									incompleteEventReceipt(t, inst, runner, event)
									return
								}
								allowed, reason, err := decide(event, runner, filepath.Join(inst.directory, "instance.toml"))
								if err != nil || allowed || reason != boundary {
									t.Fatalf("the retained L3 identity boundary must speak for both runners: allow=%v reason=%q err=%v", allowed, reason, err)
								}
							})
						}
					}
				}
			}
		})
	}
}

func TestLanebossShellGuardGaps(t *testing.T) {
	compatibilitySyntax(t)
	inst, _, worktree := authenticatedLaneFixture(t)
	inst.worktree = worktree
	input := filepath.Join(worktree, "message.md")
	if err := os.WriteFile(input, []byte("harmless fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plain := "laneboss report --config boundary --file " + input
	configuration, err := config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		for _, row := range []struct {
			text, detail string
			allowed      bool
		}{
			{plain + " --unknown-output output", "no file-effects adapter", false},
			// Mutant: drop clean's annotation; the hook allow turns red. The E2E
			// test_supervisor_delegation_hook retains the L3 CLI refusal.
			{"laneboss lane clean --config boundary --lane executor", "", true},
			{"nohup " + plain, "output files cannot be inspected", false},
			{"env -C /tmp " + plain, "changes execution context", false},
			{"env FIXTURE=1 " + plain, "environment assignments", false},
			{"FIXTURE=1 " + plain, "environment assignments", false},
			{"nice -n \"$(printf canary)\" " + plain, "substitutions and variables", false},
			{"laneboss report --config boundary --file \"$UNRESOLVED\"", "substitutions and variables", false},
			{plain + " >! " + filepath.Join(worktree, "output.log"), "zsh clobber redirection", false},
		} {
			allowed, reason, err := compatibilityDecision(t, inst, runner, row.text, nil)
			if row.allowed {
				if err != nil || !allowed {
					t.Fatalf("the literal clean must reach CLI authority checks: allow=%v reason=%q err=%v", allowed, reason, err)
				}
				cmd, err := lanebossCommand(strings.Fields(row.text), worktree)
				if err != nil || cmd.opaque || cmd.stateRoot != configuration.StateDir || len(cmd.stateWrites) != 1 || cmd.stateWrites[0] != configuration.StateDir || len(cmd.writes) != 0 {
					t.Fatalf("clean must declare exactly the checked state effect: %+v err=%v", cmd, err)
				}
				continue
			}
			if allowed || err == nil || !strings.Contains(err.Error(), row.detail) {
				t.Fatalf("the CLI shell guard must retain %q: allow=%v err=%v", row.detail, allowed, err)
			}
		}
		allowed, _, err := compatibilityDecision(t, inst, runner, plain, map[string]any{"env": map[string]any{"FIXTURE": "1"}})
		if allowed || err == nil || !strings.Contains(err.Error(), "environment overrides") {
			t.Fatalf("the CLI tool override must deny: allow=%v err=%v", allowed, err)
		}
		allowed, reason, err := compatibilityDecision(t, inst, runner, plain, nil)
		if err != nil || !allowed {
			t.Fatalf("the validated CLI control must allow: %q %v", reason, err)
		}
	}
}

func TestBlacklistLanebossReadAdapter(t *testing.T) {
	compatibilitySyntax(t)
	inst, _, worktree := authenticatedLaneFixture(t)
	inst.worktree = worktree
	configuration, err := config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		allowed, reason, err := compatibilityDecision(t, inst, runner, "laneboss state events --config "+configuration.Name, nil)
		if err != nil || !allowed || reason != "org policy permits this tool call" {
			t.Fatalf("the validated blacklist read adapter must allow from the worktree: allow=%v reason=%q err=%v", allowed, reason, err)
		}
		allowed, reason, err = compatibilityDecision(t, inst, runner, "laneboss state lanes --config "+configuration.Name, nil)
		if err != nil || !allowed {
			t.Fatalf("the reviewed state lanes view must allow: allow=%v reason=%q err=%v", allowed, reason, err)
		}
		allowed, reason, err = compatibilityDecision(t, inst, runner, "laneboss state rebuild --config "+configuration.Name, nil)
		if err != nil || !allowed {
			t.Fatalf("a plainly written unannotated verb must reach CLI authority: allow=%v reason=%q err=%v", allowed, reason, err)
		}
	}
}

func TestLegacyLanebossExternalEffects(t *testing.T) {
	compatibilitySyntax(t)
	inst, root, worktree := authenticatedLaneFixture(t)
	inst.worktree = worktree
	if err := os.WriteFile(filepath.Join(inst.home, "org.toml"), []byte("name = \"legacy\"\nlevels = [3, 4, 5, 6]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configuration, err := config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configuration.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\n[owner_channels.fixture]\nkind = \"file\"\npath = \"owner/queue.jsonl\"\n")...)
	if err := os.WriteFile(configuration.ConfigFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadInstance(inst.directory)
	if err != nil || loaded.hookMode != "blacklist" {
		t.Fatalf("the unversioned org must use blacklist semantics: %v", err)
	}
	input := filepath.Join(worktree, "message.md")
	if err := os.WriteFile(input, []byte("external-effects fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		text := "laneboss decisions stats --db " + filepath.Join(root, "outside.sqlite")
		allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
		if err != nil || allowed || reason != worktreeBoundaryReason {
			t.Fatalf("legacy sources must retain the worktree boundary for external CLI effects: allow=%v reason=%q err=%v", allowed, reason, err)
		}
		allowed, reason, err = compatibilityDecision(t, inst, runner, "laneboss report --config "+configuration.Name+" --file "+input, nil)
		if err != nil || !allowed {
			t.Fatalf("file owner channels use checked state, not external writes: %q %v", reason, err)
		}
		allowed, reason, err = compatibilityDecision(t, inst, runner, "laneboss decisions stats --db "+filepath.Join(worktree, "inside.sqlite"), nil)
		if err != nil || !allowed {
			t.Fatalf("a database inside the recorded worktree must remain allowed: %q %v", reason, err)
		}
	}
}

func TestLegacyManagedStateScope(t *testing.T) {
	compatibilitySyntax(t)
	inst, _, worktree := authenticatedLaneFixture(t)
	inst.worktree = worktree
	files := [][2]string{
		{filepath.Join(inst.home, "org.toml"), "name = \"legacy\"\nlevels = [3, 4, 5, 6]\n"},
		{filepath.Join(inst.home, "shared", "hooks", "rules.toml"), "schema_version = 1\n[[rules]]\nid = \"declared-writes\"\nkind = \"write-scope\"\npaths = []\ndeny_paths = [\"{hook_paths}\"]\n"},
		{filepath.Join(inst.home, "shared", "refusals", "declared-writes.toml"), "id = \"declared-writes\"\nrefuses = \"Only checked state writes.\"\nwhy = \"Keep the installed scope.\"\ninstead = \"Use the checked CLI.\"\nexamples_allowed = []\nexamples_refused = []\n[applies_to]\nlevels = [3]\nidentities = [\"*\"]\n"},
	}
	for _, file := range files {
		if err := os.MkdirAll(filepath.Dir(file[0]), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file[0], []byte(file[1]), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configuration, err := config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		allowed, reason, err := compatibilityDecision(t, inst, runner, "laneboss report --config "+configuration.Name+" --file -", nil)
		if err != nil || !allowed {
			t.Fatalf("legacy sources must permit the managed state adapter: %q %v", reason, err)
		}
		for _, text := range []string{
			"touch " + filepath.Join(worktree, "ordinary"),
			"printf x > " + filepath.Join(configuration.StateDir, "direct"),
		} {
			allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
			protected := strings.Contains(text, configuration.StateDir)
			if err != nil || allowed == protected || protected && !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
				t.Fatalf("legacy write allowlists are ignored while direct state writes stay protected: allow=%v reason=%q err=%v", allowed, reason, err)
			}
		}
	}
}

func TestLegacyToolAllowlistsIgnored(t *testing.T) {
	inst, _ := legacyScopeFixture(t, 3)
	data, err := os.ReadFile(filepath.Join(inst.home, "shared", "hooks", "rules.toml"))
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\n[[rules]]\nid = \"legacy-tools\"\nkind = \"tool-allowlist\"\ntools = [\"Read\"]\n")...)
	if err := os.WriteFile(filepath.Join(inst.home, "shared", "hooks", "rules.toml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	refusal := "id = \"legacy-tools\"\nrefuses = \"Unlisted tool.\"\nwhy = \"Owner grants are narrowed.\"\ninstead = \"Use Read.\"\nexamples_allowed = []\nexamples_refused = []\n[applies_to]\nlevels = [3]\nidentities = [\"*\"]\n"
	if err := os.WriteFile(filepath.Join(inst.home, "shared", "refusals", "legacy-tools.toml"), []byte(refusal), 0600); err != nil {
		t.Fatal(err)
	}
	for _, names := range []string{"[\"Read\", \"Write\"]", "[\"Read\"]"} {
		if err := os.WriteFile(filepath.Join(inst.home, "settings.toml"), []byte("tool_allow_add = "+names+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, runner := range []string{"claude", "codex"} {
			event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": "Write",
				"tool_input": map[string]any{"file_path": filepath.Join(inst.worktree, "grant.txt")}}
			allowed, reason, err := decide(event, runner, filepath.Join(inst.directory, "instance.toml"))
			// Mutant: restore tool-allowlist enforcement; the Read-only row fails.
			if err != nil || !allowed {
				t.Fatalf("recorded tool additions and legacy allowlists must not gate tools: allow=%v reason=%q err=%v", allowed, reason, err)
			}
		}
	}
}

func TestManagedHookPathConversion(t *testing.T) {
	inst, _, _ := authenticatedLaneFixture(t)
	configuration, err := config.Load("boundary")
	if err != nil {
		t.Fatal(err)
	}
	state := configuration.StateDir
	scopeRule := rule{data: map[string]any{"id": "state-check", "kind": "write-scope", "paths": []string{}, "deny_paths": []string{"{hook_paths}", state}}, refusal: map[string]any{"refuses": "State scope.", "instead": "Use checked CLI."}}
	rows, err := legacyBlacklistRows([]rule{scopeRule}, inst)
	if err != nil {
		t.Fatal(err)
	}
	managed := fileEffect{word: state, directory: "/", managed: true, managedRoot: state}
	checked := false
	for _, row := range rows {
		if len(row.pathRoots) != 1 || row.pathRoots[0] != state {
			continue
		}
		checked = true
		matched, err := blacklistMatches(row, inst, action{}, []fileEffect{managed}, nil, nil, nil, "/")
		if err != nil {
			t.Fatal(err)
		}
		if row.hookPaths && matched {
			t.Fatalf("the generated hook inventory must exempt only the managed state root: matched=%v", matched)
		}
		if !row.hookPaths && !matched {
			t.Fatalf("an explicit state deny must still match a managed effect")
		}
		ordinary := fileEffect{word: filepath.Join(state, "direct"), directory: "/"}
		matched, err = blacklistMatches(row, inst, action{}, []fileEffect{ordinary}, nil, nil, nil, "/")
		if err != nil || !matched {
			t.Fatalf("a shell state redirect must remain denied: matched=%v err=%v", matched, err)
		}
	}
	if !checked {
		t.Fatal("the fixture must contribute a state deny root")
	}
}

func TestHookModeCompatibility(t *testing.T) {
	inst, _ := boundaryFixture(t)
	for _, row := range []struct{ source, mode string }{
		{"name = \"legacy\"\n", "blacklist"},
		{"schema_version = 1\nname = \"modern\"\n", "blacklist"},
		{"name = \"legacy\"\n[hooks]\nmode = \"blacklist\"\n", "blacklist"},
		{"schema_version = 1\nname = \"legacy-strict\"\n[hooks]\nmode = \"strict\"\n", "blacklist"},
	} {
		if err := os.WriteFile(filepath.Join(inst.home, "org.toml"), []byte(row.source), 0600); err != nil {
			t.Fatal(err)
		}
		policy, err := parseHookBlacklist(inst.home)
		if err != nil || policy.mode != row.mode {
			t.Fatalf("mode compatibility must use source schema and selection: got=%q want=%q err=%v", policy.mode, row.mode, err)
		}
	}
}
