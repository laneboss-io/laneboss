package orghook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteralWriteClass(t *testing.T) {
	rows := []struct {
		name       string
		directory  bool
		incomplete bool
		command    func(string, string) string
	}{
		{"find-delete", true, true, func(p, _ string) string { return "find " + shellQuote(p) + " -name '*.tmp' -delete" }},
		{"find-exec", true, true, func(p, _ string) string { return "find " + shellQuote(p) + " -exec rm {} +" }},
		{"find-execdir", true, true, func(p, _ string) string { return "find " + shellQuote(p) + " -execdir printf x \\;" }},
		{"find-ok", true, true, func(p, _ string) string { return "find " + shellQuote(p) + " -ok rm {} \\;" }},
		{"find-okdir", true, true, func(p, _ string) string { return "find " + shellQuote(p) + " -okdir rm {} \\;" }},
		{"find-fprint", false, true, func(p, _ string) string { return "find . -fprint " + shellQuote(p) }},
		{"find-root-output", true, true, func(p, _ string) string { return "find . -fprint " + shellQuote(filepath.Join(p, "x")) }},
		{"find-fprint0", false, true, func(p, _ string) string { return "find . -fprint0 " + shellQuote(p) }},
		{"find-fls", false, true, func(p, _ string) string { return "find . -fls " + shellQuote(p) }},
		{"find-fprintf", false, true, func(p, _ string) string { return "find . -fprintf " + shellQuote(p) + " '%p\\n'" }},
		{"rsync-delete", true, true, func(p, _ string) string { return "rsync --delete source/ " + shellQuote(p) }},
		{"rsync-copy", true, true, func(p, _ string) string { return "rsync source/ " + shellQuote(p) }},
		{"tar-stdin", true, true, func(p, _ string) string { return "tar -x -C " + shellQuote(p) }},
		{"tar-file", true, true, func(p, _ string) string { return "tar -xf a.tar -C " + shellQuote(p) }},
		{"sed-inplace", false, true, func(p, _ string) string { return "sed -i 's/a/b/' " + shellQuote(p) }},
		{"dd", false, false, func(p, _ string) string { return "dd of=" + shellQuote(p) }},
		{"truncate", false, false, func(p, _ string) string { return "truncate -s 0 " + shellQuote(p) }},
		{"ln", false, true, func(p, _ string) string { return "ln -sf target " + shellQuote(p) }},
		{"chmod", true, false, func(p, _ string) string { return "chmod -R 700 " + shellQuote(p) }},
		{"chown", true, false, func(p, _ string) string { return "chown -R fixture " + shellQuote(p) }},
		{"git-clean", true, false, func(p, _ string) string { return "git -C " + shellQuote(p) + " clean -fdx" }},
		{"git-checkout", true, false, func(p, _ string) string { return "git -C " + shellQuote(p) + " checkout -- ." }},
		{"git-reset", true, false, func(p, _ string) string { return "git -C " + shellQuote(p) + " reset --hard" }},
		{"xargs-pipe", false, true, func(p, _ string) string { return "printf " + shellQuote(p+"\\n") + " | xargs rm" }},
		{"xargs-pipe-root", true, true, func(p, _ string) string { return "printf " + shellQuote(p+"\\n") + " | xargs rm -r" }},
		{"xargs-format", false, true, func(p, _ string) string { return "printf '%s\\n' " + shellQuote(p) + " | xargs rm" }},
		{"xargs-many", true, true, func(p, _ string) string { return "printf '%s\\n' harmless " + shellQuote(p) + " | xargs rm -r" }},
		{"xargs-file", false, true, func(_, list string) string { return "xargs -a " + shellQuote(list) + " rm" }},
		{"install", true, true, func(p, _ string) string { return "install -t " + shellQuote(p) + " source" }},
	}
	inst, _ := legacyScopeFixture(t, 4)
	for _, runner := range []string{"claude", "codex"} {
		for _, row := range rows {
			for _, rawGap := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/raw-%v", runner, row.name, rawGap), func(t *testing.T) {
					for _, protected := range []bool{true, false} {
						target := inst.home
						if !protected {
							target = inst.worktree
						}
						if !row.directory {
							if protected {
								target = filepath.Join(target, "org.toml")
							} else {
								target = filepath.Join(target, "ordinary.txt")
							}
						}
						list := filepath.Join(inst.worktree, "arguments.txt")
						if err := os.WriteFile(list, []byte(target+"\n"), 0600); err != nil {
							t.Fatal(err)
						}
						text := row.command(target, list)
						tool, field := "Bash", "command"
						if runner == "codex" {
							tool, field = "exec_command", "cmd"
						}
						input := map[string]any{field: text}
						if rawGap {
							input["env"] = map[string]any{"WRITE_FIXTURE": "literal"}
						}
						event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": input}
						pinned := filepath.Join(inst.directory, "instance.toml")
						allowed, reason, err := decide(event, runner, pinned)
						if protected {
							if err != nil || allowed || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
								t.Fatalf("literal protected write must refuse: allow=%v reason=%q err=%v", allowed, reason, err)
							}
							continue
						}
						if err != nil || !allowed || reason != "org policy permits this tool call" {
							t.Fatalf("ordinary L4 worktree control must allow: allow=%v reason=%q err=%v", allowed, reason, err)
						}
						if row.incomplete || rawGap {
							incompleteEventReceipt(t, inst, runner, event)
						} else {
							if err := recordCallback(event, runner, pinned, allowed, reason, nil); err != nil {
								t.Fatal(err)
							}
							data, err := os.ReadFile(filepath.Join(inst.directory, "hooks", "callbacks.jsonl"))
							if err != nil {
								t.Fatal(err)
							}
							lines := strings.Split(strings.TrimSpace(string(data)), "\n")
							var receipt map[string]any
							if err := json.Unmarshal([]byte(lines[len(lines)-1]), &receipt); err != nil {
								t.Fatal(err)
							}
							if receipt["inspection_complete"] != true || receipt["decision"] != "allow" {
								t.Fatalf("supported literal control must retain complete inspection: %v", receipt)
							}
						}
					}
				})
			}
		}
	}
	lane, root := legacyScopeFixture(t, 3)
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		for _, row := range rows {
			t.Run(runner+"/L3-outside/"+row.name, func(t *testing.T) {
				target := outside
				if !row.directory {
					target = filepath.Join(outside, "ordinary.txt")
				}
				list := filepath.Join(lane.worktree, "arguments.txt")
				if err := os.WriteFile(list, []byte(target+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				allowed, reason, err := compatibilityDecision(t, lane, runner, row.command(target, list), nil)
				if err != nil || allowed || reason != worktreeBoundaryReason {
					t.Fatalf("literal effects must reach the L3 boundary: allow=%v reason=%q err=%v", allowed, reason, err)
				}
			})
		}
	}
}

func TestFindRootsAndBoundaries(t *testing.T) {
	inst, root := legacyScopeFixture(t, 3)
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		for _, text := range []string{
			"find " + shellQuote(outside) + " -delete",
			"find " + shellQuote(inst.worktree) + " " + shellQuote(outside) + " -name '*.tmp' -delete",
		} {
			allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
			if err != nil || allowed || reason != worktreeBoundaryReason {
				t.Fatalf("each literal find root must reach the L3 boundary: allow=%v reason=%q err=%v", allowed, reason, err)
			}
		}
		for _, text := range []string{"find \"$ROOT\" -delete", "find \"$ROOT\" -exec printf x \\;"} {
			incompleteCompatibilityReceipt(t, inst, runner, text)
		}
		text := "find " + shellQuote(inst.home) + " -name x -print"
		allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
		if err != nil || !allowed || reason != "org policy permits this tool call" {
			t.Fatalf("read-only find must remain allowed: allow=%v reason=%q err=%v", allowed, reason, err)
		}
		tool, field := "Bash", "command"
		if runner == "codex" {
			tool, field = "exec_command", "cmd"
		}
		act, err := eventAction(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool,
			"tool_input": map[string]any{field: text}}, runner, inst.worktree)
		_, _, _, opaque, effectErr := actionEffects(act, inst.worktree)
		if err != nil || effectErr != nil || opaque {
			t.Fatalf("read-only find must be fully inspected: opaque=%v err=%v effects=%v", opaque, err, effectErr)
		}
	}
}

func TestLiteralWriteDataControls(t *testing.T) {
	inst, _ := legacyScopeFixture(t, 4)
	for _, runner := range []string{"claude", "codex"} {
		for _, text := range []string{
			"printf " + shellQuote(inst.home+"\\n") + " ; xargs rm",
			"tar -farchive_x.tar -t -C " + shellQuote(inst.home),
		} {
			incompleteCompatibilityReceipt(t, inst, runner, text)
		}
	}
}

func TestXargsListReadPolicy(t *testing.T) {
	inst, _ := legacyScopeFixture(t, 4)
	list := filepath.Join(inst.worktree, "private.list")
	if err := os.WriteFile(list, []byte(filepath.Join(inst.worktree, "ordinary")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(inst.home, "shared", "hooks", "rules.toml")
	data, err := os.ReadFile(rules)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\n[[rules]]\nid = \"secret-list\"\nkind = \"secret-read\"\nnames = [\"private.list\"]\n")...)
	if err := os.WriteFile(rules, data, 0600); err != nil {
		t.Fatal(err)
	}
	refusal := "id = \"secret-list\"\nrefuses = \"The input list is protected.\"\nwhy = \"Do not inspect this input.\"\ninstead = \"Use a permitted list.\"\nexamples_allowed = []\nexamples_refused = []\n[applies_to]\nlevels = [4]\nidentities = [\"*\"]\n"
	if err := os.WriteFile(filepath.Join(inst.home, "shared", "refusals", "secret-list.toml"), []byte(refusal), 0600); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		allowed, reason, err := compatibilityDecision(t, inst, runner, "xargs -a "+shellQuote(list)+" rm", nil)
		if err != nil || allowed || !strings.HasPrefix(reason, "[secret-list] Refuses:") {
			t.Fatalf("list read policy must precede target inference: allow=%v reason=%q err=%v", allowed, reason, err)
		}
	}
}
