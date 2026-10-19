package orghook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteralGapTargetsAndDirectories(t *testing.T) {
	rows := []struct {
		name      string
		directory bool
		command   func(string, string) string
	}{
		{"mv-joined", true, func(p, src string) string { return "mv -t" + shellQuote(p) + " " + shellQuote(src) }},
		{"mv-bundled", true, func(p, src string) string { return "mv -ft" + shellQuote(p) + " " + shellQuote(src) }},
		{"mv-long", true, func(p, src string) string { return "mv --target-directory=" + shellQuote(p) + " " + shellQuote(src) }},
		{"cp-target", true, func(p, src string) string { return "cp -R -t " + shellQuote(p) + " " + shellQuote(src) }},
		{"cp-joined", true, func(p, src string) string { return "cp -t" + shellQuote(p) + " " + shellQuote(src) }},
		{"cp-bundled", true, func(p, src string) string { return "cp -Rt" + shellQuote(p) + " " + shellQuote(src) }},
		{"cp-long", true, func(p, src string) string { return "cp --target-directory=" + shellQuote(p) + " " + shellQuote(src) }},
		{"install-D-target", true, func(p, src string) string { return "install -D -t " + shellQuote(p) + " " + shellQuote(src) }},
		{"install-joined", true, func(p, src string) string { return "install -t" + shellQuote(p) + " " + shellQuote(src) }},
		{"install-bundled", true, func(p, src string) string { return "install -Dt" + shellQuote(p) + " " + shellQuote(src) }},
		{"install-long", true, func(p, src string) string {
			return "install --target-directory=" + shellQuote(p) + " " + shellQuote(src)
		}},
		{"cp-sparse", false, func(p, src string) string { return "cp --sparse=always " + shellQuote(src) + " " + shellQuote(p) }},
		{"cp-slash", true, func(p, src string) string { return "cp -R " + shellQuote(src+"/") + " " + shellQuote(p) }},
		{"mv-late-terminator", false, func(p, _ string) string { return "mv " + shellQuote(p) + " --" }},
		{"mv-terminator", false, func(p, src string) string { return "mv -- " + shellQuote(src) + " " + shellQuote(p) }},
		{"cd-chain", true, func(p, _ string) string { return "cd " + shellQuote(p) + " && printf x > f" }},
		{"builtin-cd-chain", true, func(p, _ string) string { return "builtin cd " + shellQuote(p) + " && printf x > f" }},
		{"cd-branch", true, func(p, _ string) string {
			return "if true; then builtin cd " + shellQuote(p) + "; printf x > f; else printf y > g; fi"
		}},
		{"cd-after-branch", true, func(p, _ string) string {
			return "if true; then builtin cd " + shellQuote(p) + "; else true; fi; printf x > f"
		}},
		{"sed-inplace", false, func(p, _ string) string { return "sed -i 's/a/b/' " + shellQuote(p) }},
		{"patch-then-command", false, func(p, _ string) string {
			return "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: " + p + "\n+fixture\n*** End Patch\nPATCH\necho second"
		}},
	}
	for _, level := range []int{3, 4} {
		t.Run(fmt.Sprintf("L%d", level), func(t *testing.T) {
			inst, root := legacyScopeFixture(t, level)
			src := filepath.Join(inst.worktree, "source")
			outside := filepath.Join(root, "outside")
			for _, dir := range []string{src, outside, filepath.Join(inst.worktree, "inside")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			scopes := []string{"protected", "inside"}
			if level == 3 {
				scopes = append(scopes, "outside")
			}
			for _, runner := range []string{"claude", "codex"} {
				for _, row := range rows {
					for _, scope := range scopes {
						for _, rawGap := range []bool{false, true} {
							t.Run(fmt.Sprintf("%s/%s/%s/raw-%v", runner, row.name, scope, rawGap), func(t *testing.T) {
								target := filepath.Join(inst.worktree, "inside")
								if scope == "protected" {
									target = inst.home
								} else if scope == "outside" {
									target = outside
								}
								if !row.directory {
									target = filepath.Join(target, "target.txt")
								}
								tool, field := "Bash", "command"
								if runner == "codex" {
									tool, field = "exec_command", "cmd"
								}
								input := map[string]any{field: row.command(target, src)}
								if rawGap {
									input["env"] = map[string]any{"WRITE_FIXTURE": "literal"}
								}
								event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": input}
								if scope == "inside" {
									incompleteEventReceipt(t, inst, runner, event)
									return
								}
								allowed, reason, err := decide(event, runner, filepath.Join(inst.directory, "instance.toml"))
								if err != nil || allowed {
									t.Fatalf("a retained literal target must refuse: allow=%v reason=%q err=%v", allowed, reason, err)
								}
								if scope == "protected" && !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
									t.Fatalf("the protected-file gate must speak: %q", reason)
								}
								if scope == "outside" && reason != worktreeBoundaryReason {
									t.Fatalf("the full L3 worktree refusal must speak: %q", reason)
								}
							})
						}
					}
				}
			}
		})
	}
}
