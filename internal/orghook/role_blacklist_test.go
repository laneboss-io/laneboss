package orghook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleBlacklistRealDecision(t *testing.T) {
	inst, root := boundaryFixture(t)
	body := "# Role\n## Scope\nAssigned work.\n## Responsibilities\nFollow policy.\n## Deliverable\nReport evidence.\n## Must not\nExceed authority.\n"
	write := func(relative, text string) {
		t.Helper()
		filename := filepath.Join(inst.home, relative)
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("org.toml", "schema_version = 1\nlevels = [3, 4, 5, 6]\n")
	token := "role-" + filepath.Base(root)
	for _, source := range []struct {
		level          int
		role, id, word string
	}{
		{5, "reviewer", "domain-restriction", token},
		{3, "executor", "executor-restriction", token + "-executor"},
	} {
		base := fmt.Sprintf("L%d/roles/%s", source.level, source.role)
		write(base+".md", body)
		write(base+".toml", fmt.Sprintf("drivers = [\"claude\", \"codex\"]\n[[blacklist]]\nid = %q\ndescription = \"Role call restriction.\"\nband = \"refuse\"\nargv_prefix = [\"printf\", %q]\npattern_only = true\ninstead = \"Leave the call undone.\"\n", source.id, source.word))
	}
	for _, runner := range []string{"claude", "codex"} {
		for _, row := range []struct {
			level int
			role  string
			deny  bool
		}{
			{3, "executor", true}, {3, "reviewer", true}, {4, "supervisor", true},
			{4, "reviewer", true}, {5, "reviewer", true}, {5, "top", false}, {6, "supervisor", false},
		} {
			t.Run(fmt.Sprintf("%s/L%d/%s", runner, row.level, row.role), func(t *testing.T) {
				write("instances/executor/instance.toml", fmt.Sprintf("name = \"executor\"\nlevel = %d\nrole = %q\nwritable_repos = [%q]\nallowed_tools = []\nsecret_names = []\n", row.level, row.role, inst.worktree))
				write(fmt.Sprintf("L%d/hooks/rules.toml", row.level), "schema_version = 1\nrules = []\n")
				tool, field := "Bash", "command"
				if runner == "codex" {
					tool, field = "functions.exec_command", "cmd"
				}
				check := func(word string, deny bool, id, origin string) {
					t.Helper()
					event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": map[string]any{field: "printf " + word}}
					allow, reason, err := decide(event, runner, inst.directory)
					if err != nil || allow == deny {
						t.Fatalf("allow=%v, deny=%v, reason=%q, err=%v", allow, deny, reason, err)
					}
					if deny && (!strings.Contains(reason, "["+id+"] Refuses:") || !strings.Contains(reason, origin) || !strings.Contains(reason, "Instead: Leave the call undone.")) {
						t.Fatalf("refusal lost id, source or route: %q", reason)
					}
				}
				check(token, row.deny, "domain-restriction", "(L5, reviewer)")
				check(token+"-executor", row.level == 3 && row.role == "executor", "executor-restriction", "(L3, executor)")
				check(token+"-control", false, "", "")
			})
		}
	}
}
