package orghook

import (
	"os"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
)

func TestFileOwnerReportDeclaredState(t *testing.T) {
	compatibilitySyntax(t)
	for _, row := range []struct {
		name, starter string
		level         int
	}{
		{"l3-to-l4", "supervisor:mini", 3},
		{"l3-top-of-chain", "human", 3},
		{"l6-top-of-chain", "human", 6},
	} {
		t.Run(row.name, func(t *testing.T) {
			inst, _, worktree := authenticatedLaneStarterFixture(t, row.level, row.starter)
			inst.worktree = worktree
			c, err := config.Load("boundary")
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(c.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			data = append([]byte("owner_channel = \"owner\"\n"), data...)
			data = append(data, []byte("\n[owner_channels.owner]\nkind = \"file\"\npath = \"owner/queue.jsonl\"\n[supervisors.mini]\nlevel = 4\nrunner = \"fixture\"\n")...)
			if err := os.WriteFile(c.ConfigFile, data, 0600); err != nil {
				t.Fatal(err)
			}
			c, err = config.Load(c.Name)
			if err != nil {
				t.Fatal(err)
			}
			record, err := caller.Lane(c, "executor")
			if err != nil || record.Level != row.level || record.Starter != row.starter {
				t.Fatalf("the hook row must use the recorded level and report line: %v", err)
			}
			text := "laneboss report --config " + c.Name + " --file -"
			cmd, err := lanebossCommand(strings.Fields(text), worktree)
			if err != nil || cmd.opaque || len(cmd.writes) != 0 || cmd.stateRoot != c.StateDir || len(cmd.stateWrites) != 1 || cmd.stateWrites[0] != c.StateDir {
				t.Fatalf("file owner reports must declare only the checked state scope: writes=%v state=%s err=%v", cmd.writes, cmd.stateRoot, err)
			}
			for _, runner := range []string{"claude", "codex"} {
				allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
				if err != nil || !allowed || reason != "org policy permits this tool call" {
					t.Fatalf("%s report must pass decide with a file owner channel: allow=%v reason=%q err=%v", runner, allowed, reason, err)
				}
			}
		})
	}
}
