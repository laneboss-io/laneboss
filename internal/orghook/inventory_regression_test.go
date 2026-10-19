package orghook

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestOwnOrgHistorySelectors(t *testing.T) {
	compatibilitySyntax(t)
	inst, root, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	input := filepath.Join(worktree, "message.md")
	if err := os.WriteFile(input, []byte("ordinary fixture message\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// This is the caller's own org, containing its protected org.toml.
	org := filepath.Dir(inst.home)
	if org != root {
		t.Fatal("the regression must use the session's own org")
	}
	for _, runner := range []string{"claude", "codex"} {
		for _, row := range []struct {
			verb, flags string
			files       []string
		}{
			{"hook-history", "--runner claude", []string{"shared/state/history/injections.jsonl", "shared/state/history/resident-start.json", "shared/services/history.sock"}},
			{"capture-decision", "--config boundary --source terminal/fixture --text-file " + input + " --author-authority inform", []string{"shared/state/history/classifications.jsonl", "shared/state/history/review.jsonl"}},
		} {
			t.Run(runner+"/"+row.verb, func(t *testing.T) {
				text := "laneboss org " + row.verb + " --org-dir " + org + " --instance executor " + row.flags
				allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
				if err != nil || !allowed {
					t.Fatalf("own-org history work must reach the CLI: allow=%v reason=%q err=%v", allowed, reason, err)
				}
				cmd, err := lanebossCommand(strings.Fields(text), worktree)
				if err != nil || cmd.opaque || contains(cmd.writes, org) || !contains(cmd.reads, org) {
					t.Fatalf("the org must be a selector read, never a directory write: %+v err=%v", cmd, err)
				}
				want := []string{}
				for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
					want = append(want, filepath.Join(inst.home, "shared/services/decisions.sqlite")+suffix)
				}
				for _, file := range row.files {
					want = append(want, filepath.Join(inst.home, file))
				}
				sort.Strings(want)
				got := append([]string{}, cmd.managedWrites...)
				sort.Strings(got)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("history must declare only its exact managed files: got=%v want=%v", got, want)
				}
				for _, target := range want {
					allowed, reason, err := compatibilityDecision(t, inst, runner, "printf x > "+target, nil)
					if err != nil || allowed || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") {
						t.Fatalf("raw writes cannot inherit managed history effects: %q %v", reason, err)
					}
				}
			})
		}
	}
}

func TestSupervisorCLIWritesAndRawBoundary(t *testing.T) {
	compatibilitySyntax(t)
	inst, root, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	sibling := filepath.Join(root, "repository-child")
	if err := os.Mkdir(sibling, 0700); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(sibling) != filepath.Dir(worktree) || sibling == worktree {
		t.Fatal("the control must be a real sibling worktree directory")
	}
	// Use real, disposable Git working trees without adding or committing.
	for _, directory := range []string{worktree, sibling} {
		if output, err := exec.Command("git", "init", "--quiet", directory).CombinedOutput(); err != nil {
			t.Fatalf("initialize fixture worktree: %s: %v", output, err)
		}
		output, err := exec.Command("git", "-C", directory, "rev-parse", "--is-inside-work-tree").CombinedOutput()
		if err != nil || strings.TrimSpace(string(output)) != "true" {
			t.Fatalf("fixture must be a real Git worktree: %s: %v", output, err)
		}
	}
	input := filepath.Join(worktree, "brief.md")
	if err := os.WriteFile(input, []byte("ordinary child brief\n"), 0600); err != nil {
		t.Fatal(err)
	}
	start := "laneboss lane start --config boundary --lane child --brief " + input + " --worktree "
	for _, runner := range []string{"claude", "codex"} {
		for _, row := range []struct {
			text, refusal string
		}{
			{start + sibling, ""},
			{"printf x > " + filepath.Join(sibling, "f"), ""},
			{start + sibling + " > " + filepath.Join(sibling, "log"), ""},
			{start + filepath.Join(inst.home, "hooks"), "[blacklist:laneboss-files] Refuses:"},
			{"laneboss lane adopt --config boundary --lane child --runner fixture --model fixture-model-1 --session 00000000-0000-0000-0000-000000000001 --brief " + input + " --worktree " + sibling, ""},
			{"laneboss lane archive --config boundary --lane child --to " + sibling, ""},
			{"laneboss init boundary --project " + sibling, ""},
			{"laneboss decisions export --db " + filepath.Join(worktree, "decisions.sqlite") + " --out " + filepath.Join(sibling, "x"), ""},
		} {
			allowed, reason, err := compatibilityDecision(t, inst, runner, row.text, nil)
			if err != nil || row.refusal == "" && !allowed || row.refusal != "" && (allowed || !strings.HasPrefix(reason, row.refusal)) {
				t.Fatalf("CLI authority and raw boundary diverged for %q: allow=%v reason=%q err=%v", row.text, allowed, reason, err)
			}
		}
	}
}

func TestSelectorAndSubject(t *testing.T) {
	compatibilitySyntax(t)
	for _, value := range []string{"..", ".", "../peer", "peer/instance.toml", `peer\instance`, "_peer", strings.Repeat("x", 65), "peer.toml"} {
		call := cliCall{}
		if !call.pathEffects(hookArgument{Path: &cliPathEffect{Read: true, Selector: true}}, value) || !reflect.DeepEqual(call.reads, []string{value}) {
			t.Fatalf("a non-name selector must remain an observed read: %q -> %v", value, call.reads)
		}
	}
	call := cliCall{}
	if !call.pathEffects(hookArgument{Path: &cliPathEffect{Read: true, Selector: true}}, "L4-supervisor") || len(call.reads) != 0 {
		t.Fatal("a safe bare instance name must select implicit org policy")
	}
	for _, value := range []string{"subject=/tmp/input=part.md", "subject=/tmp/input==part.md"} {
		call, ok := inspectCLI([]string{"judge", "ask", "--config", "boundary", "--judge", "fixture", "--question", "fixture", "--prompt-file", "/tmp/prompt.md", "--subject", value})
		_, path, _ := strings.Cut(value, "=")
		if !ok || !contains(call.reads, path) || contains(call.reads, value) {
			t.Fatalf("subject must split at its first equals sign, as the CLI does: %q -> %v", value, call.reads)
		}
	}
}
