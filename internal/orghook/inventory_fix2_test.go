package orghook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL3CLIWriteDestinationsBoundary(t *testing.T) {
	compatibilitySyntax(t)
	inst, root, worktree := authenticatedLaneFixture(t)
	inst.worktree = worktree
	sibling := filepath.Join(root, "repository-child")
	if err := os.Mkdir(sibling, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(worktree, "brief.md")
	if err := os.WriteFile(input, []byte("ordinary brief\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		for _, text := range []string{
			"laneboss lane start --config boundary --lane child --brief " + input + " --worktree " + sibling,
			"laneboss lane adopt --config boundary --lane child --runner fixture --model fixture-model-1 --session 00000000-0000-0000-0000-000000000001 --brief " + input + " --worktree " + sibling,
			"laneboss brief render --config boundary --lane child --in " + input + " --out " + filepath.Join(sibling, "x"),
			"laneboss decisions init --db " + filepath.Join(sibling, "d.sqlite"),
			"laneboss decisions import --db " + filepath.Join(sibling, "d.sqlite") + " --in " + input,
		} {
			allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
			if err != nil || allowed || reason != worktreeBoundaryReason {
				t.Fatalf("the L3 instance's external destination must stop at the hook boundary: allow=%v reason=%q err=%v command=%q", allowed, reason, err, text)
			}
		}
		for _, text := range []string{
			"laneboss brief render --config boundary --lane child --in " + input + " --out " + filepath.Join(worktree, "rendered.md"),
			"laneboss decisions init --db " + filepath.Join(worktree, "d.sqlite"),
		} {
			allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
			if err != nil || !allowed {
				t.Fatalf("the inside-destination control must reach the CLI: %q %v", reason, err)
			}
		}
	}
}

func TestSupervisorCLIWrites(t *testing.T) {
	compatibilitySyntax(t)
	inst, root, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	sibling := filepath.Join(root, "repository-child")
	if err := os.Mkdir(sibling, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(worktree, "brief.md")
	if err := os.WriteFile(input, []byte("ordinary brief\n"), 0600); err != nil {
		t.Fatal(err)
	}
	argv := []string{"laneboss", "lane", "start", "--config", "boundary", "--lane", "child", "--brief", input, "--worktree", sibling}
	cmd, err := lanebossCommand(argv, worktree)
	if err != nil || cmd.opaque || !contains(cmd.writes, sibling) {
		t.Fatalf("complete start must retain its declared worktree write: %+v %v", cmd, err)
	}
	resolved, err := resolveHookCaller()
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := hookLaneBoundary(action{commands: []command{cmd}}, inst, worktree, resolved); err != nil || reason != "" {
		t.Fatalf("the complete L4 child-worktree control must allow: %q %v", reason, err)
	}
	// The hook marks commands opaque when a surrounding inspection is partial.
	// Ordinary supervisor writes have no worktree boundary even in a gap.
	cmd.opaque = true
	if reason, err := hookLaneBoundary(action{commands: []command{cmd}}, inst, worktree, resolved); err != nil || reason != "" {
		t.Fatalf("opaque ordinary supervisor effects must keep their write authority: %q %v", reason, err)
	}
	// Grammar parsing succeeds here, but the bound configuration cannot be
	// resolved. The adapter must still report that error to its caller.
	unresolved := append([]string{}, argv...)
	unresolved[4] = "missing"
	for _, row := range []struct {
		words      []string
		parseError bool
	}{
		{append(append([]string{}, argv...), "--unknown-output", sibling), true},
		{unresolved, true},
		{[]string{"laneboss", "lane", "start", "--worktree", sibling}, true},
		{[]string{"laneboss", "lane", "start", "--help"}, false},
		{[]string{"laneboss", "decisions", "export", "--db", filepath.Join(worktree, "d.sqlite"), "--out", filepath.Join(sibling, "x")}, false},
	} {
		_, err := lanebossCommand(row.words, worktree)
		if (err != nil) != row.parseError {
			t.Fatalf("adapter parse errors must remain unchanged: %v err=%v", row.words, err)
		}
	}
}

func TestClobberTargetsKept(t *testing.T) {
	inst, root := boundaryFixture(t)
	inside := filepath.Join(inst.worktree, "inside")
	outside := filepath.Join(root, "outside")
	protected := filepath.Join(inst.home, "hooks", "output")
	for _, form := range []string{">!", ">>!", "&>!", ">&!", ">! "} {
		for _, target := range []string{inside, outside, protected} {
			for _, prefix := range []string{"", "true && "} {
				event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": "Bash", "tool_input": map[string]any{"command": prefix + "printf x " + form + target + " 2> " + inside + "-stderr"}}
				act, err := eventAction(event, "claude", inst.worktree)
				if err == nil || !isObservationGap(err) || !strings.Contains(err.Error(), "zsh clobber redirection") {
					t.Fatalf("retain the observation gap: %v", err)
				}
				writes, _, _, _, err := actionEffects(act, inst.worktree)
				if err != nil {
					t.Fatal(err)
				}
				observed := []string{}
				for _, effect := range writes {
					observed = append(observed, effect.word)
				}
				if !contains(observed, target) || !contains(observed, inside+"-stderr") {
					t.Fatalf("all literal redirects must survive the gap: %v", observed)
				}
				reason, err := builtInWriteRefusal(inst, writes)
				if err != nil || target == protected && !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") || target != protected && reason != "" {
					t.Fatalf("protected destinations must retain their gate: %q %v", reason, err)
				}
				reason, err = laneBoundary(act, inst, inst.worktree, inst.worktree)
				if err != nil || target == outside && reason != worktreeBoundaryReason || target == inside && reason != "" {
					t.Fatalf("literal outside writes must reach the boundary: %q %v", reason, err)
				}
			}
		}
	}
}

// This integration row also requires the parallel R48 decide() correction:
// the old zsh-specific early error in policy.go must no longer preempt effects.
func TestClobberBoundaryReceipt(t *testing.T) {
	for _, runner := range []string{"claude", "codex"} {
		inst, root := legacyScopeFixture(t, 3)
		outside := "printf x >! " + filepath.Join(root, "outside")
		allowed, reason, err := compatibilityDecision(t, inst, runner, outside, nil)
		if err != nil || allowed || reason != worktreeBoundaryReason {
			t.Fatalf("an outside literal zsh target must refuse at the L3 boundary: %q %v", reason, err)
		}
		tool, field := "Bash", "command"
		if runner == "codex" {
			tool, field = "exec_command", "cmd"
		}
		event := map[string]any{"hook_event_name": "PreToolUse", "cwd": inst.worktree, "tool_name": tool, "tool_input": map[string]any{field: "printf x >! " + filepath.Join(inst.worktree, "inside")}}
		pinned := filepath.Join(inst.directory, "instance.toml")
		allowed, reason, err = decide(event, runner, pinned)
		if err != nil || !allowed {
			t.Fatalf("an inside literal zsh target must allow with an incomplete receipt: %q %v", reason, err)
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
		if receipt["decision"] != "allow" || receipt["inspection_complete"] != false || receipt["inspection_notice"] == nil {
			t.Fatalf("the allowed observation gap must retain its receipt: %s", data)
		}
	}
}
