package orghook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/config"
)

func TestBlacklistLanebossLadderVerbs(t *testing.T) {
	compatibilitySyntax(t)
	inst, _, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	if inst.hookMode != "blacklist" || inst.level != 4 {
		t.Fatal("the caller must be a hooked L4 supervisor in default blacklist mode")
	}
	configuration, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(worktree, "input.md")
	if err := os.WriteFile(input, []byte("delegation input\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Mutant for each row: delete that verb's hook annotation in syntax.json;
	// the literal allow must fail with the existing opaque-laneboss refusal.
	rows := []struct {
		verb, state, read string
		args              []string
	}{
		{"lane start", "write", "--brief", []string{"--lane", "child", "--brief", input, "--level", "3", "--role", "executor", "--runner", "fixture", "--model", "fixture-model-1", "--worktree", worktree}},
		{"lane resume", "write", "--message", []string{"--lane", "child", "--message", input}},
		{"lane turn", "write", "", []string{"--lane", "child"}},
		{"lane stop", "write", "", []string{"--lane", "child"}},
		{"lane mark", "write", "", []string{"--lane", "child", "--state", "verifying"}},
		{"lane clean", "write", "", []string{"--lane", "child"}},
		{"lane adopt", "write", "--brief", []string{"--lane", "child", "--brief", input, "--worktree", worktree, "--session", "12345678-1234-1234-1234-123456789abc", "--runner", "fixture", "--model", "fixture-model-1", "--level", "3", "--role", "executor"}},
		{"lane attach", "write", "", []string{"--lane", "child"}},
		{"lane send", "write", "--file", []string{"--lane", "child", "--file", input}},
		{"report", "write", "--file", []string{"--file", input}},
		{"lane status", "read", "", []string{"--lane", "child"}},
		{"state events", "read", "", nil},
		{"state lanes", "read", "", nil},
		{"event tail", "read", "", []string{"--lane", "child", "--since", "0"}},
	}
	for _, row := range rows {
		t.Run(row.verb, func(t *testing.T) {
			words := append(strings.Fields(row.verb), "--config", configuration.Name)
			words = append(words, row.args...)
			call, supported := inspectCLI(words)
			if !supported || call.effects.State != row.state || call.effects.Config != "--config" {
				t.Fatalf("the verb must declare its actual configuration effect: %+v supported=%v", call, supported)
			}
			if row.read == "" && len(call.effects.Reads) != 0 || row.read != "" && (len(call.effects.Reads) != 1 || call.effects.Reads[0] != row.read) {
				t.Fatalf("the file-input declaration is wrong: %+v", call.effects)
			}
			words = append([]string{"laneboss"}, words...)
			cmd, err := lanebossCommand(words, worktree)
			// The path inventory (4c9d128) declares a supplied --worktree as an ordinary write, so the
			// protected-file gate sees it; every other write stays the checked state root.
			wantWrites := 0
			if contains(row.args, "--worktree") {
				wantWrites = 1
			}
			if err != nil || cmd.opaque || cmd.stateRoot != configuration.StateDir || len(cmd.stateWrites) != 1 || cmd.stateWrites[0] != configuration.StateDir || len(cmd.writes) != wantWrites || wantWrites == 1 && cmd.writes[0] != worktree {
				t.Fatalf("the adapter must declare only its checked state root and a supplied worktree: %+v err=%v", cmd, err)
			}
			if row.read != "" && !contains(cmd.reads, input) {
				t.Fatal("the actual input file must remain visible to read policies")
			}
			for _, runner := range []string{"claude", "codex"} {
				allowed, reason, err := compatibilityDecision(t, inst, runner, strings.Join(words, " "), nil)
				if err != nil || !allowed || reason != "org policy permits this tool call" {
					t.Fatalf("%s must allow the literal %s: allow=%v reason=%q err=%v", runner, row.verb, allowed, reason, err)
				}
				// Mutant: accept nohup by stripping it without declaring its output.
				allowed, _, err = compatibilityDecision(t, inst, runner, "nohup "+strings.Join(words, " "), nil)
				if allowed || err == nil || !strings.Contains(err.Error(), "output files cannot be inspected") {
					t.Fatalf("%s must still refuse obscured %s: allow=%v err=%v", runner, row.verb, allowed, err)
				}
			}
		})
	}
}

func TestBlacklistLanebossBriefReadBoundary(t *testing.T) {
	compatibilitySyntax(t)
	inst, root, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	configuration, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	insideBrief, outsideBrief := filepath.Join(worktree, "brief.md"), filepath.Join(root, "private-brief.md")
	for _, path := range []string{insideBrief, outsideBrief} {
		if err := os.WriteFile(path, []byte("brief read canary\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// The existing explicit path blacklist is this fixture's readable boundary;
	// there is no blanket rule denying every read outside a worktree.
	policy := fmt.Sprintf("schema_version = 1\nname = \"fixture\"\n[hooks]\nmode = \"blacklist\"\n[[hooks.blacklist]]\nid = \"brief-scope\"\ndescription = \"This input is outside the readable scope.\"\nband = \"refuse\"\npath_glob = %q\ninstead = \"Use a readable brief.\"\n", outsideBrief)
	if err := os.WriteFile(filepath.Join(inst.home, "org.toml"), []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		for _, row := range []struct {
			path    string
			allowed bool
		}{{insideBrief, true}, {outsideBrief, false}} {
			text := "laneboss lane start --config " + configuration.Name + " --lane child --level 3 --role executor --brief " + row.path
			// Mutant: remove --brief from lane start's reads; the outside row allows.
			allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
			if err != nil || allowed != row.allowed || !allowed && !strings.HasPrefix(reason, "[brief-scope] Refuses:") {
				t.Fatalf("the ordinary brief read policy must decide: allow=%v reason=%q err=%v", allowed, reason, err)
			}
		}
	}
}

func TestBlacklistLanebossStartSettings(t *testing.T) {
	compatibilitySyntax(t)
	inst, _, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	configuration, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(worktree, "brief.md")
	if err := os.WriteFile(input, []byte("settings input\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, options := range []string{
		" --instance L3-fixture --set model=fixture-model-1 --set effort=high --touches billing --touches deploy",
		" --instance=L3-fixture --set=model=fixture-model-1 --set=effort=high --touches=billing --touches=deploy",
	} {
		text := "laneboss lane start --config " + configuration.Name + " --lane child --level 3 --role executor --brief " + input + options
		// Mutant: omit --instance, --set, or either repeat shape from lane start.
		call, supported := inspectCLI(strings.Fields(text)[1:])
		if !supported || len(call.values["--set"]) != 2 || len(call.values["--touches"]) != 2 || len(call.values["--instance"]) != 1 {
			t.Fatalf("literal instance/settings flags must be fully parsed: %+v supported=%v", call, supported)
		}
		for _, runner := range []string{"claude", "codex"} {
			allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
			if err != nil || !allowed {
				t.Fatalf("%s must allow the literal instance/settings call: allow=%v reason=%q err=%v", runner, allowed, reason, err)
			}
			// Mutant: ignore truly unknown flags while accepting known settings.
			allowed, _, err = compatibilityDecision(t, inst, runner, text+" --unknown-output output", nil)
			if allowed || err == nil || err.Error() != "the tool or command has no file-effects adapter" {
				t.Fatalf("an actually unknown option must retain the opaque refusal: allow=%v err=%v", allowed, err)
			}
		}
	}
}

func TestDelegationKeepsInstalledRefusals(t *testing.T) {
	compatibilitySyntax(t)
	inst, _, worktree := authenticatedLaneLevelFixture(t, 4)
	inst.worktree = worktree
	configuration, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	files := [][2]string{
		{filepath.Join(inst.home, "L4", "hooks", "rules.toml"), "schema_version = 1\n[[rules]]\nid = \"delegation-review\"\nkind = \"command-pattern\"\npatterns = [[\"laneboss\", \"lane\", \"start\"]]\n"},
		{filepath.Join(inst.home, "L4", "refusals", "delegation-review.toml"), "id = \"delegation-review\"\nrefuses = \"Review this delegation first.\"\nwhy = \"Keep the installed policy.\"\ninstead = \"Report the request.\"\nexamples_allowed = []\nexamples_refused = []\n[applies_to]\nlevels = [4]\nidentities = [\"*\"]\n"},
	}
	for _, file := range files {
		path, data := file[0], file[1]
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	text := "laneboss lane start --config " + configuration.Name + " --lane child --level 3 --role executor --brief " + filepath.Join(worktree, "brief.md")
	for _, mode := range []string{"strict", "blacklist"} {
		data := fmt.Sprintf("schema_version = 1\nname = \"fixture\"\n[hooks]\nmode = %q\n", mode)
		if err := os.WriteFile(filepath.Join(inst.home, "org.toml"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		for _, runner := range []string{"claude", "codex"} {
			// Mutant: let an annotated CLI call skip the installed mode's rules.
			allowed, reason, err := compatibilityDecision(t, inst, runner, text, nil)
			if err != nil || allowed || !strings.HasPrefix(reason, "[delegation-review] Refuses:") {
				t.Fatalf("%s must retain the installed delegation refusal in %s mode: allow=%v reason=%q err=%v", runner, mode, allowed, reason, err)
			}
		}
	}
}
