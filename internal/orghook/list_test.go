package orghook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/rolepolicy"
)

func TestBlacklistListForAuthenticatedLane(t *testing.T) {
	for _, level := range []int{3, 4} {
		t.Run(fmt.Sprintf("L%d", level), func(t *testing.T) {
			inst, root, worktree := authenticatedLaneLevelFixture(t, level)
			write := func(filename, text string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			orgSource := filepath.Join(inst.home, "org.toml")
			write(orgSource, "schema_version = 1\nlevels = [3, 4, 5, 6]\n"+
				"[[hooks.blacklist]]\nid = \"raw-codex-exec\"\ndescription = \"Raw sessions bypass the lifecycle.\"\nband = \"refuse\"\nargv_words = [\"codex\", \"exec\"]\npattern_only = true\ninstead = \"laneboss lane start / laneboss lane resume / laneboss lane turn\"\n"+
				"[[hooks.blacklist]]\nid = \"org-other-role\"\ndescription = \"Only another role.\"\nband = \"refuse\"\nargv_prefix = [\"printf\", \"other\"]\npattern_only = true\n[hooks.blacklist.applies_to]\nroles = [\"researcher\"]\n")
			body := "## Scope\nAssigned work.\n## Responsibilities\nFollow policy.\n## Deliverable\nReport evidence.\n## Must not\nExceed authority.\n"
			origins := map[string]string{"raw-codex-exec": orgSource, "no-push": filepath.Join(inst.home, "L3/hooks/rules.toml")}
			for _, pair := range []struct {
				level          int
				role, id, band string
			}{
				{3, "executor", "own-executor", "refuse"},
				{3, "reviewer", "reviewer-only", "refuse"},
				{4, "reviewer", "stream-review", "refuse"},
				{4, "supervisor", "", "refuse"}, // existing empty sources must be listed
				{5, "reviewer", "domain-warning", "warn"},
				{6, "supervisor", "org-role", "refuse"},
			} {
				base := filepath.Join(inst.home, fmt.Sprintf("L%d/roles/%s", pair.level, pair.role))
				write(base+".md", body)
				text := "drivers = [\"true\"]\n"
				if pair.id != "" {
					text += fmt.Sprintf("[[blacklist]]\nid = %q\ndescription = %q\nband = %q\nargv_prefix = [\"printf\", %q]\npattern_only = true\ninstead = %q\n", pair.id, "Restriction "+pair.id, pair.band, pair.id, "Route "+pair.id)
					origins[pair.id] = base + ".toml"
				}
				write(base+".toml", text)
			}
			write(filepath.Join(inst.home, "shared/protocol/rules.md"), "# Shared\nRead the rules.\n")
			write(filepath.Join(inst.home, fmt.Sprintf("L%d/protocol/rules.md", level)), "# Level\nFollow the assigned scope.\n")
			configuration := filepath.Join(root, "configuration/configs/boundary/config.toml")
			configBytes, err := os.ReadFile(configuration)
			if err != nil {
				t.Fatal(err)
			}
			write(configuration, fmt.Sprintf("org_dir = %q\n", root)+string(configBytes))
			t.Setenv("LANEBOSS_INSTANCE", inst.directory)
			inst, err = loadInstance(inst.directory)
			if err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			if code := Run("blacklist", []string{"list", "--format", "json"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
				t.Fatalf("the authenticated lane must read its own rules: exit=%d stderr=%s", code, &stderr)
			}
			var got struct {
				Caller, Role, Instance string
				Level                  int
				Sources                []string
				Entries                []struct{ ID, Band, Description, Instead, Source string }
				Builtins               []struct{ ID, Description, Instead string }
			}
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Caller != "lane:executor" || got.Level != level || got.Role != inst.role || got.Instance != inst.name {
				t.Fatalf("identity must come from the real process record: %+v", got)
			}
			// Compare every listed field with the hook's real effective rows,
			// including its scope filter, then assert an independent expected set.
			rows, err := blacklistGuardRows(inst)
			if err != nil {
				t.Fatal(err)
			}
			index := 0
			ids := []string{}
			for _, row := range rows {
				if !blacklistScopeApplies(row, inst) {
					continue
				}
				if index >= len(got.Entries) {
					t.Fatal("list omitted a hook entry")
				}
				entry := got.Entries[index]
				if entry.ID != row.id || entry.Band != row.band || entry.Description != row.description || entry.Instead != row.instead || entry.Source != origins[row.id] {
					t.Fatalf("listed entry disagrees with hook/source: %+v, hook=%+v", entry, row)
				}
				ids = append(ids, entry.ID)
				index++
			}
			if index != len(got.Entries) {
				t.Fatal("list added entries the hook does not evaluate")
			}
			wantIDs := []string{"no-push", "raw-codex-exec", "own-executor", "stream-review", "domain-warning", "org-role"}
			wantSources := []string{orgSource, origins["own-executor"], origins["stream-review"], filepath.Join(inst.home, "L4/roles/supervisor.toml"), origins["domain-warning"], origins["org-role"]}
			if level == 4 {
				wantIDs = []string{"raw-codex-exec", "domain-warning", "org-role"}
				wantSources = []string{orgSource, filepath.Join(inst.home, "L4/roles/supervisor.toml"), origins["domain-warning"], origins["org-role"]}
			}
			if !reflect.DeepEqual(ids, wantIDs) || !reflect.DeepEqual(got.Sources, wantSources) {
				t.Fatalf("R49/own-role/source order mismatch: ids=%v sources=%v", ids, got.Sources)
			}
			boundary := false
			for _, builtin := range got.Builtins {
				boundary = boundary || builtin.ID == "lane-worktree"
			}
			if boundary != (level == 3) {
				t.Fatal("only an L3 list should carry the L3 worktree-boundary line")
			}
			stdout.Reset()
			if code := Run("blacklist", []string{"list"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
				t.Fatalf("plain rules must succeed: %d %s", code, &stderr)
			}
			for _, text := range []string{"[raw-codex-exec] Band: refuse", "[domain-warning] Band: warn", "Instead: Route domain-warning", "Built-in refusals", "Secret-file reads are refused only when"} {
				if !strings.Contains(stdout.String(), text) {
					t.Fatalf("plain rules lost %q", text)
				}
			}
			selection, err := rolepolicy.Start("", map[string]any{"org_dir": root}, fmt.Sprint(level), inst.role, "supervisor", []string{"true"})
			if err != nil {
				t.Fatal(err)
			}
			prefix, err := selection.Prefix()
			if err != nil {
				t.Fatal(err)
			}
			_, section, found := strings.Cut(string(prefix), "## What your org hook refuses\n")
			if !found {
				t.Fatal("the generated blacklist section is missing")
			}
			section, _, _ = strings.Cut(section, "## Your task")
			briefSources := []string{}
			for _, line := range strings.Split(section, "\n") {
				if strings.HasPrefix(line, "- `") {
					briefSources = append(briefSources, strings.TrimSuffix(strings.TrimPrefix(line, "- `"), "`"))
				}
			}
			if !reflect.DeepEqual(briefSources, got.Sources) || !strings.Contains(section, "Run `laneboss org blacklist list` first") || strings.Contains(section, "Restriction domain-warning") || !strings.Contains(section, "current at the start") {
				t.Fatalf("brief must name the command and the hook's source paths, without embedding entries: %s", section)
			}
			compatibilitySyntax(t)
			for _, command := range []string{"laneboss org blacklist list", "laneboss org blacklist list --config boundary --format json"} {
				adapted, err := lanebossCommand(strings.Fields(command), worktree)
				if err != nil || adapted.opaque || len(adapted.writes) != 0 {
					t.Fatalf("the rules command must declare read-only hook effects: %+v %v", adapted, err)
				}
				for _, runner := range []string{"claude", "codex"} {
					allowed, reason, err := compatibilityDecision(t, inst, runner, command, nil)
					if err != nil || !allowed {
						t.Fatalf("the real hook must allow its literal list command: %s %q %v", runner, reason, err)
					}
				}
			}
			for _, args := range [][]string{{"list", "--level", "6"}, {"list", "--role", "reviewer"}, {"list", "--instance", "other"}} {
				stdout.Reset()
				if code := Run("blacklist", args, strings.NewReader(""), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
					t.Fatal("a caller must not select a different rule identity")
				}
			}
		})
	}
}
