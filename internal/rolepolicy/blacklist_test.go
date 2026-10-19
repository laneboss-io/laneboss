package rolepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const blacklistRoleBody = "# Role\n\n## Scope\nAssigned work.\n## Responsibilities\nFollow policy.\n## Deliverable\nReport evidence.\n## Must not\nExceed authority.\n"

func blacklistSource(t *testing.T, root, relative, text string) {
	t.Helper()
	filename := filepath.Join(root, ".laneboss", relative)
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func blacklistRole(t *testing.T, root string, level int, role, entries string) {
	t.Helper()
	base := fmt.Sprintf("L%d/roles/%s", level, role)
	blacklistSource(t, root, base+".md", blacklistRoleBody)
	blacklistSource(t, root, base+".toml", "drivers = [\"claude\", \"codex\"]\n"+entries)
}

func blacklistEntry(id string) string {
	return fmt.Sprintf("\n[[blacklist]]\nid = %q\ndescription = \"A role-owned restriction.\"\nband = \"refuse\"\nargv_prefix = [\"printf\", %q]\npattern_only = true\ninstead = \"Keep the call undone.\"\n", id, id)
}

func TestRoleBlacklistDirection(t *testing.T) {
	root := t.TempDir()
	blacklistSource(t, root, "org.toml", "schema_version = 1\nlevels = [3, 4, 5, 6]\n")
	blacklistRole(t, root, 3, "executor", blacklistEntry("executor-only"))
	blacklistRole(t, root, 5, "reviewer", blacklistEntry("domain-review"))
	blacklistRole(t, root, 6, "supervisor", blacklistEntry("org-policy"))
	catalog, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		level int
		role  string
		want  []string
	}{
		{3, "executor", []string{"executor-only", "domain-review", "org-policy"}},
		{3, "reviewer", []string{"domain-review", "org-policy"}},
		{4, "supervisor", []string{"domain-review", "org-policy"}},
		{4, "reviewer", []string{"domain-review", "org-policy"}},
		{5, "reviewer", []string{"domain-review", "org-policy"}},
		{5, "top", []string{"org-policy"}},
		{6, "supervisor", []string{"org-policy"}},
	} {
		t.Run(fmt.Sprintf("L%d/%s", row.level, row.role), func(t *testing.T) {
			sources, err := catalog.EffectiveBlacklist(row.level, row.role)
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, source := range sources {
				for _, entry := range source.Rows {
					got = append(got, entry.ID)
				}
			}
			if !reflect.DeepEqual(got, row.want) {
				t.Fatalf("effective blacklist = %v, want %v", got, row.want)
			}
		})
	}
	// A fallback contributes no entries of its own, including beside an owned peer.
	if len(catalog.Levels[3].Roles["reviewer"].Blacklist) != 0 {
		t.Fatal("built-in fallback gained a blacklist")
	}
}

func TestMalformedRoleBlacklistAndOrgWideIDs(t *testing.T) {
	for _, row := range []struct{ name, entries, org, other, want string }{
		{"band", strings.ReplaceAll(blacklistEntry("bad"), "band = \"refuse\"", "band = \"allow\""), "", "", "band"},
		{"description", strings.ReplaceAll(blacklistEntry("bad"), "description = \"A role-owned restriction.\"", "description = \"\""), "", "", "description"},
		{"unknown", blacklistEntry("bad") + "unknown = true\n", "", "", "unknown field"},
		{"operator", strings.ReplaceAll(blacklistEntry("bad"), "[\"printf\", \"bad\"]", "[\"printf\", \";\"]"), "", "", "shell operators"},
		{"empty-prefix", strings.ReplaceAll(blacklistEntry("bad"), "[\"printf\", \"bad\"]", "[]"), "", "", "nonempty strings"},
		{"duplicate", blacklistEntry("bad") + blacklistEntry("bad"), "", "", "duplicate id"},
		{"cross-role", blacklistEntry("shared"), "", blacklistEntry("shared"), "unique per org"},
		{"org-collision", blacklistEntry("shared"), "\n[[hooks.blacklist]]\nid = \"shared\"\ndescription = \"Org restriction.\"\nband = \"refuse\"\n", "", "unique per org"},
		{"pattern-type", strings.ReplaceAll(blacklistEntry("bad"), "pattern_only = true", "pattern_only = \"yes\""), "", "", "pattern_only"},
		{"no-pattern", strings.ReplaceAll(blacklistEntry("bad"), "argv_prefix = [\"printf\", \"bad\"]\n", ""), "", "", "deterministic matcher"},
		{"bad-scope", blacklistEntry("bad") + "[blacklist.applies_to]\nlevels = [2]\n", "", "", "levels"},
		{"unsupported-job", blacklistEntry("bad") + "job = \"publish\"\n", "", "", "job"},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			blacklistSource(t, root, "org.toml", "schema_version = 1\nlevels = [3, 4, 5, 6]\n"+row.org)
			blacklistRole(t, root, 5, "reviewer", row.entries)
			if row.other != "" {
				blacklistRole(t, root, 3, "executor", row.other)
			}
			if _, err := Load(root); err == nil || !strings.Contains(err.Error(), row.want) {
				t.Fatalf("malformed source must fail with %q, got %v", row.want, err)
			}
		})
	}
}
