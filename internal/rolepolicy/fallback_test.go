package rolepolicy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/settings"
)

func TestFallbackCeilingAndBinding(t *testing.T) {
	root := t.TempDir()
	write := func(relative, text string) {
		t.Helper()
		filename := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(".laneboss/org.toml", "schema_version = 1\nlevels = [4]\n")
	write(".laneboss/shared/protocol/rules.md", "# Shared\n\nKeep the review independent.\n")
	write(".laneboss/L4/protocol/rules.md", "# Level\n\nReview the assigned scope.\n")
	body, err := library.ReadFile("library/L4/supervisor.md")
	if err != nil {
		t.Fatal(err)
	}
	write(".laneboss/L4/roles/supervisor.md", string(body))
	write(".laneboss/L4/roles/supervisor.toml", "drivers = [\"claude\"]\n")
	write(".laneboss/settings.toml", "tool_deny_add = [\"Write\"]\n")
	data := map[string]any{"org_dir": root}
	if _, err := Start("", data, "4", "reviewer", "supervisor", []string{"codex"}); err == nil || !strings.Contains(err.Error(), "runner driver is not allowed") {
		t.Fatal("a fallback must refuse a driver outside the org ceiling", err)
	}
	selected, err := Start("", data, "4", "reviewer", "supervisor", []string{"claude"})
	if err != nil {
		t.Fatal("the intersected driver must remain usable", err)
	}
	resolved, err := settings.Resolve(root, 4, "reviewer", "", map[string]any{}, nil)
	if err != nil || strings.Join(settings.Strings(resolved.Values["tool_deny_add"]), ",") != "Write" || len(settings.Strings(resolved.Values["tool_allow_add"])) != 0 {
		t.Fatal("fallback must preserve org tool restrictions without adding rights", err)
	}
	payload := map[string]any{}
	selected.Record(payload)
	if err := Revet("", data, payload, []string{"claude"}); err != nil {
		t.Fatal("unchanged org policy must revalidate", err)
	}
	write(".laneboss/L4/roles/supervisor.toml", "drivers = [\"claude\", \"claudock\"]\n")
	if err := Revet("", data, payload, []string{"claude"}); err == nil || !strings.Contains(err.Error(), "sources changed after the run was planned") {
		t.Fatal("fallback planning must bind the actual org ceiling bytes", err)
	}
}

func TestBuiltinFallbackKeepsExactDriverGate(t *testing.T) {
	for _, level := range []int{4, 5} {
		t.Run(fmt.Sprintf("L%d", level), func(t *testing.T) {
			root := t.TempDir()
			write := func(relative, text string) {
				t.Helper()
				filename := filepath.Join(root, relative)
				if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(".laneboss/org.toml", fmt.Sprintf("schema_version = 1\nlevels = [%d]\n", level))
			write(".laneboss/shared/protocol/rules.md", "# Shared\n\nKeep the review independent.\n")
			write(fmt.Sprintf(".laneboss/L%d/protocol/rules.md", level), "# Level\n\nReview the assigned scope.\n")
			data := map[string]any{"org_dir": root}
			selectDriver := func(driver string) (*Selection, error) {
				return Start("", data, fmt.Sprint(level), "reviewer", "supervisor", []string{driver})
			}
			builtinDriver := "codex"
			if level == 5 {
				builtinDriver = "claude"
			}
			selection, err := selectDriver(builtinDriver)
			if err != nil {
				t.Fatalf("built-in reviewer must resolve without installed roles: %v", err)
			}
			body, err := library.ReadFile(fmt.Sprintf("library/L%d/reviewer.md", level))
			if err != nil {
				t.Fatal(err)
			}
			drivers, err := library.ReadFile(fmt.Sprintf("library/L%d/reviewer.toml", level))
			if err != nil {
				t.Fatal(err)
			}
			if selection.Role == nil || !bytes.Equal(selection.Role.Bytes, body) || !bytes.Equal(selection.Role.DriverBytes, drivers) {
				t.Fatal("fallback must retain the real embedded role and driver sources")
			}
			prefix, err := selection.Prefix()
			if err != nil || !bytes.Contains(prefix, body) {
				t.Fatal("the real built-in role must reach the lane brief", err)
			}
			for _, input := range selection.Inputs[len(selection.Inputs)-2:] {
				if !strings.HasPrefix(input.Path, fmt.Sprintf("builtin/L%d/roles/reviewer.", level)) {
					t.Fatalf("embedded provenance must not claim an org file: %s", input.Path)
				}
			}
			if _, err := selectDriver("unlisted-review-driver"); err == nil || !strings.Contains(err.Error(), "runner driver is not allowed") {
				t.Fatal("fallback must enforce its driver list", err)
			}
			if level == 5 {
				if _, err := selectDriver("codex"); err == nil || !strings.Contains(err.Error(), "runner driver is not allowed") {
					t.Fatal("the L5 reviewer must retain its existing driver restriction", err)
				}
			}
			rolePath := fmt.Sprintf(".laneboss/L%d/roles/reviewer", level)
			write(rolePath+".md", string(body)+"\nOrg-owned review instruction.\n")
			write(rolePath+".toml", "drivers = [\"org-review-driver\"]\n")
			selection, err = selectDriver("org-review-driver")
			if err != nil || !strings.HasPrefix(selection.Role.Path, ".laneboss/") || !bytes.Contains(selection.Role.Bytes, []byte("Org-owned review instruction.")) {
				t.Fatal("org sources must take precedence over the embedded pair", err)
			}
			if _, err := selectDriver(builtinDriver); err == nil || !strings.Contains(err.Error(), "runner driver is not allowed") {
				t.Fatal("an override must not inherit the built-in driver's authority", err)
			}
			if err := os.Remove(filepath.Join(root, rolePath+".toml")); err != nil {
				t.Fatal(err)
			}
			if _, err := selectDriver(builtinDriver); err == nil || !strings.Contains(err.Error(), "TOML driver file") {
				t.Fatal("an incomplete org pair must fail instead of falling back", err)
			}
		})
	}
}
