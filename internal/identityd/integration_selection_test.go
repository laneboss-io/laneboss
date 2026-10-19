package identityd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
)

func TestAbsentServiceDoesNotReloadPolicy(t *testing.T) {
	root := t.TempDir()
	home, states := filepath.Join(root, "config"), filepath.Join(root, "state")
	name := "no-service-probe"
	directory := filepath.Join(home, "configs", name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	// The command already parsed its service selection. This separate full
	// load deliberately fails on role policy, independently of that selection.
	input := "schema_version = 1\nname = \"" + name + "\"\norg_dir = \"" + filepath.Join(root, "missing-org") + "\"\n[runners.demo]\ncommand = [\"echo\", \"{brief}\"]\n[supervisors.top]\nlevel = 5\nrunner = \"demo\"\n"
	if err := os.WriteFile(filepath.Join(directory, "config.toml"), []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEBOSS_HOME", home)
	t.Setenv("LANEBOSS_STATE_HOME", states)
	t.Setenv("LANEBOSS_CONFIG", name)
	if _, err := config.Load(name); err == nil || !strings.Contains(err.Error(), "org_dir") {
		t.Fatal("the unrelated invalid-policy control must fail its full load")
	}
	parsed := &config.Configuration{Name: name, Home: home, StateHome: states, Data: map[string]any{"org_dir": filepath.Join(root, "missing-org")}}
	if caller.RequiresTicket(parsed, Client{}) {
		t.Fatal("ServiceSelection: unrelated role policy enabled ticket mode")
	}
	for _, selection := range []any{map[string]any{}, map[string]any{"runtime_root": "relative"}} {
		parsed.Data["identity_service"] = selection
		if !caller.RequiresTicket(parsed, Client{}) {
			t.Fatal("a present service selection lost its fail-closed ticket gate")
		}
	}
}
