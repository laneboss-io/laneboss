package report

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/config"
)

func TestChannelSource(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "configuration")
	protected := filepath.Join(home, "orgs", "fixture")
	worktree := filepath.Join(base, "lane-a")
	rogue := filepath.Join(worktree, "nested-org")
	writeOrg := func(directory, channel string) {
		t.Helper()
		files := map[string]string{
			".laneboss/org.toml":                           "[services.discord]\nguild_id = \"123456789\"\ntoken_secret = \"REPORT_BOT\"\n",
			".laneboss/instances/top-a/instance.toml":      "name = \"top-a\"\nlevel = 5\n",
			".laneboss/shared/services/discord-roles.toml": fmt.Sprintf("schema_version = 1\n[roles.top-a]\ninstance = \"top-a\"\nchannel_id = %q\nchannel_name = \"reports\"\nstate_file = \"state.json\"\nevents_file = \"events.jsonl\"\nform_doorbell = \"forms.json\"\nmembers = [{user_id = \"987654321\", authority = \"decide\"}]\n", channel),
		}
		for name, data := range files {
			filename := filepath.Join(directory, name)
			if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	number := binary.BigEndian.Uint64(random[:])>>1 | 1
	trustedID, rogueID := fmt.Sprint(number), fmt.Sprint(number+1)
	writeOrg(protected, trustedID)
	writeOrg(worktree, rogueID)
	writeOrg(rogue, rogueID)
	c := &config.Configuration{Home: home, ConfigDir: filepath.Join(home, "configs", "fixture"), Data: map[string]any{"organisation": "fixture"}}
	for _, row := range []struct {
		name, cwd, override string
	}{
		{"protected-control", protected, ""},
		{"lane-working-directory", worktree, ""},
		{"lane-org-override", worktree, rogue},
		{"lane-metadata-override", worktree, filepath.Join(rogue, ".laneboss")},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Chdir(row.cwd)
			t.Setenv("LANEBOSS_ORG", row.override)
			id, installed, err := discordChannel(orgDirectory(c), "supervisor:top-a", nil)
			if err != nil {
				t.Fatalf("Discord discovery failed: %s", err)
			}
			if !installed || id != trustedID {
				t.Fatal("Discord discovery used lane-controlled settings instead of the protected configuration")
			}
		})
	}
	// A selected org without a matching role must not fall back to a lane's
	// matching role, and no org selection must not invent an installation.
	t.Chdir(worktree)
	t.Setenv("LANEBOSS_ORG", rogue)
	if err := os.WriteFile(filepath.Join(protected, ".laneboss/shared/services/discord-roles.toml"), []byte("schema_version = 1\nroles = {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, installed, err := discordChannel(orgDirectory(c), "supervisor:top-a", nil); err != nil || installed {
		t.Fatal("a missing protected role was replaced by a lane-controlled role")
	}
	delete(c.Data, "organisation")
	if _, installed, err := discordChannel(orgDirectory(c), "supervisor:top-a", nil); err != nil || installed {
		t.Fatal("a lane installed Discord without a configured organisation")
	}
	c.Data["organisation"] = "uninstalled"
	if _, installed, err := discordChannel(orgDirectory(c), "supervisor:top-a", nil); err != nil || installed {
		t.Fatal("a missing protected org installed a lane-controlled Discord channel")
	}
}
