package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/peers"
	"laneboss.io/laneboss/internal/testdata"
)

func ownerFileFixture(t *testing.T, path string) (*config.Configuration, *eventstore.Configuration) {
	t.Helper()
	fixture := testdata.OpenStore(t)
	t.Setenv("LANEBOSS_HOME", fixture.Config.Home)
	t.Setenv("LANEBOSS_STATE_HOME", fixture.Config.StateHome)
	t.Setenv("LANEBOSS_CONFIG", fixture.Config.Name)
	filename := filepath.Join(fixture.Config.Directory, "config.toml")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte("owner_channel = \"owner\"\n"), data...)
	data = append(data, []byte(fmt.Sprintf("\n[owner_channels.owner]\nkind = \"file\"\npath = %q\n[supervisors.mini]\nlevel = 4\nrunner = \"fixture\"\n", path))...)
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(fixture.Config.Name)
	if err != nil {
		t.Fatal(err)
	}
	return c, fixture.Config
}

func TestFileOwnerChannelRouting(t *testing.T) {
	for _, row := range []struct {
		name, starter, recipient string
		level                    int
		owner                    bool
	}{
		{"l3-to-l4", "supervisor:mini", "supervisor:mini", 3, false},
		{"l3-top-of-chain", "human", "human", 3, true},
		{"l6-top-of-chain", "human", "human", 6, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			c, store := ownerFileFixture(t, "owner/queue.jsonl")
			from := caller.Principal{ID: "lane:source", Level: row.level, Starter: row.starter}
			recorded := map[string]caller.Principal{from.ID: from, "supervisor:mini": {ID: "supervisor:mini", Level: 4}}
			to := target(c, from, recorded)
			if to.ID != row.recipient || to.ID == "supervisor:mini" && to.Level != 4 {
				t.Fatalf("report route = %+v, want %s", to, row.recipient)
			}
			installed, err := Installed(c.Name, to.ID)
			if err != nil || installed["file"] != row.owner {
				t.Fatalf("report-line discovery must match recipient routing: %v, %v", installed, err)
			}
			peerChannels, err := peers.Channels(c, to.ID)
			if err != nil || peerChannels["file"] != row.owner {
				t.Fatalf("peer discovery must match report delivery: %v, %v", peerChannels, err)
			}
			path := filepath.Join(c.StateDir, "owner/queue.jsonl")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			before := []byte("{\"text\":\"previous owner record\"}\n")
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			body := []byte("Actual report bytes for " + t.Name())
			var stdout, stderr bytes.Buffer
			if code := sendReport(c, store, from, to, row.level, false, body, nil, &stdout, &stderr); code != 0 {
				t.Fatalf("report delivery exit = %d: %s; %s", code, &stdout, &stderr)
			}
			decoder := json.NewDecoder(&stdout)
			for _, name := range []string{"dashboard", "discord", "file", "terminal"} {
				var outcome Delivery
				if err := decoder.Decode(&outcome); err != nil || outcome.Channel != name {
					t.Fatalf("missing channel outcome for %s: %+v, %v", name, outcome, err)
				}
				if name == "file" {
					want := "skipped"
					if row.owner {
						want = "delivered"
					}
					if outcome.Status != want {
						t.Fatalf("file outcome = %s, want %s", outcome.Status, want)
					}
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(data, before) {
				t.Fatal("delivery overwrote the existing owner queue")
			}
			if row.owner {
				var payload eventstore.Object
				if err := json.Unmarshal(data[len(before):], &payload); err != nil || payload["text"] != string(body) || payload["to"] != "human" || payload["from"] != from.ID {
					t.Fatalf("the state-root owner queue lost the actual report: %v, %v", payload, err)
				}
			} else if !bytes.Equal(data, before) {
				t.Fatal("an L3-to-L4 report changed the owner queue")
			}
			if _, err := os.Stat(filepath.Join(c.ConfigDir, "owner/queue.jsonl")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("report touched the old configuration-root owner queue: %v", err)
			}
		})
	}
}

func TestFileOwnerChannelSymlinkEscape(t *testing.T) {
	c, store := ownerFileFixture(t, "alias/queue.jsonl")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(c.StateDir, "alias")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := sendReport(c, store, caller.Principal{ID: "instance:root", Level: 6}, caller.Principal{ID: "human"}, 6, false, []byte(t.Name()), nil, &stdout, &stderr)
	if code != 4 || !strings.Contains(stdout.String(), "channel paths must not contain symbolic links") {
		t.Fatalf("a state-root symlink must fail only file delivery: exit=%d, %s; %s", code, &stdout, &stderr)
	}
	for _, path := range []string{filepath.Join(outside, "queue.jsonl"), filepath.Join(c.ConfigDir, "alias/queue.jsonl")} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused owner channel wrote outside its state root: %v", err)
		}
	}
}

func TestFileOwnerChannelPathValidation(t *testing.T) {
	c, _ := ownerFileFixture(t, "owner/queue.jsonl")
	valid, err := os.ReadFile(c.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	for i, path := range []string{"../escape.jsonl", "owner/../../escape.jsonl", "/escape.jsonl", "owner/./queue.jsonl", "owner\\queue.jsonl"} {
		t.Run(fmt.Sprintf("invalid-%d", i), func(t *testing.T) {
			data := bytes.Replace(valid, []byte(`path = "owner/queue.jsonl"`), []byte(fmt.Sprintf("path = %q", path)), 1)
			if bytes.Equal(data, valid) {
				t.Fatal("the validation control did not change the owner path")
			}
			if err := os.WriteFile(c.ConfigFile, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := config.Load(c.Name)
			var invalid *config.Error
			if !errors.As(err, &invalid) || invalid.Field != "owner_channels.owner.path" {
				t.Fatalf("the escaping path must fail owner path validation: %v", err)
			}
		})
	}
	if err := os.WriteFile(c.ConfigFile, valid, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(c.Name); err != nil {
		t.Fatalf("the valid relative owner path control must still load: %v", err)
	}
}
