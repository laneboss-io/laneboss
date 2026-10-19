package orghook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedRoutesKeepBoundary(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "")
	root := t.TempDir()
	inst := &instance{home: filepath.Join(root, ".laneboss")}
	if err := os.MkdirAll(filepath.Join(inst.home, "instances"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ path, route string }{
		{"shared/state/lanes/peer/mail/entry.md", "laneboss lane send"},
		{"shared/state/reports/terminals/human.json", "laneboss report"},
		{"shared/state/owner-discord.events.top.jsonl", "laneboss report"},
		{"org.toml", "Leave Laneboss policy and records unchanged and report the requested change to the supervisor."},
	} {
		target := filepath.Join(inst.home, row.path)
		for _, raw := range []bool{false, true} {
			var reason string
			var err error
			if raw {
				reason, err = builtInRawWriteRefusal(inst, "touch "+shellQuote(target), root, nil)
			} else {
				reason, err = builtInWriteRefusal(inst, []fileEffect{{word: target, directory: root}})
			}
			if err != nil || !strings.HasPrefix(reason, "[blacklist:laneboss-files] Refuses:") || !strings.HasSuffix(reason, "\nInstead: "+row.route) {
				t.Fatalf("protected write lost its refusal or route (raw=%v, path=%s): %q %v", raw, row.path, reason, err)
			}
		}
	}
	ordinary := filepath.Join(root, "ordinary.txt")
	if reason, err := builtInWriteRefusal(inst, []fileEffect{{word: ordinary, directory: root}}); err != nil || reason != "" {
		t.Fatal("refusal wording must not widen the protected-file boundary")
	}
}
