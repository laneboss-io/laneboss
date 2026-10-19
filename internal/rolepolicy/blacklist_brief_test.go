package rolepolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBlacklistBriefFallbackAndRefresh(t *testing.T) {
	root := t.TempDir()
	blacklistSource(t, root, "org.toml", "schema_version = 1\nlevels = [3, 4, 5, 6]\n")
	blacklistSource(t, root, "shared/protocol/rules.md", "# Shared\nFollow the rules.\n")
	blacklistSource(t, root, "L3/protocol/rules.md", "# Level\nWork within the brief.\n")
	blacklistRole(t, root, 5, "reviewer", blacklistEntry("higher-rule"))
	data := map[string]any{"org_dir": root}
	selected, err := Start("", data, "3", "executor", "supervisor", []string{"codex"})
	if err != nil {
		t.Fatal(err)
	}
	paths := func(selection *Selection, task bool) []string {
		t.Helper()
		var prefix []byte
		var err error
		if task {
			prefix, err = selection.Prefix()
		} else {
			prefix, err = selection.PolicyWith("")
		}
		if err != nil {
			t.Fatal(err)
		}
		_, section, found := strings.Cut(string(prefix), "## What your org hook refuses\n")
		if !found || !strings.Contains(section, "Run `laneboss org blacklist list` first") {
			t.Fatal("the brief must tell the agent to read its rules first")
		}
		if strings.Contains(section, "## Your task") != task {
			t.Fatal("the generated section must preserve task and automatic-idle ordering")
		}
		got := []string{}
		for _, line := range strings.Split(section, "\n") {
			if strings.HasPrefix(line, "- `") {
				got = append(got, strings.TrimSuffix(strings.TrimPrefix(line, "- `"), "`"))
			}
		}
		return got
	}
	org := filepath.Join(root, ".laneboss/org.toml")
	higher := filepath.Join(root, ".laneboss/L5/roles/reviewer.toml")
	if got := paths(selected, true); !reflect.DeepEqual(got, []string{org, higher}) {
		t.Fatalf("fallback must list existing sources only: %v", got)
	}
	payload := map[string]any{}
	selected.Record(payload)
	// Resume/turn share Previous. A new higher source appears in their next
	// prefix, while the already-rendered start selection remains unchanged.
	blacklistRole(t, root, 4, "supervisor", "")
	next, err := Previous("", data, payload, []string{"codex"})
	if err != nil {
		t.Fatal(err)
	}
	stream := filepath.Join(root, ".laneboss/L4/roles/supervisor.toml")
	for _, task := range []bool{true, false} {
		if got := paths(next, task); !reflect.DeepEqual(got, []string{org, stream, higher}) {
			t.Fatalf("the next run must refresh source paths, including empty sources: %v", got)
		}
	}
	if got := paths(selected, true); !reflect.DeepEqual(got, []string{org, higher}) {
		t.Fatal("a start's source-path snapshot must not change retroactively")
	}
	kept := map[string][]byte{}
	for _, input := range next.Inputs {
		kept[input.Path] = input.Bytes
	}
	for _, relative := range []string{".laneboss/L4/roles/supervisor.toml", ".laneboss/L5/roles/reviewer.toml"} {
		want, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kept[relative], want) {
			t.Fatalf("effective source bytes must be retained for %s", relative)
		}
	}
}
