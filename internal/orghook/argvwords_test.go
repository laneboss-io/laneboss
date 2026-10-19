package orghook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgvWordsBoundaries(t *testing.T) {
	for _, row := range []struct {
		name  string
		words []string
		argv  []string
		want  bool
	}{
		{"basename", []string{"codex", "exec"}, []string{"/opt/tools/codex", "-c", "k=v", "exec"}, true},
		{"program-anchor", []string{"codex", "exec"}, []string{"git", "commit", "-m", "codex exec"}, false},
		{"later-program", []string{"codex", "exec"}, []string{"git", "codex", "exec"}, false},
		{"partial-program", []string{"codex", "exec"}, []string{"codex-helper", "exec"}, false},
		{"partial-word", []string{"codex", "exec"}, []string{"codex", "exec-only"}, false},
		{"quoted-argument", []string{"codex", "exec"}, []string{"codex", "--note", "exec later"}, false},
		{"literal-pattern", []string{"codex", "ex*"}, []string{"codex", "exec"}, false},
		{"ordered", []string{"aws", "ec2", "run-instances"}, []string{"aws", "--region", "r", "ec2", "--debug", "run-instances"}, true},
		{"reversed", []string{"aws", "ec2", "run-instances"}, []string{"aws", "run-instances", "ec2"}, false},
		{"empty-command", []string{"codex", "exec"}, nil, false},
		{"empty-pattern", nil, []string{"codex", "exec"}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := argvWordsMatch(row.argv, row.words); got != row.want {
				t.Fatalf("whole-word ordered match = %v, want %v", got, row.want)
			}
		})
	}
	row := blacklistRule{argvWords: []string{"codex", "exec"}}
	for _, sample := range []struct {
		raw  string
		want bool
	}{
		{"true && codex -c k=v exec", true},
		{"git commit -m \"codex exec\"", false},
		{"codex --note 'exec later'", false},
		{"codex --version; printf '%s' exec", false},
	} {
		matched, err := blacklistMatches(row, &instance{}, action{raw: sample.raw}, nil, nil, nil, nil, "/")
		if err != nil || matched != sample.want {
			t.Fatalf("raw fallback must retain argv boundaries: matched=%v want=%v err=%v", matched, sample.want, err)
		}
	}
	for _, sample := range []struct {
		argv []any
		want bool
	}{
		{[]any{"codex", "-c", "k=v", "exec"}, true},
		{[]any{"codex", "--note", "exec later"}, false},
		{[]any{"git", "commit", "-m", "codex exec"}, false},
	} {
		event := map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec_command", "tool_input": map[string]any{"argv": sample.argv}}
		act, err := eventAction(event, "codex", "/")
		if err != nil {
			t.Fatal(err)
		}
		matched, err := blacklistMatches(row, &instance{}, act, nil, nil, nil, nil, "/")
		if err != nil || matched != sample.want {
			t.Fatalf("literal argv arrays must preserve whole words in the fallback: matched=%v want=%v err=%v", matched, sample.want, err)
		}
	}
}

func TestArgvWordsSource(t *testing.T) {
	for _, row := range []struct {
		name, value, extra string
		valid              bool
	}{
		{"valid-pattern-only", `["codex", "exec"]`, "", true},
		{"empty", `[]`, "", false},
		{"scalar", `"codex exec"`, "", false},
		{"non-string", `["codex", 1]`, "", false},
		{"operator", `["codex", "&&", "exec"]`, "", false},
		{"redirect", `["codex", ">"]`, "", false},
		{"mixed-matchers", `["codex", "exec"]`, "argv_prefix = [\"codex\", \"exec\"]\n", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			home := t.TempDir()
			source := "schema_version = 1\n[hooks]\nmode = \"blacklist\"\n[[hooks.blacklist]]\nid = \"fixture\"\ndescription = \"Fixture session control.\"\nband = \"refuse\"\npattern_only = true\nargv_words = " + row.value + "\n" + row.extra
			if err := os.WriteFile(filepath.Join(home, "org.toml"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			policy, err := parseHookBlacklist(home)
			if row.valid {
				if err != nil || len(policy.blacklist) != 1 || !policy.blacklist[0].patternOnly || !blacklistHasDeterministic(policy.blacklist[0]) || len(policy.blacklist[0].argvWords) != 2 {
					t.Fatalf("valid ordered-word source lost its deterministic matcher: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "argv_words") {
				t.Fatalf("invalid ordered-word source needs its field diagnostic: %v", err)
			}
		})
	}
}
