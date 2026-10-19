package orgtree

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/orghook"
)

// Existing-org compatibility fixtures opt into the former shared policy.
const initialSharedHookRules = `schema_version = 1

[[rules]]
id = "declared-writes"
kind = "write-scope"
paths = ["{writable_repos}"]
deny_paths = ["{hook_paths}"]

[[rules]]
id = "secret-files"
kind = "secret-read"
names = ["{secret_names}", ".env", ".env.*", "*.key", "*.pem"]
`

var legacySharedRefusals = map[string]string{
	"declared-writes": `id = "declared-writes"
refuses = "Writes outside declared repositories, writes to hook policy and settings, and uninspectable commands."
why = "An agent's writes must stay in its scope and cannot change the guard that enforces it."
instead = "Write in a declared repository with a supported file tool; leave policy changes to the supervisor."
examples_allowed = ["Edit a source file inside a declared writable repository."]
examples_refused = ["Write in another identity's repository.", "Replace shared/hooks/rules.toml."]
[applies_to]
levels = [3]
identities = ["*"]
`,
	"secret-files": `id = "secret-files"
refuses = "Reading or printing a file whose name is protected as a secret."
why = "Secret values must remain outside agent output at every level."
instead = "Refer to secrets by name only; read a permitted non-secret source or ask the supervisor to supply a public or redacted input."
examples_allowed = ["Read README.md.", "Print the literal name of a secret without reading its file."]
examples_refused = ["Read .env.", "Print a file listed in secret_names."]
[applies_to]
levels = [3]
identities = ["*"]
`,
	"runner-launches": `id = "runner-launches"
refuses = "Starting an agent runner directly from an agent tool call."
why = "The launcher must check and pass the org's mandatory hook settings before a runner starts."
instead = "Have the supervisor start the instance through the checked launcher command."
examples_allowed = ["Run git status."]
examples_refused = ["Start claude directly.", "Start codex directly."]
[applies_to]
levels = [3]
identities = ["*"]
`,
}

func TestOrgInitRawTaskBlacklist(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "")
	root := filepath.Join(t.TempDir(), "rawpack")
	name := "rawpack"
	if _, err := initOrg(root, "3-6", &name); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, home, "org.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := decodeTOML(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	hooks := data["hooks"].(map[string]any)
	if hooks["mode"] != "blacklist" {
		t.Fatal("new orgs must retain blacklist mode")
	}
	rows, ok := array(hooks["blacklist"])
	if !ok || len(rows) != 12 || strings.Count(string(raw), "\n[[hooks.blacklist]]\n") != 12 {
		t.Fatal("org init must write twelve active source entries")
	}
	want := map[string][]string{
		"raw-codex-exec": {"codex", "exec"}, "raw-claude-p": {"claude", "-p"},
		"raw-claude-print": {"claude", "--print"}, "raw-claudock-run": {"claudock", "run"},
		"raw-tmux-new-session": {"tmux", "new-session"}, "raw-tmux-new": {"tmux", "new"},
		"raw-tmux-kill-session": {"tmux", "kill-session"}, "raw-tmux-send-keys": {"tmux", "send-keys"},
		"raw-tmux-attach": {"tmux", "attach"}, "raw-tmux-attach-session": {"tmux", "attach-session"},
		"raw-aws-run-instances":       {"aws", "ec2", "run-instances"},
		"raw-gcloud-instances-create": {"gcloud", "compute", "instances", "create"},
	}
	for _, value := range rows {
		row := value.(map[string]any)
		id, _ := row["id"].(string)
		prefix, _ := array(row["argv_words"])
		words := make([]string, len(prefix))
		for i, word := range prefix {
			words[i], _ = word.(string)
		}
		if !reflect.DeepEqual(words, want[id]) || row["band"] != "refuse" || row["description"] == "" || row["pattern_only"] != true {
			t.Fatalf("missing or widened raw-task source entry: %s", id)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatal("org init omitted raw-task entries")
	}
	if _, err := os.Lstat(filepath.Join(root, home, "shared", "hooks", "rules.toml")); !os.IsNotExist(err) {
		t.Fatal("new orgs must not retain the broad legacy runner prefix")
	}
}

func TestOrgInitOnlyPackPolicy(t *testing.T) {
	for _, key := range []string{"LANEBOSS_CONFIG", "LANEBOSS_INSTANCE", "LANEBOSS_LANE", "LANEBOSS_ROLE"} {
		t.Setenv(key, "")
	}
	root := filepath.Join(t.TempDir(), "minimal-policy")
	name := "minimal-policy"
	if _, err := initOrg(root, "3-6", &name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("fixture input without credentials\n"), 0600); err != nil {
		t.Fatal(err)
	}
	assertSources := func() {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, home, "org.toml"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(raw), "[[hooks.blacklist]]") != 12 || strings.Contains(string(raw), "allowed_tools") {
			t.Fatal("fresh org policy must contain exactly the twelve pack entries and no allowlist field")
		}
		for _, id := range []string{"remote-push", "credential-files", "destructive-history"} {
			if strings.Contains(string(raw), id) {
				t.Fatalf("org init retained starter example %s", id)
			}
		}
		for _, layer := range []string{"shared", "L3", "L4", "L5", "L6"} {
			for _, part := range []string{"hooks/rules.toml", "refusals"} {
				if _, err := os.Lstat(filepath.Join(root, home, layer, part)); !os.IsNotExist(err) {
					t.Fatalf("org init seeded %s/%s: %v", layer, part, err)
				}
			}
		}
	}
	assertSources()
	for _, format := range []string{"text", "json"} {
		var stdout, stderr bytes.Buffer
		args := []string{root}
		want := ""
		if format == "json" {
			args = append(args, "--format", "json")
			want = "[]\n"
		}
		if code := orghook.Run("refusals", args, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("fresh org refusals (%s) exited %d: %s", format, code, stderr.String())
		}
		if stdout.String() != want || stderr.Len() != 0 {
			t.Fatalf("fresh org refusals (%s) must be empty without warnings: stdout=%q stderr=%q", format, stdout.String(), stderr.String())
		}
	}
	assertSources()
	if _, err := renderOrg(root); err != nil {
		t.Fatal(err)
	}
	assertSources()
	if report := validateOrg(root); !report.Valid || len(report.Problems) != 0 || len(report.Warnings) != 0 {
		t.Fatalf("absent rule sources must validate without warnings: %+v", report)
	}
	checks, err := orghook.CheckHooks(root)
	if err != nil || checks["ok"] != true {
		t.Fatalf("absent rule sources must pass check-hooks: %v %v", checks, err)
	}
	for level := 3; level <= 6; level++ {
		directory := filepath.Join(root, home, "instances", exampleNames[level])
		for _, runner := range []string{"claude", "codex"} {
			for _, row := range []struct{ tool, path, want string }{
				{"Read", filepath.Join(root, ".env"), "allow"},
				{"Write", filepath.Join(root, home, "org.toml"), "deny"},
				{"Write", filepath.Join(root, home, "shared", "services", "decisions.sqlite"), "deny"},
				{"Write", filepath.Join(root, home, "shared", "hooks", "rules.toml"), "deny"},
			} {
				t.Run(fmt.Sprintf("L%d/%s/%s/%s", level, runner, row.tool, filepath.Base(row.path)), func(t *testing.T) {
					tool, field := "Bash", "command"
					if runner == "codex" {
						tool, field = "exec_command", "cmd"
					}
					command := "touch"
					if row.tool == "Read" {
						command = "cat"
					}
					command += " '" + strings.ReplaceAll(row.path, "'", "'\\''") + "'"
					event, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": directory,
						"tool_name": tool, "tool_input": map[string]any{field: command}})
					if err != nil {
						t.Fatal(err)
					}
					var stdout, stderr bytes.Buffer
					if code := orghook.Run("hook", []string{"--runner", runner, "--instance", filepath.Join(directory, "instance.toml")}, bytes.NewReader(event), &stdout, &stderr); code != 0 {
						t.Fatalf("hook failed: %s", stderr.String())
					}
					var output struct {
						Hook map[string]any `json:"hookSpecificOutput"`
					}
					if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
						t.Fatal(err)
					}
					if output.Hook["permissionDecision"] != row.want {
						t.Fatalf("fresh policy lost its read/protected-write behavior: %v", output.Hook)
					}
					if row.want == "deny" && !strings.HasPrefix(fmt.Sprint(output.Hook["permissionDecisionReason"]), "[blacklist:laneboss-files] Refuses:") {
						t.Fatalf("write must be refused by the built-in protection: %v", output.Hook)
					}
				})
			}
		}
	}
}

func TestRawPackNoJudgeWarning(t *testing.T) {
	for _, name := range []string{"LANEBOSS_CONFIG", "LANEBOSS_INSTANCE", "LANEBOSS_LANE", "LANEBOSS_ROLE"} {
		t.Setenv(name, "")
	}
	root := filepath.Join(t.TempDir(), "plain-allow")
	name := "plain-allow"
	if _, err := initOrg(root, "3", &name); err != nil {
		t.Fatal(err)
	}
	// A present, disabled guide previously made the pack add an unscored
	// blacklist warning. Ordinary decision guidance correctly adds nothing.
	guide := filepath.Join(root, home, "shared", "services", "guide.toml")
	if err := os.WriteFile(guide, []byte("enabled = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := renderOrg(root); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, home, "instances", "L3-lane-example")
	invoke := func(runner string) map[string]any {
		t.Helper()
		tool, field := "Bash", "command"
		if runner == "codex" {
			tool, field = "exec_command", "cmd"
		}
		event, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": directory,
			"tool_name": tool, "tool_input": map[string]any{field: "printf '%s' ordinary-work"}})
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := orghook.Run("hook", []string{"--runner", runner, "--instance", filepath.Join(directory, "instance.toml")}, bytes.NewReader(event), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("hook failed: %s", stderr.String())
		}
		var result struct {
			Output map[string]any `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Output
	}
	for _, runner := range []string{"claude", "codex"} {
		output := invoke(runner)
		if output["permissionDecision"] != "allow" || output["permissionDecisionReason"] != "org policy permits this tool call" || output["additionalContext"] != nil {
			t.Fatalf("pattern-only pack added a judge warning to unrelated work: %v", output)
		}
	}
	// An ordinary authored entry must still warn when its judge is disabled.
	// This control catches an implementation that skips all blacklist scoring.
	source := filepath.Join(root, home, "org.toml")
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "pattern_only = true") != 12 {
		t.Fatal("the installed pack must explicitly opt out of judge scoring")
	}
	writeRawpackSource(t, source, strings.Replace(string(raw), "pattern_only = true", "pattern_only = false", 1))
	if _, err := renderOrg(root); err != nil {
		t.Fatal(err)
	}
	for _, runner := range []string{"claude", "codex"} {
		output := invoke(runner)
		reason, _ := output["permissionDecisionReason"].(string)
		context, _ := output["additionalContext"].(string)
		if output["permissionDecision"] != "allow" || !strings.Contains(reason, "the blacklist judge has a warning") || !strings.Contains(context, "[blacklist-judge]") {
			t.Fatalf("an authored scored entry lost its judge-unavailable control: %v", output)
		}
	}
}

func TestRawTaskPackExplicitSourceOptIn(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "")
	root := filepath.Join(t.TempDir(), "existing")
	name := "existing"
	if _, err := initOrg(root, "3", &name); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, home, "org.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := decodeTOML(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Model a pre-pack org, retaining an unrelated owner-authored entry.
	hooks := data["hooks"].(map[string]any)
	custom := map[string]any{"id": "custom", "description": "Keep fixture publishing local.", "band": "refuse", "argv_prefix": []any{"git", "push"}, "instead": "Ask the supervisor."}
	hooks["blacklist"] = []any{custom}
	text, err := encodeTOML(data, orgOrder)
	if err != nil {
		t.Fatal(err)
	}
	writeRawpackSource(t, path, text)
	sharedPath := filepath.Join(root, home, "shared", "hooks", "rules.toml")
	legacyShared := initialSharedHookRules + "\n[[rules]]\nid = \"runner-launches\"\nkind = \"command-pattern\"\npatterns = [[\"claude\"], [\"codex\"]]\n"
	writeRawpackSource(t, sharedPath, legacyShared)
	// Install the old rule catalog explicitly, as an existing org would have it.
	for id, description := range legacySharedRefusals {
		writeRawpackSource(t, filepath.Join(root, home, "shared", "refusals", id+".toml"), description)
	}
	if _, err := renderOrg(root); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(path)
	if err != nil || string(kept) != text {
		t.Fatal("render silently migrated an existing org source")
	}
	shared, err := os.ReadFile(sharedPath)
	if err != nil || string(shared) != legacyShared {
		t.Fatal("render silently changed the existing broad legacy policy")
	}
	// The documented opt-in is an owner source edit, followed by render.
	hooks["blacklist"] = append([]any{custom}, rawTaskBlacklist()...)
	optedIn, err := encodeTOML(data, orgOrder)
	if err != nil {
		t.Fatal(err)
	}
	writeRawpackSource(t, path, optedIn)
	writeRawpackSource(t, sharedPath, initialSharedHookRules)
	if _, err := renderOrg(root); err != nil {
		t.Fatal(err)
	}
	kept, err = os.ReadFile(path)
	if err != nil || string(kept) != optedIn || strings.Count(string(kept), "\n[[hooks.blacklist]]\n") != 13 {
		t.Fatal("the explicit source opt-in lost an entry or changed its bytes")
	}
	shared, err = os.ReadFile(sharedPath)
	if err != nil || string(shared) != initialSharedHookRules {
		t.Fatal("the explicit opt-in did not retain the reviewed shared source edit")
	}
}

func writeRawpackSource(t *testing.T, path, text string) {
	t.Helper()
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0444); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if err := os.Chmod(path, mode|0200); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, mode); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
