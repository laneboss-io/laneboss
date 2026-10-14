package hookconfig

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArrayHooks(t *testing.T) {
	clean := map[string]any{"nested": []any{map[string]any{"model": "sample"}}}
	bad := map[string]any{"nested": []any{map[string]any{"hooks": map[string]any{}}}}
	if foreignHooks(clean, "") || !foreignHooks(bad, "") {
		t.Fatal("inline arrays must retain hook inspection")
	}
}

func TestUserPrefs(t *testing.T) {
	home := t.TempDir()
	if err := systemPrefs(home); err != nil {
		t.Fatal("clean user preferences must be accepted")
	}
	path := filepath.Join(home, "Library", "Preferences", "com.openai.codex.plist")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<plist><dict><key>hooks</key></dict></plist>"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := systemPrefs(home); err == nil {
		t.Fatal("user preference hooks must be refused")
	}
}

func TestFlagWords(t *testing.T) {
	for _, embedded := range []string{CodexTrustBypass, "prefix=" + CodexTrustBypass, "'" + CodexTrustBypass + "'", "text " + CodexTrustBypass + " tail"} {
		for _, argv := range [][]string{
			{"env", "-S", "A=1 codex exec " + embedded},
			{"env", "-C", "/tmp", "codex", "exec", embedded},
			{"sh", "-c", "c\"\"odex exec " + embedded},
			{"runner-script", "exec", embedded},
			{"codex", "exec", embedded},
		} {
			var gate CodexGate
			if _, err := gate.Prepare(argv, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "caller-supplied hook trust bypass") {
				t.Fatal("embedded caller trust flags must be refused before probing")
			}
		}
	}
}

func TestRevetShapes(t *testing.T) {
	if err := Revet([]string{"env", "A=1", "echo", "plain"}, t.TempDir(), nil); err != nil {
		t.Fatal("ordinary non-Codex commands must remain valid")
	}
	for _, option := range []string{"-S", "--split-string", "-C", "--chdir", "-P", "-0", "--block-signal", "-iu"} {
		for _, tail := range []string{"A=1 codex exec", "A=1 codex exec " + CodexTrustBypass} {
			if err := Revet([]string{"env", option, tail}, t.TempDir(), nil); err == nil {
				t.Fatal("unknown env options must fail closed")
			}
		}
	}
	for _, wrapper := range []string{"sh", "bash", "zsh", "dash", "nice", "nohup", "timeout", "stdbuf", "sudo", "xargs", "exec", "runner-script"} {
		if err := Revet([]string{wrapper, "-c", "c\"\"odex exec " + CodexTrustBypass}, t.TempDir(), nil); err == nil {
			t.Fatal("non-direct trust flags must fail closed")
		}
	}
	for _, word := range []string{"'" + CodexTrustBypass + "'", "prefix=" + CodexTrustBypass, "text " + CodexTrustBypass} {
		if err := Revet([]string{"codex", "exec", CodexTrustBypass, word}, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "embedded") {
			t.Fatal("quoted trust flags must fail closed")
		}
		if err := Revet([]string{"env", "A=" + word, "codex", "exec", CodexTrustBypass}, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "embedded") {
			t.Fatal("quoted trust flags must fail closed")
		}
	}
}

func TestOverrideValues(t *testing.T) {
	for _, value := range []string{CodexEnable, `model="sample"`, `model="gpt-6.1-sol"`, `model_reasoning_effort=high`, `values=[[{model="sample"}]]`, `model="a hook word"`, `model="sample" trailing`} {
		for _, args := range [][]string{{"-c", value}, {"--config", value}, {"--config=" + value}, {"-c" + value}, {"-c=" + value}} {
			if err := vetConfigArgs(args); err != nil {
				t.Fatal("valid non-hook config must be accepted")
			}
		}
	}
	for _, value := range []string{
		`hooks.PreToolUse=[]#features.hooks=true`, `hooks=[]`,
		`managed_dir="somewhere"`, `project_root_markers=["other"]`,
		`features.hooks=true # altered`, `features.hooks=false`,
		`values=[[{hook_source="other"}]]`, `values={managed_dir="other"}`,
		`agents.enabled=true`, `agents.worker.config_file="private-canary-value"`,
		`features.multi_agent_v2=true`, `features.collab=true`,
		`profiles.sample.agents.enabled=true`, `values=[[{agents={enabled=true}}]]`,
	} {
		for _, args := range [][]string{{"-c", value}, {"--config", value}, {"--config=" + value}, {"-c" + value}, {"-c=" + value}} {
			if err := vetConfigArgs(args); err == nil {
				t.Fatal("unvetted override keys must be refused")
			}
			argv := append([]string{"codex", "exec", CodexTrustBypass}, args...)
			if err := Revet(argv, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "command config") {
				t.Fatal("supervisor overrides must retain config checks")
			}
		}
	}
	// Empty overrides are rejected by the argv validator before key inspection.
	for _, args := range [][]string{{"-c", ""}, {"--config", ""}, {"--config="}, {"-c="}} {
		flag, _, _ := codexFlag(args[0])
		for _, check := range []func() error{
			func() error { return vetConfigArgs(args) },
			func() error {
				return Revet(append([]string{"codex", "exec", CodexTrustBypass}, args...), t.TempDir(), nil)
			},
		} {
			if err := check(); err == nil || !strings.Contains(err.Error(), "vetted argv allowlist") || !strings.Contains(err.Error(), flag) {
				t.Fatal("empty overrides must be refused by both argv gates")
			}
		}
	}
}

// Revet vets the argv allowlist before it looks for --disable plugins (TestOverrideValues pins that
// order). The allowlist reads every word after "--" as an operand: exec takes one and resume two, so
// only a resume shape reaches the plugin gate with both words after "--".
func TestPluginFlag(t *testing.T) {
	for _, argv := range [][]string{
		{"codex", "exec", CodexTrustBypass},
		{"env", "CODEX_HOME=/tmp/canary", "codex", "exec", CodexTrustBypass},
		{"codex", "exec", CodexTrustBypass, "resume", "--", "--disable", "plugins"},
	} {
		if err := Revet(argv, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "requires --disable plugins") {
			t.Fatalf("bypass without plugin disabling must be refused by the plugin gate: %q", argv)
		}
	}
	// Two operands after "--" on exec are refused by the allowlist before the plugin gate is reached.
	argv := []string{"codex", "exec", CodexTrustBypass, "--", "--disable", "plugins"}
	if err := Revet(argv, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "extra positional arguments") {
		t.Fatal("operands after -- must be refused and never count as plugin disabling")
	}
	// Control: the real flag passes the plugin gate; the later instance checks then refuse the empty home.
	argv = []string{"codex", "exec", CodexTrustBypass, "--disable", "plugins"}
	err := Revet(argv, t.TempDir(), []string{"CODEX_HOME=" + t.TempDir()})
	if err == nil || strings.Contains(err.Error(), "requires --disable plugins") || !strings.Contains(err.Error(), "config.toml") {
		t.Fatal("the plugin gate must pass when the flag is present")
	}
}

func TestSandboxRoots(t *testing.T) {
	for _, args := range [][]string{{"--add-dir", "/tmp"}, {"--add-dir=/tmp"}, {"--sandbox", "danger-full-access"}, {"--yolo"},
		{"-c", `sandbox_workspace_write.writable_roots=["/tmp"]`}, {"-c", "sandbox_workspace_write.exclude_slash_tmp=false"}} {
		if err := vetConfigArgs(args); err == nil {
			t.Fatal("additional or implicit writable roots must be refused")
		}
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	safe := "[agents]\nenabled=false\n[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n"
	for _, extra := range []string{"", "writable_roots=[]\n", "[profiles.sample.sandbox_workspace_write]\nwritable_roots=[\"/tmp\"]\n"} {
		if err := os.WriteFile(path, []byte(safe+extra), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := writableRoots(path, t.TempDir())
		if (err != nil) != (extra != "") {
			t.Fatal("sandbox root configuration must be checked by meaning")
		}
	}
	root := t.TempDir()
	home, cwd := filepath.Join(root, "org", ".codex"), filepath.Join(root, "org", "state")
	for _, directory := range []string{home, cwd} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := vetWriteRoots(home, []string{cwd}, nil); err != nil {
		t.Fatal("the isolated cwd root must remain valid")
	}
	if err := vetWriteRoots(home, []string{cwd, root}, nil); err == nil {
		t.Fatal("a temp writable root containing the org must be refused")
	}
}

func TestDefaultPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	for _, mode := range []string{":workspace", ":danger-full-access"} {
		data := "default_permissions=\"" + mode + "\"\n[agents]\nenabled=false\n[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n"
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := writableRoots(path, t.TempDir()); err == nil || !strings.Contains(err.Error(), "default_permissions") {
			t.Fatal("default_permissions must not hide unvetted roots")
		}
	}
}

func TestPermissionLayers(t *testing.T) {
	for _, item := range []struct{ key, text string }{
		{"default_permissions", "default_permissions=\"private-canary-value\"\n"},
		{"permissions", "[permissions.sample]\nvalue=\"private-canary-value\"\n"},
		{"approvals_reviewer", "approvals_reviewer=\"private-canary-value\"\n"},
		{"approval_policy", "approval_policy=\"private-canary-value\"\n"},
		{"mcp_servers", "[mcp_servers.sample]\ncommand=\"private-canary-value\"\n"},
		{"notify", "notify=[\"private-canary-value\"]\n"},
		{"use_legacy_landlock", "use_legacy_landlock=true\n"},
		{"guardianv2", "[features]\nguardianv2=true\n"},
		{"guardian_ext", "[features]\nguardian_ext=true\n"},
		{"future_permissions", "future_permissions=\"private-canary-value\"\n"},
		{"agents", "[agents]\nenabled=true\n"},
		{"agents", "[agents]\nenabled=\"private-canary-value\"\n"},
		{"agents", "[agents.worker]\nconfig_file=\"private-canary-value\"\n"},
		{"multi_agent_v2", "[features]\nmulti_agent_v2=true\n"},
		{"collab", "[features]\ncollab=true\n"},
	} {
		for _, prefix := range []string{"", "[profiles.sample]\n", "[projects.\"/fixture\"]\n"} {
			text := item.text
			if prefix != "" {
				if strings.HasPrefix(text, "[") {
					text = "[" + strings.TrimSuffix(strings.TrimPrefix(prefix, "["), "]\n") + "." + text[1:]
				} else {
					text = prefix + text
				}
			}
			for _, name := range []string{"instance/config.toml", "repository/.codex/config.toml", "system/config.toml", "system/requirements.toml", "system/managed_config.toml"} {
				path := filepath.Join(t.TempDir(), name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				err := checkConfig(path)
				if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), item.key) || strings.Contains(err.Error(), "private-canary-value") {
					t.Fatalf("permission layer must name file and key only: %s %s", name, item.key)
				}
			}
			err := plistConfig(base64.StdEncoding.EncodeToString([]byte(text)))
			if err == nil || !strings.Contains(err.Error(), item.key) || strings.Contains(err.Error(), "private-canary-value") {
				t.Fatalf("decoded preferences must name the refused key only: %s", item.key)
			}
		}
		path := filepath.Join(t.TempDir(), "preferences.plist")
		data := "<plist><dict><key>" + item.key + "</key><string>private-canary-value</string></dict></plist>"
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := inspectPlist(path); err == nil || !strings.Contains(err.Error(), item.key) || strings.Contains(err.Error(), "private-canary-value") {
			t.Fatalf("direct preferences must name the refused key only: %s", item.key)
		}
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("approval_policy=\"never\"\n[agents]\nenabled=false\n[features]\nmulti_agent_v2=false\ncollab=false\n[profiles.sample]\napproval_policy=\"never\"\n[profiles.sample.agents]\nenabled=false\n[profiles.sample.features]\nmulti_agent_v2=false\ncollab=false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkConfig(path); err != nil {
		t.Fatal("never approval and disabled agent controls must remain valid")
	}
}

func TestPermissionArgs(t *testing.T) {
	for _, key := range []string{"default_permissions", "permissions", "approvals_reviewer", "approval_policy", "mcp_servers", "notify", "use_legacy_landlock", "guardianv2", "guardian_ext", "future_permissions", "agents", "multi_agent_v2", "collab"} {
		for _, prefix := range []string{"", "profiles.sample.", "projects.\"/fixture\"."} {
			value := prefix + key + "=\"private-canary-value\""
			for _, args := range [][]string{{"-c", value}, {"--config", value}, {"--config=" + value}, {"-c" + value}, {"-c=" + value}} {
				err := vetConfigArgs(args)
				if err == nil || !strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "private-canary-value") {
					t.Fatalf("permission overrides must name the refused key only: %s", key)
				}
			}
		}
	}
	for _, flag := range []string{"--approve-for-me", "--not-so-yolo", "--worktree", "--full-auto", "--future-permissions"} {
		for _, args := range [][]string{{flag}, {flag + "=private-canary-value"}} {
			err := vetConfigArgs(args)
			if err == nil || !strings.Contains(err.Error(), flag) || strings.Contains(err.Error(), "private-canary-value") {
				t.Fatalf("unsafe flags must name the refused flag only: %s", flag)
			}
		}
	}
	for _, args := range [][]string{{"-a", "on-request"}, {"--ask-for-approval=on-request"}, {"-aon-request"}, {"--sandbox="}, {"--ask-for-approval="},
		{"--enable", "external_sandbox"}, {"--disable=permissions"}, {"--enable=auto_review"}} {
		if err := vetConfigArgs(args); err == nil {
			t.Fatal("unsafe or incomplete sandbox and approval flags must be refused")
		}
	}
	for _, args := range [][]string{{"-c", "approval_policy=never"}, {"--ask-for-approval", "never"}, {"-anever"}, {"--sandbox", "workspace-write"}, {"-sread-only"}} {
		if err := vetConfigArgs(args); err != nil {
			t.Fatal("safe approval and sandbox controls must remain valid")
		}
	}
	for _, key := range []string{"multi_agent_v2", "collab"} {
		for _, args := range [][]string{{"--enable", key}, {"--enable=" + key}, {"--enable", "hooks," + key}} {
			if err := vetConfigArgs(args); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("collaboration feature refusals must name the key")
			}
		}
	}
}

func TestRenderedAgents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	sandbox := "[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n"
	for _, agents := range []string{"", "[agents]\nenabled=true\n", "[agents]\nenabled=\"private-canary-value\"\n", "[agents]\nenabled=false\n[agents.worker]\nconfig_file=\"private-canary-value\"\n"} {
		if err := os.WriteFile(path, []byte(sandbox+agents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := writableRoots(path, t.TempDir()); err == nil || !strings.Contains(err.Error(), "agents") || strings.Contains(err.Error(), "private-canary-value") {
			t.Fatal("rendered home must require disabled agents without role tables")
		}
	}
	if err := os.WriteFile(path, []byte(sandbox+"[agents]\nenabled=false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writableRoots(path, t.TempDir()); err != nil {
		t.Fatal("rendered disabled agents must remain valid")
	}
}

func TestUnknownFlag(t *testing.T) {
	if err := vetSandboxArgs([]string{"--future-option"}); err == nil || !strings.Contains(err.Error(), "--future-option") {
		t.Fatal("unknown flags must be refused by the argv allowlist")
	}
}

func TestCodexShapes(t *testing.T) {
	for _, args := range [][]string{
		{"--model", "gpt-6.1-sol", "exec", "Read the brief file /fixture/brief.md"},
		{"--model", "gpt-6.1-sol", "exec", "resume", "--last", "Read the message file /fixture/message.md"},
		{"-c", CodexEnable, "--disable", "plugins", "--ask-for-approval", "never", "exec", CodexTrustBypass,
			"--json", "--sandbox", "workspace-write", "--skip-git-repo-check", "--model", "gpt-6.1-sol", "-"},
		{"-c", CodexEnable, "--disable", "plugins", "exec", CodexTrustBypass, "resume", "--json", "fixture-session", "-"},
		{"-c", CodexEnable, "--disable", "plugins", "--version"},
		{"-psample", "-c", CodexEnable, "--disable", "plugins", "features", "list"},
	} {
		if err := vetSandboxArgs(args); err != nil {
			t.Fatal("built start, resume, bypass and probe argv must be accepted")
		}
	}
	for _, flag := range []string{"--ignore-user-config", "--output-last-message", "-o", "--approve-for-me", "--not-so-yolo", "--worktree"} {
		err := vetSandboxArgs([]string{flag + "=private-canary-value"})
		if err == nil || !strings.Contains(err.Error(), flag) || strings.Contains(err.Error(), "private-canary-value") {
			t.Fatalf("unvetted flags must name the flag only: %s", flag)
		}
	}
	for _, feature := range []string{"auto_review", "guardianv2", "guardian_ext", "use_legacy_landlock"} {
		for _, args := range [][]string{{"--enable", feature}, {"--disable=" + feature}} {
			if err := vetConfigArgs(args); err == nil {
				t.Fatal("unvetted guardian and sandbox switches must be refused")
			}
		}
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[agents]\nenabled=false\n[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writableRoots(path, t.TempDir(), []string{"--ignore-user-config"}); err == nil {
		t.Fatal("root inspection must refuse a user config layer that will not load")
	}
}

func TestCodexEnvironment(t *testing.T) {
	for _, name := range []string{"CODEX_CONFIG_PATH", "CODEX_SANDBOX_MODE", "CODEX_APPROVAL_POLICY", "CODEX_FUTURE_CONFIG"} {
		entry := name + "=private-canary-value"
		err := VetCodexEnvironment([]string{entry})
		if err == nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "private-canary-value") {
			t.Fatal("unvetted environment controls must name the key only")
		}
		var gate CodexGate
		if _, err := gate.Prepare([]string{"env", entry, "codex", "exec", "-"}, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatal("literal env controls must be refused before a probe")
		}
		if err := Revet([]string{"codex", "exec", CodexTrustBypass, "--disable", "plugins", "-"}, t.TempDir(), []string{entry}); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatal("the execution gate must retain environment checks")
		}
	}
	if err := VetCodexEnvironment([]string{"CODEX_HOME=/fixture/.codex", "CODEX_API_KEY=fixture", "CODEX_BASE_URL=https://example.invalid/v1", "OTHER=fixture"}); err != nil {
		t.Fatal("vetted home and provider transport names must remain valid")
	}
}

func TestConfigState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	state := "[features]\nhooks=true\n[projects.\"/fixture/hook-worktrees/sample\"]\ntrust_level=\"trusted\"\n"
	state += "[notice]\nhide_full_access_warning=true\n[notice.model_migrations]\nold=\"new\"\n"
	if err := os.WriteFile(path, []byte(state), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkConfig(path); err != nil {
		t.Fatal("project trust and notice state must remain valid")
	}
	for _, table := range []string{"hooks", "profiles.sample.hooks", `projects."/other/hook-worktrees/sample".hooks`} {
		text := state + "[" + table + "]\ncommand=\"private-canary-value\"\n"
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		err := checkConfig(path)
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "unvetted") || !strings.Contains(err.Error(), "hooks") {
			t.Fatal("hook config refusals must name the file and key")
		}
		if strings.Contains(err.Error(), "private-canary-value") {
			t.Fatal("hook config diagnostics must not expose values")
		}
	}
}

func TestCwdInputs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	home, state := filepath.Join(root, ".codex"), filepath.Join(root, "state")
	deep := filepath.Join(home, "cache", "deep")
	for _, directory := range []string{state, deep, filepath.Join(root, "hooks")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := vetCwd(home, state); err != nil {
		t.Fatal("sibling state must allow a Codex workspace")
	}
	for _, item := range []struct {
		path string
		rule string
	}{
		{root, "must not contain vetted Codex input"},
		{filepath.Dir(root), "must not contain vetted Codex input"},
		{home, "must not be at or below vetted Codex home"},
		{deep, "must not be at or below vetted Codex home"},
		{filepath.Join(root, "hooks"), "must not contain vetted Codex input"},
	} {
		err := vetCwd(home, item.path)
		if err == nil || !strings.Contains(err.Error(), item.path) || !strings.Contains(err.Error(), item.rule) {
			t.Fatal("protected input workspaces must name their containment rule")
		}
	}
	alias := filepath.Join(filepath.Dir(root), "instance-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if err := vetCwd(home, alias); err == nil || !strings.Contains(err.Error(), "must not contain vetted Codex input") {
		t.Fatal("instance aliases must retain input containment")
	}
	executable := filepath.Join(state, "org-hook")
	if err := os.WriteFile(executable, []byte("harmless fixture\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := vetCwd(home, state, executable); err == nil || !strings.Contains(err.Error(), executable) {
		t.Fatal("a workspace holding the vetted executable must be refused")
	}
}

func TestCwdOrder(t *testing.T) {
	root := t.TempDir()
	home, policy := filepath.Join(root, ".codex"), filepath.Join(root, "hooks")
	for _, path := range []string{home, policy} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(policy, "render.json")
	if err := os.WriteFile(input, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{input, policy}, {policy, input}} {
		err := vetCwd(home, policy, extra...)
		if err == nil || !strings.Contains(err.Error(), "must not be inside protected policy input") || strings.Contains(err.Error(), "must not contain") {
			t.Fatal("inside protection must precede containing an input in any list order")
		}
	}
}

func TestStateRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	home, state := filepath.Join(root, ".codex"), filepath.Join(root, "state")
	for _, directory := range []string{home, state} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "hooks.json"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := vetRepository(state, home); err != nil {
		t.Fatal("state must not rediscover its vetted instance home as foreign")
	}
	foreign := filepath.Join(state, ".codex")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(foreign, "hooks.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := vetRepository(state, home); err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "repository must not inject") {
		t.Fatal("state must still refuse a foreign repository hook source")
	}
}

func TestUnicodeOverrides(t *testing.T) {
	for _, space := range []string{"\u00a0", "\n", "\v", "\u2003", "\u202f"} {
		for _, key := range []string{"managed_dir", "project_root_markers", "hooks.PreToolUse", "plugins.sample.enabled"} {
			if err := vetOverride(space + key + "=" + space + "true" + space); err == nil {
				t.Fatal("Unicode key whitespace must not hide forbidden overrides")
			}
		}
		if err := vetOverride("model_reasoning_effort=" + space + "high" + space); err != nil {
			t.Fatal("Unicode plain-string controls must pass")
		}
		if err := vetOverride("values=" + space + `[{hooks={}}]` + space); err == nil {
			t.Fatal("Unicode value whitespace must not hide structured hooks")
		}
	}
	for _, raw := range []string{"[{broken", "{broken", "[broken"} {
		if err := vetOverride("values=" + raw); err == nil {
			t.Fatal("unparsed arrays and tables must fail closed")
		}
	}
}

func TestPluginConfigs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	for _, text := range []string{`model="sample"`, `[plugins]`, "[plugins.sample]\nenabled=false\n"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkConfig(path); err != nil {
			t.Fatal("no-enabled-plugin configuration must remain valid")
		}
	}
	for _, text := range []string{"[plugins.sample]\nenabled=true\n", "[plugins.sample]\n", "[features]\nplugins=true\n"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkConfig(path); err == nil {
			t.Fatal("enabled plugins must be refused before bypass")
		}
	}
	for _, args := range [][]string{{"-c", "plugins.sample.enabled=true"}, {"--config=plugins.sample.enabled=true"},
		{"-cplugins.sample.enabled=true"}, {"--enable", "plugins"}, {"--enable=plugins"}, {"--enable", "other,plugins"}} {
		if err := vetConfigArgs(args); err == nil {
			t.Fatal("plugin-enabling flags must be refused before bypass")
		}
	}
}

func TestNestedArrays(t *testing.T) {
	for depth := 2; depth <= 5; depth++ {
		var clean any = map[string]any{"model": "sample"}
		var bad any = map[string]any{"hooks": map[string]any{}}
		for i := 0; i < depth; i++ {
			clean = []any{clean}
			bad = []any{bad}
		}
		if foreignHooks(map[string]any{"values": clean}, "") || !foreignHooks(map[string]any{"values": bad}, "") {
			t.Fatal("nested arrays must retain hook inspection")
		}
	}
}

func TestNestedToml(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	for _, value := range []string{`values=[[{model="sample"}]]`, `values=[[[{model="other"}]]]`} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkConfig(path); err != nil {
			t.Fatal("clean config arrays must remain valid")
		}
	}
	for _, value := range []string{`values=[[{hooks={}}]]`, `values=[[[{hook_source="other"}]]]`, `values=[[{managed_dir="other"}]]`} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkConfig(path); err == nil {
			t.Fatal("nested config arrays must retain hook inspection")
		}
	}
}

func TestPlistValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preferences.plist")
	clean := `<?xml version="1.0"?><plist version="1.0"><dict><key>values</key><array><dict><key>model</key><string>sample</string></dict><true/><false/><integer>12</integer><real>1.25</real><date>2026-01-01T00:00:00Z</date><data>Y2xlYW4=</data></array></dict></plist>`
	if err := os.WriteFile(path, []byte(clean), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspectPlist(path); err != nil {
		t.Fatal("valid plist collections must remain readable")
	}
	for _, body := range []string{
		`<not-plist><dict/></not-plist>`, `<plist><dict/><dict/></plist>`,
		`<plist><dict><key>model</key></dict></plist>`,
		`<plist><dict><key><string>model</string></key><string>sample</string></dict></plist>`,
		`<plist><dict><key>model</key><integer>invalid</integer></dict></plist>`,
		`<plist><dict><key>model</key><real>invalid</real></dict></plist>`,
		`<plist><dict><key>model</key><date>invalid</date></dict></plist>`,
		`<plist><dict><key>model</key><data>invalid!</data></dict></plist>`,
		`<plist><dict><key>values</key><array><dict><key>hook_source</key><string>other</string></dict></array></dict></plist>`,
		`<plist><dict><key>model</key><true>invalid</true></dict></plist>`,
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := inspectPlist(path); err == nil {
			t.Fatal("invalid or hook-bearing plists must fail closed")
		}
	}
}

func TestPrefsHomes(t *testing.T) {
	for _, name := range []string{"com.openai.codex.plist", ".GlobalPreferences.plist", "ByHost/com.openai.codex.sample.plist", "ByHost/.GlobalPreferences.sample.plist"} {
		for target := 0; target < 2; target++ {
			homes := []string{t.TempDir(), t.TempDir()}
			for i, home := range homes {
				real, err := filepath.EvalSymlinks(home)
				if err != nil {
					t.Fatal(err)
				}
				homes[i] = real
				path := filepath.Join(real, "Library", "Preferences", name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(`<plist><dict><key>color</key><string>light</string></dict></plist>`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := vetPrefs(homes[0], homes[1]); err != nil {
				t.Fatal("clean preferences in both homes must pass")
			}
			path := filepath.Join(homes[target], "Library", "Preferences", name)
			for _, key := range []string{"hooks", "managed_dir", "project_root_markers", "hook_source"} {
				if err := os.WriteFile(path, []byte(`<plist><dict><key>`+key+`</key><array/></dict></plist>`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := vetPrefs(homes[0], homes[1]); err == nil {
					t.Fatal("both preference homes and all domains must be inspected")
				}
			}
		}
	}
	home := t.TempDir()
	path := filepath.Join(home, "Library", "Preferences", "com.openai.codex.plist")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := vetPrefs(home, t.TempDir()); err == nil {
		t.Fatal("unreadable preference files must fail closed")
	}
	home = t.TempDir()
	path = filepath.Join(home, "Library", "Preferences", ".GlobalPreferences.plist")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`<plist><dict/></plist>`), 0000); err != nil {
		t.Fatal(err)
	}
	if err := vetPrefs(home, t.TempDir()); err == nil {
		t.Fatal("unreadable preference files must fail closed")
	}
}

func TestEncodedPrefs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preferences.plist")
	for _, key := range []string{"config_toml_base64", "requirements_toml_base64"} {
		for _, item := range []struct {
			text string
			bad  bool
		}{{`model="gpt-6.1-sol"`, false}, {`hooks.PreToolUse=[]`, true}, {`values=[[{hook_source="other"}]]`, true},
			{"[plugins.sample]\nenabled=true\n", true}, {"[plugins.sample]\nenabled=false\n", false}} {
			encoded := base64.StdEncoding.EncodeToString([]byte(item.text))
			data := `<plist><dict><key>` + key + `</key><string>` + encoded + `</string></dict></plist>`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := inspectPlist(path); (err != nil) != item.bad {
				t.Fatal("encoded preference hooks must be refused and clean config must pass")
			}
		}
		if err := os.WriteFile(path, []byte(`<plist><dict><key>`+key+`</key><string>invalid!</string></dict></plist>`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := inspectPlist(path); err == nil {
			t.Fatal("undecodable encoded preferences must be refused")
		}
	}
	app := `<plist><dict><key>SUEnableAutomaticChecks</key><true/><key>SUFeedURL</key><string>https://example.invalid/updates</string><key>DockIconVisible</key><true/><key>LastRunAppBundlePath</key><string>/Applications/Example.app</string><key>NSNavPanelExpandedSizeForSaveMode</key><string>small</string><key>NSOSPLastRootDirectory</key><string>/Applications</string><key>CodexSparkleSeenUpdateVersions</key><array><string>1.0</string></array></dict></plist>`
	if err := os.WriteFile(path, []byte(app), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspectPlist(path); err != nil {
		t.Fatal("ordinary desktop app preferences must pass")
	}
}
