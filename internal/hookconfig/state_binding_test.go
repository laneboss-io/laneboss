package hookconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Keep the launcher's real configuration bound to the original org while using
// a second, fully rendered hook home, as standalone hook-vetting callers may do.
func unrelatedStateFixture(t *testing.T, custom bool) (string, string, string) {
	t.Helper()
	home, cwd, state := stateRootFixture(t, custom)
	org := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(home))))
	other := filepath.Join(filepath.Dir(org), "other-org")
	if err := os.CopyFS(other, os.DirFS(org)); err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(other, ".laneboss", "instances", "executor", ".codex")
	path := RenderMarkerPath(home)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var marker RenderedHooks
	if err := json.Unmarshal(data, &marker); err != nil {
		t.Fatal(err)
	}
	marker.Home = home
	marker.Instance = filepath.Join(filepath.Dir(home), "instance.toml")
	data, err = json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	writeNoStateConfig(t, home)
	return home, cwd, state
}

func writeNoStateConfig(t *testing.T, home string) []byte {
	t.Helper()
	data := []byte("# Preserve this standalone configuration.\nmodel=\"fixture-model-1\"\n[agents]\nenabled=false\n" +
		"[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n")
	if err := os.WriteFile(filepath.Join(home, "config.toml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func stateBindingProbe(t *testing.T, home, cwd string) (string, string, []string) {
	t.Helper()
	root := filepath.Dir(cwd)
	runner := filepath.Join(root, "bin", "codex")
	log := filepath.Join(root, "probe-calls")
	program := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$HOOKCONFIG_PROBE_LOG\"\n" +
		"hooks=false\nplugins=true\nprevious=\nfor argument do\n" +
		"  if [ \"$previous\" = '-c' ] && [ \"$argument\" = 'features.hooks=true' ]; then hooks=true; fi\n" +
		"  if [ \"$previous\" = '--disable' ] && [ \"$argument\" = 'plugins' ]; then plugins=false; fi\n" +
		"  previous=$argument\ndone\n" +
		"case \" $* \" in\n" +
		"  *\" --version \"*) printf '%s\\n' 'codex-cli 0.146.0' ;;\n" +
		"  *\" features list \"*) printf '%s\\n' \"hooks stable $hooks\" \"plugins stable $plugins\" ;;\n" +
		"  *) exit 91 ;;\nesac\n"
	if err := os.WriteFile(runner, []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	environment := []string{"HOME=" + os.Getenv("HOME"), "LANEBOSS_HOME=" + os.Getenv("LANEBOSS_HOME"),
		"LANEBOSS_STATE_HOME=" + os.Getenv("LANEBOSS_STATE_HOME"), "LANEBOSS_CONFIG=fixture",
		"CODEX_HOME=" + home, "PATH=/usr/bin:/bin:" + filepath.Dir(runner), "HOOKCONFIG_PROBE_LOG=" + log}
	return runner, log, environment
}

func TestUnrelatedStateBindingNoGrant(t *testing.T) {
	for _, custom := range []bool{false, true} {
		name := "default"
		if custom {
			name = "custom"
		}
		t.Run(name, func(t *testing.T) {
			home, cwd, _ := unrelatedStateFixture(t, custom)
			before := writeNoStateConfig(t, home)
			if err := VetCodex(home, cwd); err != nil {
				t.Fatalf("a fully vetted unrelated home without extra roots must pass: %v", err)
			}
			runner, log, environment := stateBindingProbe(t, home, cwd)
			var gate CodexGate
			prepared, err := gate.Prepare([]string{runner, "exec", "-"}, cwd, environment)
			if err != nil {
				t.Fatalf("an unrelated home without a state grant must reach the feature probes: %v", err)
			}
			if err := Revet(prepared, cwd, environment); err != nil {
				t.Fatalf("the prepared unrelated home must pass execution vetting: %v", err)
			}
			calls, err := os.ReadFile(log)
			if err != nil || !strings.Contains(string(calls), "--version\n") || !strings.Contains(string(calls), "features\nlist\n") {
				t.Fatalf("the no-grant control must execute both real probe processes: %v", err)
			}
			after, err := os.ReadFile(filepath.Join(home, "config.toml"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("an unrelated home must keep its exact configuration bytes without a state grant")
			}
		})
	}
}

func TestUnrelatedBindingInjection(t *testing.T) {
	for _, source := range []string{"hooks.json", "config.toml"} {
		t.Run(source, func(t *testing.T) {
			home, cwd, _ := unrelatedStateFixture(t, false)
			runner, log, environment := stateBindingProbe(t, home, cwd)
			injection := filepath.Join(cwd, ".codex", source)
			if err := os.Mkdir(filepath.Dir(injection), 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte("[hooks]\n")
			if source == "hooks.json" {
				var err error
				data, err = os.ReadFile(filepath.Join(home, "hooks.json"))
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(injection, data, 0600); err != nil {
				t.Fatal(err)
			}
			var gate CodexGate
			_, err := gate.Prepare([]string{runner, "exec", "-"}, cwd, environment)
			if err == nil || !strings.Contains(err.Error(), "repository must not inject hooks") || !strings.Contains(err.Error(), injection) {
				t.Fatalf("repository injection must retain its diagnostic before any probe: %v", err)
			}
			if _, err := os.Stat(log); !os.IsNotExist(err) {
				t.Fatal("repository injection must refuse before any Codex invocation")
			}
			argv := []string{runner, "exec", CodexTrustBypass, "--disable", "plugins", "-"}
			if err := Revet(argv, cwd, environment); err == nil || !strings.Contains(err.Error(), "repository must not inject hooks") {
				t.Fatalf("execution vetting must retain the repository injection refusal: %v", err)
			}
		})
	}
}

func TestUnrelatedBindingGrantRefused(t *testing.T) {
	home, cwd, state := unrelatedStateFixture(t, false)
	runner, log, environment := stateBindingProbe(t, home, cwd)
	writeStateConfig(t, home, []string{state}, "")
	before, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var gate CodexGate
	checks := []struct {
		name string
		run  func() error
	}{
		{"vet", func() error { return VetCodex(home, cwd) }},
		{"prepare", func() error {
			_, err := gate.Prepare([]string{runner, "exec", "-"}, cwd, environment)
			return err
		}},
		{"revet", func() error {
			return Revet([]string{runner, "exec", CodexTrustBypass, "--disable", "plugins", "-"}, cwd, environment)
		}},
		{"render", func() error { return renderStateRoot(home, nil) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err == nil || !strings.Contains(err.Error(), "writable_roots") {
				t.Fatalf("a supplied state grant must require the matching org binding: %v", err)
			}
		})
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("a mismatched supplied state grant must refuse before any Codex invocation")
	}
	after, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("a refused supplied state grant must not be repaired or discarded")
	}
}
