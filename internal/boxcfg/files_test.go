package boxcfg_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcfg"
)

// TestCredentialsFirst detects skipped credential scans or leaked values.
func TestCredentialsFirst(t *testing.T) {
	secrets := []string{
		"-----BEGIN " + "PRIVATE KEY-----",
		"AK" + "IA" + strings.Repeat("A", 16),
	}
	for i, secret := range secrets {
		rows := []struct{ text, key string }{
			{`org = ` + strconv.Quote(secret), "org"},
			{minimal + "unknown = " + strconv.Quote(secret), "unknown"},
			{minimal + "[ledger]\nschema = " + strconv.Quote(secret), "ledger.schema"},
			{minimal + "[defaults]\narch = " + strconv.Quote(secret), "defaults.arch"},
			{minimal + "[guest]\ndone_files = [" + strconv.Quote(secret) + "]", "guest.done_files[0]"},
			{minimal + "[aws]\nprofile = " + strconv.Quote(secret), "aws.profile"},
			{minimal + "[gcp]\nproject = " + strconv.Quote(secret), "gcp.project"},
			{minimal + "[[gcp.shape]]\ntype = " + strconv.Quote(secret), "gcp.shape[0].type"},
			{minimal + "[unknown]\nitems = [{ text = " + strconv.Quote(secret) + " }]", "unknown.items[0].text"},
			{minimal + strconv.Quote(secret) + ` = "demo"`, "<key>"},
		}
		for j, row := range rows {
			t.Run(fmt.Sprintf("credential-%d-%d", i, j), func(t *testing.T) {
				path := writeConfig(t, row.text)
				_, err := boxcfg.Load(path, testEnv(t))
				want := path + ": " + row.key + ": credential-shaped text is forbidden"
				if err == nil || err.Error() != want || strings.Contains(err.Error(), secret) {
					t.Fatalf("credential refusal lacks safe path at %s", row.key)
				}
			})
		}
	}
}

// TestSyntaxPosition detects lost parse positions or exposed source text.
func TestSyntaxPosition(t *testing.T) {
	for _, row := range []struct {
		text   string
		column int
	}{
		{"vcpu = SECRET-NEEDLE\n", 8},
		{"vcpu    =     SECRET-NEEDLE\n", 15},
	} {
		path := writeConfig(t, minimal+"[defaults]\n"+row.text)
		_, err := boxcfg.Load(path, testEnv(t))
		want := fmt.Sprintf("%s: TOML syntax error at line 4 column %d", path, row.column)
		if err == nil || err.Error() != want || strings.Contains(err.Error(), "SECRET-NEEDLE") {
			t.Fatalf("syntax error lacks the exact safe position: %v", err)
		}
	}
}

// TestFileLimits detects relaxed size, UTF-8 or regular-file requirements.
func TestFileLimits(t *testing.T) {
	env := testEnv(t)
	const limit = 256 * 1024
	atLimit := minimal + "#" + strings.Repeat("x", limit-len(minimal)-1)
	mustLoad(t, atLimit, env)
	for _, row := range []struct{ name, text string }{
		{"large", atLimit + "x"}, {"utf8", minimal + string([]byte{255})},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := writeConfig(t, row.text)
			got, err := boxcfg.Load(path, env)
			if err == nil || got != nil || !strings.HasPrefix(err.Error(), path+": file: ") {
				t.Fatalf("invalid file accepted or mislabeled: %v", err)
			}
		})
	}
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing.toml")} {
		if got, err := boxcfg.Load(path, env); err == nil || got != nil || !strings.HasPrefix(err.Error(), path+": file: ") {
			t.Fatalf("directory or missing file accepted: %v", err)
		}
	}
	path := writeConfig(t, minimal)
	link := filepath.Join(t.TempDir(), "box.toml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	got, err := boxcfg.Load(link, env)
	if err != nil || got.Path != link {
		t.Fatalf("regular-file symlink load = %v", err)
	}
}

// TestPathExpansion detects relative paths, wrong tilde roots or altered values.
func TestPathExpansion(t *testing.T) {
	env := testEnv(t)
	rows := []struct{ table, key string }{
		{"ledger", "path"}, {"ledger", "registry"}, {"defaults", "run_dir"},
		{"aws", "ssh_identity"}, {"gcp", "gcloud_config_dir"},
	}
	for _, row := range rows {
		for _, value := range []string{"SECRET-NEEDLE", "~other/SECRET-NEEDLE"} {
			assertRefused(t, edit(t, explicit, row.table, row.key, strconv.Quote(value), false), fieldPath(row.table, row.key), "")
		}
	}
	text := explicit
	for _, row := range rows {
		text = edit(t, text, row.table, row.key, `"~"`, false)
	}
	got := mustLoad(t, text, env)
	for _, path := range []string{got.Ledger.Path, got.Ledger.Registry, got.Defaults.RunDir, got.AWS.SSHIdentity, got.GCP.GcloudConfigDir} {
		if path != env.UserHome {
			t.Fatal("bare tilde did not expand to UserHome")
		}
	}
	path := writeConfig(t, minimal)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Fatal(err)
	}
	got, err = boxcfg.Load(relative, env)
	if err != nil || got.Path != path {
		t.Fatalf("relative config path was not made absolute: %v", err)
	}
	text = edit(t, explicit, "ledger", "path", `"/tmp/demo/../events"`, false)
	if got := mustLoad(t, text, env).Ledger.Path; got != "/tmp/demo/../events" {
		t.Fatal("explicit absolute path was replaced")
	}
}

// TestLocateOrder detects changed precedence, name rules or unsafe diagnostics.
func TestLocateOrder(t *testing.T) {
	home := t.TempDir()
	named := filepath.Join(home, "configs", "demo-name", "box.toml")
	if err := os.MkdirAll(filepath.Dir(named), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(named, []byte(minimal), 0600); err != nil {
		t.Fatal(err)
	}
	flag, fromEnv := writeConfig(t, minimal), writeConfig(t, minimal)
	rows := []struct {
		name string
		o    boxcfg.LocateOptions
		want string
	}{
		{"flag", boxcfg.LocateOptions{Flag: flag, EnvValue: fromEnv, ConfigName: "bad/name", Home: home}, flag},
		{"env", boxcfg.LocateOptions{EnvValue: fromEnv, ConfigName: "bad/name", Home: home}, fromEnv},
		{"named", boxcfg.LocateOptions{ConfigName: "demo-name", Home: home}, named},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got, err := boxcfg.Locate(row.o)
			if err != nil || got != row.want {
				t.Fatalf("Locate = %q, %v", got, err)
			}
		})
	}
	link := filepath.Join(t.TempDir(), "link.toml")
	if err := os.Symlink(flag, link); err != nil {
		t.Fatal(err)
	}
	if got, err := boxcfg.Locate(boxcfg.LocateOptions{Flag: link}); err != nil || got != link {
		t.Fatalf("Locate symlink = %q, %v", got, err)
	}
	for i, o := range []boxcfg.LocateOptions{
		{}, {Flag: filepath.Join(home, "SECRET-NEEDLE"), EnvValue: fromEnv},
		{EnvValue: filepath.Join(home, "SECRET-NEEDLE"), ConfigName: "demo-name", Home: home},
		{ConfigName: "SECRET-NEEDLE", Home: home}, {ConfigName: "missing", Home: home},
		{Flag: home}, {Flag: filepath.Join(home, "configs")},
		{ConfigName: strings.Repeat("a", 33), Home: home}, {ConfigName: "../demo", Home: home},
	} {
		t.Run(fmt.Sprintf("error-%d", i), func(t *testing.T) {
			got, err := boxcfg.Locate(o)
			if err == nil || got != "" || !strings.Contains(err.Error(), "--box-config") ||
				strings.Contains(err.Error(), "SECRET-NEEDLE") || strings.Contains(err.Error(), home) {
				t.Fatalf("Locate error lacks safe order: %v", err)
			}
			if o.Flag == "" && !strings.Contains(err.Error(), "LANEBOSS_BOX_CONFIG") {
				t.Fatal("environment lookup was not named")
			}
			if o.Flag == "" && o.EnvValue == "" && !strings.Contains(err.Error(), "Home/configs/ConfigName/box.toml") {
				t.Fatal("named lookup was not named")
			}
		})
	}
	for _, name := range []string{"a", strings.Repeat("a", 32), "0-demo"} {
		path := filepath.Join(home, "configs", name, "box.toml")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(minimal), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := boxcfg.Locate(boxcfg.LocateOptions{ConfigName: name, Home: home}); err != nil || got != path {
			t.Fatalf("valid name failed: %v", err)
		}
	}
}

// TestEnvFrom detects relative overrides or incorrect environment defaults.
func TestEnvFrom(t *testing.T) {
	home := t.TempDir()
	fallback := boxcfg.Env{
		Home: filepath.Join(home, ".config", "laneboss"), StateHome: filepath.Join(home, ".local", "state", "laneboss"), UserHome: home,
	}
	for _, value := range []string{"", "relative", "~/relative"} {
		got := boxcfg.EnvFrom(func(string) string { return value }, home)
		if !reflect.DeepEqual(got, fallback) {
			t.Fatal("unset or relative environment value replaced a fallback")
		}
	}
	values := map[string]string{
		"LANEBOSS_HOME": filepath.Join(home, "demo-config"), "LANEBOSS_STATE_HOME": filepath.Join(home, "demo-state"),
	}
	got := boxcfg.EnvFrom(func(key string) string { return values[key] }, home)
	want := boxcfg.Env{Home: values["LANEBOSS_HOME"], StateHome: values["LANEBOSS_STATE_HOME"], UserHome: home}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("absolute environment overrides differ")
	}
	if got := boxcfg.EnvFrom(nil, home); !reflect.DeepEqual(got, fallback) {
		t.Fatal("nil environment reader did not use fallbacks")
	}
}
