package textcontext

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredPolicy(t *testing.T) {
	data := []byte("schema_version = 1\n[[tools]]\ncommand = ['record-tool', 'add']\ntext_from = 3\n")
	tools, err := Parse(data)
	if err != nil || len(tools) != 1 || tools[0].TextFrom != 3 || tools[0].Command[1] != "add" {
		t.Fatal("the policy must retain its real configured prefix and prose index")
	}
	for _, invalid := range []string{
		"schema_version = 2\n",
		"schema_version = 1\nunknown = true\n",
		"schema_version = 1\n[[tools]]\ncommand = []\n",
		"schema_version = 1\n[[tools]]\ncommand = ['tool', 'send']\ntext_from = 1\n",
		"schema_version = 1\n[[tools]]\ncommand = ['tool']\ntext_option = 'body'\n",
	} {
		if _, err := Parse([]byte(invalid)); err == nil {
			t.Fatal("an invalid org policy was silently accepted")
		}
	}
}

func TestPolicyFileOwnership(t *testing.T) {
	org := t.TempDir()
	configuration := map[string]any{"org_dir": org}
	if tools, err := Load("", configuration); err != nil || len(tools) != 0 {
		t.Fatal("a missing optional policy must preserve built-in observation contexts")
	}
	path := filepath.Join(org, Source)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.toml")
	if err := os.WriteFile(outside, []byte("schema_version = 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("", configuration); err == nil {
		t.Fatal("the org policy must not follow a symlink outside its owned file")
	}
}

func TestPolicyFileLoad(t *testing.T) {
	home := t.TempDir()
	org := filepath.Join(home, "orgs", "fixture")
	path := filepath.Join(org, Source)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("schema_version = 1\n[[tools]]\ncommand = ['record-tool', 'send']\ntext_from = 3\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, configuration := range []map[string]any{{"org_dir": org}, {"organisation": "fixture"}} {
		tools, err := Load(home, configuration)
		if err != nil || len(tools) != 1 || tools[0].Command[1] != "send" || tools[0].TextFrom != 3 {
			t.Fatal("a regular TOML policy must load through either configuration-owned org binding")
		}
	}
	if err := os.WriteFile(path, append(data, 0xff), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(home, map[string]any{"org_dir": org}); err == nil {
		t.Fatal("an invalid UTF-8 source must fail policy loading")
	}
}
