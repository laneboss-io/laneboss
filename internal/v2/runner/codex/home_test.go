package codex

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// H1: ordinary tool artifacts must be observed, while owned credential/config
// paths remain strict. Rejecting every link/socket cannot pass the controls.
func TestAuditOrdinaryArtifacts(t *testing.T) {
	for _, shape := range []string{"symlink", "hardlink", "socket", "dangling", "cycle"} {
		t.Run(shape, func(t *testing.T) {
			home, _ := newTestHome(t)
			if _, err := home.Audit(); err != nil {
				t.Fatal("ordinary artifact setup did not audit", err)
			}
			outside := filepath.Join(canonicalTemp(t), "canary")
			putFile(t, outside, []byte(t.Name()), 0600)
			name := filepath.Join(home.path, "ordinary")
			switch shape {
			case "symlink":
				if err := os.Symlink(outside, name); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(getFile(t, name), []byte(t.Name())) {
					t.Fatal("link control did not reach its harmless file")
				}
			case "hardlink":
				if err := os.Link(outside, name); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(getFile(t, name), []byte(t.Name())) {
					t.Fatal("hardlink control did not work")
				}
			case "socket":
				listener, err := net.Listen("unix", name)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			case "dangling":
				if err := os.Symlink("missing", name); err != nil {
					t.Fatal(err)
				}
			case "cycle":
				if err := os.Symlink("ordinary", name); err != nil {
					t.Fatal(err)
				}
			}
			report, err := home.Audit()
			if err != nil {
				t.Fatal("ordinary tool artifact blocked future turns", err)
			}
			if !slices.ContainsFunc(report.Observations, func(row Observation) bool { return row.Path == "ordinary" }) {
				t.Fatal("ordinary artifact was silently ignored")
			}
		})
	}
}

// H1/H4: broad-mode, linked or special OWNED entries and linked containers
// must fail. Every row first audits its unchanged home successfully.
func TestAuditOwnedEntries(t *testing.T) {
	for _, shape := range []string{"auth-symlink", "auth-hardlink", "auth-mode", "runtime-directory", "runtime-link", "ancestor", "config-hardlink"} {
		t.Run(shape, func(t *testing.T) {
			home, _ := newTestHome(t)
			if _, err := home.Audit(); err != nil {
				t.Fatal(err)
			}
			auth := filepath.Join(home.path, ".codex/auth.json")
			outside := filepath.Join(canonicalTemp(t), "canary")
			putFile(t, outside, []byte(t.Name()), 0600)
			switch shape {
			case "auth-symlink":
				if err := os.Symlink(outside, auth); err != nil {
					t.Fatal(err)
				}
			case "auth-hardlink":
				if err := os.Link(outside, auth); err != nil {
					t.Fatal(err)
				}
			case "auth-mode":
				putFile(t, auth, []byte(t.Name()), 0644)
			case "runtime-directory":
				canonicalTemp(t, filepath.Join(home.path, ".runnerhome-runtime/.runnerhome-bad"))
			case "runtime-link":
				if err := os.Symlink(outside, filepath.Join(home.path, ".runnerhome-runtime/.runnerhome-bad")); err != nil {
					t.Fatal(err)
				}
			case "ancestor":
				if err := os.Rename(filepath.Join(home.path, ".codex"), filepath.Join(home.path, "moved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("moved", filepath.Join(home.path, ".codex")); err != nil {
					t.Fatal(err)
				}
			case "config-hardlink":
				if err := os.Link(filepath.Join(home.path, ".codex/config.toml"), filepath.Join(home.path, "config-copy")); err != nil {
					t.Fatal(err)
				}
			}
			_, err := home.Audit()
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

// H2: lane-side driver/binding forgeries cannot change protected authority;
// replacing a read-only configuration inode with different bytes must fail.
func TestProtectedRecordsAndDigests(t *testing.T) {
	home, _ := newTestHome(t)
	for _, name := range []string{".runnerhome-driver", ".runnerhome-conversation.json"} {
		putFile(t, filepath.Join(home.path, name), []byte("forged_lane_record"), 0600)
	}
	opened, err := Open(home.path, home.records)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if opened.record.Driver != api.DriverCodex || opened.record.Session.VendorID != "" || opened.record.Home != home.Descriptor() {
		t.Fatal("lane-side record became authority")
	}
	if within(home.path, home.records.path) || within(home.path, filepath.Join(home.records.path, home.key+".json")) {
		t.Fatal("protected record is inside the lane mount")
	}
	for _, name := range []string{".codex/config.toml", ".codex/hooks.json"} {
		original := getFile(t, filepath.Join(home.path, name))
		temporary := filepath.Join(home.path, "replacement")
		putFile(t, temporary, append(original, []byte("changed")...), 0400)
		if err := os.Rename(temporary, filepath.Join(home.path, name)); err != nil {
			t.Fatal(err)
		}
		_, err := home.Audit()
		wantCode(t, err, api.CodeIntegrity)
		putFile(t, temporary, original, 0400)
		if err := os.Rename(temporary, filepath.Join(home.path, name)); err != nil {
			t.Fatal(err)
		}
		if _, err := home.Audit(); err != nil {
			t.Fatal("restored byte-identical control failed", err)
		}
	}
}

// H4: the old open root must not audit a new private directory at its path.
func TestAuditOpenRootIdentity(t *testing.T) {
	home, _ := newTestHome(t)
	if err := os.Rename(home.path, home.path+"-moved"); err != nil {
		t.Fatal(err)
	}
	canonicalTemp(t, home.path)
	_, err := home.Audit()
	wantCode(t, err, api.CodeIntegrity)
	if _, err := Open(home.path, home.records); err == nil {
		t.Fatal("replacement directory inherited another inode's records")
	}
}

// H4: group/world access must fail before a home is created, even without write
// permission. Restoring a private parent permits creation, without overwrites.
func TestCreatePrivateParent(t *testing.T) {
	home, _ := newTestHome(t)
	base := canonicalTemp(t)
	path := filepath.Join(base, "new-home")
	descriptor := home.Descriptor()
	descriptor.VendorDirectory = filepath.Join(path, ".codex")
	for _, mode := range []os.FileMode{0750, 0705, 0777} {
		if err := os.Chmod(base, mode); err != nil {
			t.Fatal(err)
		}
		unexpected, err := Create(path, descriptor, home.records)
		if unexpected != nil {
			if err := unexpected.Close(); err != nil {
				t.Error(err)
			}
			t.Fatal("accessible parent was accepted")
		}
		wantCode(t, err, api.CodeIntegrity)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("private-parent rejection created a directory")
		}
	}
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	created, err := Create(path, descriptor, home.records)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	history := filepath.Join(path, ".codex/history.jsonl")
	putFile(t, history, []byte(t.Name()), 0600)
	_, err = Create(path, descriptor, home.records)
	wantCode(t, err, api.CodeConflict)
	if !bytes.Equal(getFile(t, history), []byte(t.Name())) {
		t.Fatal("failed creation changed existing history")
	}
}

// H4: a file or a symlink to an otherwise valid private directory must not be
// used as the parent. The actual file/target remains unchanged after refusal.
func TestCreateRejectsOddParent(t *testing.T) {
	for _, shape := range []string{"file", "symlink"} {
		t.Run(shape, func(t *testing.T) {
			home, _ := newTestHome(t)
			base := canonicalTemp(t)
			parent := filepath.Join(base, "parent")
			target := filepath.Join(base, "target")
			canary := []byte("ordinary_parent_control")
			if shape == "file" {
				putFile(t, parent, canary, 0600)
			} else {
				canonicalTemp(t, target)
				if err := os.Symlink(target, parent); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(parent, "new-home")
			descriptor := home.Descriptor()
			descriptor.VendorDirectory = filepath.Join(path, ".codex")
			unexpected, err := Create(path, descriptor, home.records)
			if unexpected != nil {
				if err := unexpected.Close(); err != nil {
					t.Error(err)
				}
				t.Fatal("nonordinary parent was accepted")
			}
			wantCode(t, err, api.CodeIntegrity)
			if shape == "file" {
				if !bytes.Equal(getFile(t, parent), canary) {
					t.Fatal("rejected parent file changed")
				}
			} else if _, err := os.Lstat(filepath.Join(target, "new-home")); !os.IsNotExist(err) {
				t.Fatal("rejected linked parent target changed")
			}
		})
	}
}

// H2/H5: source assets are independent copies; runtime/history imports and auth
// redirects fail with an unwrap-compatible reason, without private path values.
func TestSeedAndErrorReasons(t *testing.T) {
	home, _ := newTestHome(t)
	source := filepath.Join(canonicalTemp(t), "skill")
	putFile(t, source, []byte(t.Name()), 0700)
	if err := home.Seed(source, ".codex/skills/tool"); err != nil {
		t.Fatal(err)
	}
	putFile(t, source, []byte("changed_source"), 0700)
	if !bytes.Equal(getFile(t, filepath.Join(home.path, ".codex/skills/tool")), []byte(t.Name())) {
		t.Fatal("seeded skill was not an independent copy")
	}
	for _, bad := range []string{".codex/auth.json", ".codex/history.jsonl", ".codex/skills/../../escape"} {
		if err := home.Seed(source, bad); err == nil {
			t.Fatal("runtime or escaping asset accepted")
		}
	}
	putFile(t, source, []byte("cli_auth_credentials_store = \"keyring\"\n"), 0600)
	err := home.Seed(source, ".codex/config.toml")
	wantCode(t, err, api.CodeForbidden)
	var inner *api.Error
	if !errors.As(err, &inner) || !errors.Is(err, inner) || !strings.Contains(err.Error(), "keyring") || strings.Contains(err.Error(), home.path) || strings.Contains(err.Error(), source) {
		t.Fatal("mapped inner reason was lost or private path leaked")
	}
	if _, err := home.Audit(); err != nil {
		t.Fatal("refused seed changed the existing config", err)
	}
}

// H2: writable project/ancestor settings must not redirect auth even when the
// home config is intact. Ordinary model/editor settings remain a valid control.
func TestProjectConfiguration(t *testing.T) {
	root := canonicalTemp(t)
	nested := canonicalTemp(t, filepath.Join(root, "child"))
	container := canonicalTemp(t, filepath.Join(root, ".codex"))
	for _, bad := range []string{
		"cli_auth_credentials_store = \"keyring\"\n",
		"model_provider = \"borrowed\"\n",
		"[profiles.other]\nmodel_provider = \"borrowed\"\n",
		"[shell_environment_policy.set]\nCODEX_HOME = \"/synthetic/other\"\n",
		"[model_providers.other]\nenv_key = \"SYNTHETIC_KEY\"\n",
	} {
		putFile(t, filepath.Join(container, "config.toml"), []byte(bad), 0644)
		err := CheckProjectConfig(root, nested)
		wantCode(t, err, api.CodeForbidden)
	}
	putFile(t, filepath.Join(container, "config.toml"), []byte("model_reasoning_effort = \"high\"\n[features]\nordinary_tool = true\n"), 0644)
	if err := CheckProjectConfig(root, nested); err != nil {
		t.Fatal("ordinary settings control failed", err)
	}
}
