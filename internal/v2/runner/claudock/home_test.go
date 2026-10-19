package claudock

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func temporary(t *testing.T) string {
	t.Helper()
	created := t.TempDir()
	// Go's per-test leaf inherits the process umask. The fixture must meet
	// the same private-directory rule as production, independently of it.
	if err := os.Chmod(created, 0700); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.EvalSymlinks(created)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || native.Uid != uint32(os.Geteuid()) {
		t.Fatal("test directory must be real, private and owned by the test identity")
	}
	return path
}

// Fails when the shared fixture inherits broad permissions instead of creating
// an ordinary private directory usable by the production records/home checks.
// The Linux mutation runner executes this under permissive and private umasks.
func TestPrivateFixtureSetup(t *testing.T) {
	path := temporary(t)
	r, err := NewRecords(path)
	if err != nil {
		t.Fatal("private fixture failed the production records check", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(info, r.info) || info.Mode().Perm() != 0700 {
		t.Fatal("production records did not open the private fixture object")
	}
}

// The valid control must open first. Broad group/world permissions, a regular
// file and a directory symlink are separate inputs that NewRecords must refuse.
func TestRecordsDirectoryGuards(t *testing.T) {
	control, err := NewRecords(temporary(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"group", "world", "file", "link"} {
		t.Run(kind, func(t *testing.T) {
			parent := temporary(t)
			path := filepath.Join(parent, "records")
			switch kind {
			case "group", "world":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				mode := os.FileMode(0750)
				if kind == "world" {
					mode = 0705
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			case "file":
				put(t, path, []byte("ordinary_file"))
			case "link":
				if err := os.Symlink(temporary(t), path); err != nil {
					t.Fatal(err)
				}
			}
			records, err := NewRecords(path)
			if err == nil {
				if closeErr := records.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("accessible or nonordinary records directory was accepted")
			}
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

// Group/world access and a non-directory parent must not create a home. The
// regular-file canary must remain intact; privacy is never relaxed for tests.
func TestHomeParentTypes(t *testing.T) {
	records := testRecords(t)
	for _, kind := range []string{"group", "world", "file"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(temporary(t), "parent")
			code := api.CodeIntegrity
			if kind == "file" {
				put(t, path, []byte("parent_canary"))
				code = api.CodePrerequisite
			} else {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				mode := os.FileMode(0750)
				if kind == "world" {
					mode = 0705
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			}
			_, err := CreateHome(filepath.Join(path, "home"), records)
			if err == nil {
				t.Fatal("accessible or non-directory home parent was accepted")
			}
			wantCode(t, err, code)
			if kind == "file" {
				if !bytes.Equal(get(t, path), []byte("parent_canary")) {
					t.Fatal("parent refusal changed the file canary")
				}
			} else if _, err := os.Lstat(filepath.Join(path, "home")); !os.IsNotExist(err) {
				t.Fatal("parent refusal created a home")
			}
		})
	}
}

func testRecords(t *testing.T) *Records {
	t.Helper()
	r, err := NewRecords(temporary(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func testHome(t *testing.T, records *Records) *Home {
	t.Helper()
	h, err := CreateHome(filepath.Join(temporary(t), "home"), records)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func replaceForTest(t *testing.T, path string, data []byte) {
	t.Helper()
	staging := filepath.Join(filepath.Dir(path), "test-replacement")
	put(t, staging, data)
	if err := os.Chmod(staging, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staging, path); err != nil {
		t.Fatal(err)
	}
}

// H1: fails if ordinary tool artifacts still prevent another turn, or if the
// narrowed audit also stops detecting a hardlink to an owned credential file.
func TestOwnedAuditKeepsTools(t *testing.T) {
	h := testHome(t, testRecords(t))
	canary := filepath.Join(temporary(t), "canary")
	put(t, canary, []byte(t.Name()))
	for name, target := range map[string]string{"venv-link": canary, "browser-lock": "missing"} {
		if err := os.Symlink(target, filepath.Join(h.path, name)); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(get(t, filepath.Join(h.path, "venv-link")), get(t, canary)) {
		t.Fatal("outside link control was not reached")
	}
	if err := os.Link(canary, filepath.Join(h.path, "git-object")); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(h.path, "gpg-socket"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	findings, err := h.Inspect()
	if err != nil || len(findings) != 4 {
		t.Fatal("ordinary tool state blocked or was not reported", err)
	}
	auth := filepath.Join(h.path, ".claude/.credentials.json")
	put(t, auth, []byte("synthetic_auth"))
	if err := os.Link(auth, filepath.Join(temporary(t), "copy")); err != nil {
		t.Fatal(err)
	}
	if err := h.AuditOwned(); !errors.Is(err, ErrOwnedLink) {
		t.Fatal("owned hardlink was not refused with its reason", err)
	}
}

// H1/H5: each internal-link control first proves os.Root could follow the
// intermediate alias; Lstat on every owned ancestor must still refuse it.
func TestOwnedAncestorsAreReal(t *testing.T) {
	for _, name := range []string{".config", ".config/claudock", ".claude", ".runnerhome-runtime"} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			h := testHome(t, testRecords(t))
			original := filepath.Join(h.path, name)
			moved := original + "-saved"
			if err := os.Rename(original, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(moved), original); err != nil {
				t.Fatal(err)
			}
			r, err := h.open()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Stat(name); err != nil {
				t.Fatal("internal-link control did not resolve", err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := h.AuditOwned(); !errors.Is(err, ErrOwnedType) {
				t.Fatal("owned ancestor alias was accepted or lost its cause", err)
			}
		})
	}
}

// H1: hard checks retain exact owned-file type/link/privacy failures. A broad
// "report everything" relaxation fails this test after a working control.
func TestOwnedFileGuards(t *testing.T) {
	for _, shape := range []string{"link", "hardlink", "mode", "directory"} {
		t.Run(shape, func(t *testing.T) {
			h := testHome(t, testRecords(t))
			if err := h.AuditOwned(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(h.path, ".runnerhome-runtime/.runnerhome-probe")
			want := ErrOwnedType
			switch shape {
			case "link":
				if err := os.Symlink("../.claude/settings.json", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				put(t, path, []byte(t.Name()))
				if err := os.Link(path, filepath.Join(h.path, "ordinary-copy")); err != nil {
					t.Fatal(err)
				}
				want = ErrOwnedLink
			case "mode":
				put(t, path, []byte(t.Name()))
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
				want = ErrOwnedMode
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.AuditOwned(); !errors.Is(err, want) {
				t.Fatal("owned guard lost its specific reason", err)
			}
		})
	}
}

// H2/H4: state must be outside the home, survive rename/reopen and retain the
// original session. Replacing a mode-0400 settings file must fail by digest.
func TestProtectedHomeRecords(t *testing.T) {
	r := testRecords(t)
	h := testHome(t, r)
	request := api.RunnerRequest{Session: api.Session{ID: "session-a", VendorID: "existing-conversation", LogicalCWD: "/work/main"},
		Home: api.PrivateHome{ID: "home-a", HistoryID: "history-a"}, Model: "claude-sonnet-4-6"}
	if err := h.bind(request, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".runnerhome-driver", ".runnerhome-conversation.json", ".laneboss-claudock"} {
		if _, err := os.Lstat(filepath.Join(h.path, name)); !os.IsNotExist(err) {
			t.Fatal("authoritative record remained in home")
		}
	}
	if _, err := os.Stat(filepath.Join(r.path, h.key+".json")); err != nil {
		t.Fatal("protected record was not created", err)
	}
	moved := h.path + "-moved"
	if err := os.Rename(h.path, moved); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenHome(moved, r)
	if err != nil || opened.key != h.key {
		t.Fatal("renamed home lost its filesystem record", err)
	}
	if err := opened.bind(request, false); err != nil {
		t.Fatal("continuation lost its protected binding", err)
	}
	bad := request
	bad.Model = "claude-opus-4-6"
	if err := opened.bind(bad, false); err == nil {
		t.Fatal("changed model replaced the protected binding")
	}
	settings := filepath.Join(opened.path, ".claude/settings.json")
	replaceForTest(t, settings, []byte(`{"sandbox":{"enabled":false},"hooks":{}}`))
	if _, err := OpenHome(opened.path, r); err == nil {
		t.Fatal("replaced generated settings passed their protected digest")
	}
}

// H2: copied assets preserve exact bytes and independent source identity; a
// lane-side replacement of a generated hook is caught despite its private mode.
func TestSeedPinsGeneratedBytes(t *testing.T) {
	h := testHome(t, testRecords(t))
	source := temporary(t)
	input := []byte("generated_hook\n")
	put(t, filepath.Join(source, "hook"), input)
	if err := os.Chmod(filepath.Join(source, "hook"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := h.Seed(source, ".claude/hooks"); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(source, "hook"), []byte("source_changed"))
	target := filepath.Join(h.path, ".claude/hooks/hook")
	if !bytes.Equal(get(t, target), input) {
		t.Fatal("source mutation changed the generated copy")
	}
	if err := h.verifyGenerated(); err != nil {
		t.Fatal("unchanged generated control failed", err)
	}
	replaceForTest(t, target, []byte("lane_changed"))
	if err := h.verifyGenerated(); err == nil {
		t.Fatal("generated hook replacement was not detected")
	}
}

// H2: auth/history cannot be imported as generated assets and source links do
// not become an implicit credential/home grant. A failed copy poisons its record.
func TestSeedRejectsRuntimeAndLinks(t *testing.T) {
	for _, destination := range []string{".claude/.credentials.json", ".claude/projects", ".config/claudock", "../escape"} {
		h := testHome(t, testRecords(t))
		file := filepath.Join(temporary(t), "input")
		put(t, file, []byte("synthetic_input"))
		if err := h.Seed(file, destination); err == nil {
			t.Fatal("runtime or escaping asset import passed")
		}
		if err := h.verifyGenerated(); err != nil {
			t.Fatal("preflight refusal mutated the protected generation", err)
		}
	}
	h := testHome(t, testRecords(t))
	source := temporary(t)
	if err := os.Symlink("missing", filepath.Join(source, "asset")); err != nil {
		t.Fatal(err)
	}
	if err := h.Seed(source, ".claude/hooks"); err == nil {
		t.Fatal("source symlink was imported")
	}
	if err := h.verifyGenerated(); err == nil {
		t.Fatal("partial import was accepted as a complete generation")
	}
}

// H4: the audit must inspect its actual open handle, rather than reopen and
// validate another good home. The original matching-handle control must pass.
func TestAuditChecksOpenRoot(t *testing.T) {
	r := testRecords(t)
	a, b := testHome(t, r), testHome(t, r)
	root, err := a.open()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := a.auditRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := b.auditRoot(root); !errors.Is(err, ErrRootChanged) {
		t.Fatal("a different open root passed the audit", err)
	}
}

// H4: a broad/shared parent must fail before Create mutates it. Nested records
// cannot be used to make service state writable through the lane's home mount.
func TestPrivateParentsAndRecords(t *testing.T) {
	r := testRecords(t)
	parent := temporary(t)
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "home")
	if _, err := CreateHome(path, r); err == nil {
		t.Fatal("shared home parent was accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed parent check created a home")
	}
	h := testHome(t, r)
	nested := filepath.Join(h.path, "records")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	inside, err := NewRecords(nested)
	if err != nil {
		t.Fatal(err)
	}
	defer inside.Close()
	if _, err := OpenHome(h.path, inside); err == nil {
		t.Fatal("lane-mounted service records were accepted")
	}
}

// H5: dependency mapping must keep constant wrapped reasons available to the
// supervisor and errors.Is, instead of flattening every failure to one string.
func TestAuditReasonSurvivesMapping(t *testing.T) {
	err := dependency(ownedError(ErrOwnedMode))
	var typed *api.Error
	if !errors.Is(err, ErrOwnedMode) || !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
		t.Fatal("audit cause or typed code was flattened")
	}
}
