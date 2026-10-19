package claudock

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestVendorTreeGuards(t *testing.T) {
	for _, kind := range []string{"history-link", "history-hardlink", "sessions-link", "nested-project-link", "history-mode", "project-mode", "file-mode", "hooks", "plugins", "agents", "skills", "extra-directory", "cache-link"} {
		t.Run(kind, func(t *testing.T) {
			f := runnerSetup(t)
			if _, err := f.service.Start(context.Background(), f.request); err != nil {
				t.Fatal(err)
			}
			history := f.history(t)
			if err := f.home.AuditOwned(); err != nil {
				t.Fatal("private vendor control failed", err)
			}
			outside := filepath.Join(temporary(t), "canary")
			put(t, outside, []byte("independent_canary"))
			switch kind {
			case "history-link", "history-hardlink":
				path := filepath.Join(f.home.path, ".claude/history.jsonl")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "history-link" {
					err = os.Symlink(outside, path)
				} else {
					err = os.Link(outside, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "sessions-link", "nested-project-link":
				path := filepath.Join(f.home.path, ".claude/sessions")
				if kind == "nested-project-link" {
					path = filepath.Dir(history)
				}
				if err := os.Rename(path, path+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(temporary(t), path); err != nil {
					t.Fatal(err)
				}
			case "history-mode":
				if err := os.Chmod(filepath.Join(f.home.path, ".claude/history.jsonl"), 0644); err != nil {
					t.Fatal(err)
				}
			case "project-mode":
				if err := os.Chmod(filepath.Dir(history), 0755); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				if err := os.Chmod(history, 0644); err != nil {
					t.Fatal(err)
				}
			case "extra-directory":
				if err := os.Mkdir(filepath.Join(f.home.path, ".claude/hooks/unrecorded"), 0700); err != nil {
					t.Fatal(err)
				}
			case "cache-link":
				if err := os.Symlink(outside, filepath.Join(f.home.path, ".claude/cache/alias")); err != nil {
					t.Fatal(err)
				}
			default:
				put(t, filepath.Join(f.home.path, ".claude", kind, "unrecorded"), []byte("unrecorded_asset"))
			}
			for _, check := range []func() error{f.home.AuditOwned, f.home.verifyGenerated} {
				if err := check(); err == nil {
					t.Fatal("vendor tree accepted unsafe state")
				}
			}
			for index, call := range []func(context.Context, api.RunnerRequest) (api.RunnerPlan, error){f.service.Start, f.service.Resume, f.service.Turn} {
				if index > 0 {
					f.request.Target.Run = 2
					mode := "resume"
					if index == 2 {
						mode = "turn"
					}
					f.sourceLaunch(t, mode)
				}
				_, err := call(context.Background(), f.request)
				wantCode(t, err, api.CodeIntegrity)
			}
		})
	}
}

func TestSeedRecordsDirectories(t *testing.T) {
	home := testHome(t, testRecords(t))
	source := temporary(t)
	if err := os.Mkdir(filepath.Join(source, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(source, "asset"), []byte("generated_asset"))
	if err := home.Seed(source, ".claude/skills/review"); err != nil {
		t.Fatal(err)
	}
	if err := home.AuditOwned(); err != nil {
		t.Fatal("seeded directories lost protected provenance", err)
	}
	if err := home.verifyGenerated(); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(home.path, ".claude/skills/review/injected"), []byte("unexpected_asset"))
	if err := home.AuditOwned(); err == nil {
		t.Fatal("seed provenance accepted an extra asset")
	}
	if err := os.Remove(filepath.Join(home.path, ".claude/skills/review/injected")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home.path, ".claude/skills/review/empty")); err != nil {
		t.Fatal(err)
	}
	if err := home.verifyGenerated(); err == nil {
		t.Fatal("missing generated directory was accepted")
	}
}

func TestConversationTreeGuards(t *testing.T) {
	for _, kind := range []string{"directory-link", "file-hardlink", "directory-mode", "file-mode"} {
		t.Run(kind, func(t *testing.T) {
			f := runnerSetup(t)
			path := f.history(t)
			if found, err := f.home.conversation(f.request.Session); err != nil || !found {
				t.Fatal(err)
			}
			switch kind {
			case "directory-link":
				parent := filepath.Dir(path)
				if err := os.Rename(parent, parent+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-saved", parent); err != nil {
					t.Fatal(err)
				}
			case "file-hardlink":
				if err := os.Link(path, filepath.Join(temporary(t), "copy")); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.home.conversation(f.request.Session); err == nil {
				t.Fatal("conversation accepted shared state")
			}
		})
	}
}

func TestInspectStopsAtBound(t *testing.T) {
	files := fstest.MapFS{"a/x": &fstest.MapFile{}, "b/x": &fstest.MapFile{}, "c/x": &fstest.MapFile{}}
	findings, err := inspectFiles(files, 2)
	if err != nil {
		t.Fatal(err)
	}
	bounded := 0
	for _, finding := range findings {
		if finding.Kind == "unreadable-or-bounded" {
			bounded++
		}
	}
	if bounded != 1 {
		t.Fatal("inspection continued after its bound")
	}
	findings, err = inspectFiles(files, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Kind == "unreadable-or-bounded" {
			t.Fatal("unbounded control was incorrectly cut")
		}
	}
}

func TestRotationRecheckReleasesLease(t *testing.T) {
	f := runnerSetup(t)
	next := testCredential(t, "next", "next-login")
	var captured *lease
	f.slot.claimLogin = func(login string) (*lease, error) {
		claim, err := f.home.records.acquireLease("login/claudock-cli/" + login)
		if err != nil {
			return nil, err
		}
		captured = claim
		if err := f.home.records.markRotation(login); err != nil {
			claim.close()
			return nil, err
		}
		return claim, nil
	}
	defer func() {
		if err := captured.close(); err != nil {
			t.Error(err)
		}
	}()
	err := f.slot.Install(next)
	wantCode(t, err, api.CodeForbidden)
	if f.slot.logins[next.login] != nil {
		t.Fatal("rejected login polluted lease ownership")
	}
	probe, err := f.home.records.acquireLease("login/claudock-cli/" + next.login)
	if err != nil {
		t.Fatal("rotation recheck retained a rejected login lease", err)
	}
	if err := probe.close(); err != nil {
		t.Fatal(err)
	}
	credential, err := f.slot.Token()
	if err != nil || !bytes.Equal(credential.token, testCredential(t, "profile-a", "login-a").token) {
		t.Fatal("refused rotation changed the selected token", err)
	}
}

func TestRevokeNeedsRecords(t *testing.T) {
	for _, kind := range []string{"broad", "closed", "replaced"} {
		t.Run(kind, func(t *testing.T) {
			f := runnerSetup(t)
			r := f.home.records
			copyPath := filepath.Join(temporary(t), "copy")
			if err := os.Link(filepath.Join(f.home.path, ".runnerhome-runtime/.runnerhome-token"), copyPath); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "broad":
				if err := os.Chmod(r.path, 0755); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				if err := os.Rename(r.path, r.path+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(r.path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var revokeErr error
			func() {
				defer func() {
					if recover() != nil {
						t.Error("revocation used unchecked records")
					}
				}()
				_, revokeErr = f.slot.Revoke()
			}()
			if revokeErr == nil {
				t.Error("revocation used unchecked records")
			}
			markerPath := r.path
			if kind == "replaced" {
				markerPath += "-saved"
			}
			if _, err := os.Lstat(filepath.Join(markerPath, rotationName("login-a"))); !os.IsNotExist(err) {
				t.Error("revocation wrote through unchecked records")
			}
			if _, err := os.Stat(filepath.Join(f.home.path, ".runnerhome-runtime/.runnerhome-token")); !os.IsNotExist(err) {
				t.Error("record failure blocked credential removal")
			}
			if kind == "replaced" {
				if err := os.Remove(r.path); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(r.path+"-saved", r.path); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "broad" {
				if err := os.Chmod(r.path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "closed" {
				fresh, err := NewRecords(r.path)
				if err != nil {
					t.Fatal(err)
				}
				f.home.records = fresh
				t.Cleanup(func() {
					if _, err := f.slot.Close(); err != nil {
						t.Error(err)
					}
					if err := fresh.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			probe, err := f.home.records.acquireLease("login/claudock-cli/login-a")
			if !errors.Is(err, ErrBusy) {
				if probe != nil {
					probe.close()
				}
				t.Error("failed revocation released canonical ownership")
			}
			if _, err := f.slot.Revoke(); err != nil {
				t.Fatal("record recovery could not finish revocation", err)
			}
			wantCode(t, f.home.records.rotationAbsent("login-a"), api.CodeForbidden, "rotation recovery forgot copied credential")
			if _, err := f.slot.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
