//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func nativeCleanFixture(t *testing.T) (cleanupEnrollment, func(string) error) {
	return nativeCleanFixtureFor(t, "workspace", "clean-life")
}

func nativeCleanFixtureFor(t *testing.T, workspace, life api.ID) (cleanupEnrollment, func(string) error) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("native cleanup canary requires the disposable root Linux host")
	}
	base, err := os.MkdirTemp("/var/lib", "lb-v2-admin-clean-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	git, err := os.ReadFile("/usr/bin/git")
	if err != nil {
		t.Fatal("native Git fixture executable unavailable")
	}
	gitPath := filepath.Join(base, "git")
	if err := os.WriteFile(gitPath, git, 0555); err != nil {
		t.Fatal(err)
	}
	// Start from an empty initial commit. The unmerged regression below adds
	// its own real lane commit, as required by the cleanup review brief.
	main := filepath.Join(base, "main")
	for _, args := range [][]string{{"init", "--quiet", main}, {"-C", main, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "--allow-empty", "-m", "initial"}} {
		command := exec.Command(gitPath, args...)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
		if err := command.Run(); err != nil {
			t.Fatal("native Git fixture setup failed")
		}
	}
	parent := filepath.Join(base, "lanes")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	e := cleanupEnrollment{Parent: parent, Repository: filepath.Join(main, ".git"), GitPath: gitPath, GitArtifact: api.ReleaseArtifact{Bytes: int64(len(git)), SHA256: digestBytes(git)}, Workspace: api.CleanupWorkspace{ID: workspace, RootID: "root", RepositoryID: "repository", Target: api.LifeRef{LifeID: life, Run: 1}, Generation: 1, Branch: "lane/" + string(life)}}
	e.GitDir = filepath.Join(e.Repository, "worktrees", string(e.Workspace.ID))
	if _, err := gitSuccess(context.Background(), e, false, "worktree", "add", "--quiet", "-b", e.Workspace.Branch, filepath.Join(parent, string(e.Workspace.ID)), "HEAD"); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		dst  *string
	}{{parent, &e.Workspace.RootIdentity}, {e.Repository, &e.Workspace.GitIdentity}, {filepath.Join(parent, string(e.Workspace.ID)), &e.Workspace.DirectoryIdentity}} {
		file, err := os.Open(item.name)
		if err != nil {
			t.Fatal(err)
		}
		identity, _, readErr := dataIdentity(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("native cleanup identity setup failed")
		}
		*item.dst = identity
	}
	head, present, err := cleanupBranch(context.Background(), e)
	if err != nil || !present {
		t.Fatal("native cleanup branch setup failed")
	}
	e.Workspace.Head = head
	journal, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	persist := func(phase string) error {
		if err := proofWrite(journal, "journal.json", struct{ Phase string }{phase}); err != nil {
			return err
		}
		raw, err := proofRead(journal, "journal.json", 0)
		if err != nil {
			return err
		}
		var actual struct{ Phase string }
		if err := decodeStrict(raw, &actual); err != nil {
			return err
		}
		if actual.Phase != phase {
			return errors.New("cleanup journal readback differs")
		}
		return nil
	}
	return e, persist
}

func TestNativeClean(t *testing.T) {
	for _, mode := range []string{"clean", "dirty", "changed", "parent", "unforced", "journal", "unmerged", "gitlink", "expired", "expiry-worktree", "expiry-branch"} {
		t.Run(mode, func(t *testing.T) {
			e, persist := nativeCleanFixture(t)
			ctx := context.Background()
			name := filepath.Join(e.Parent, string(e.Workspace.ID), "untracked")
			if mode == "dirty" || mode == "unforced" {
				if err := os.WriteFile(name, []byte("retained dirty bytes\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unmerged" {
				own := filepath.Join(e.Parent, string(e.Workspace.ID), "owned.txt")
				if err := os.WriteFile(own, []byte("lane commit kept on abandoned branch\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := gitSuccess(ctx, e, true, "add", "--", "owned.txt"); err != nil {
					t.Fatal(err)
				}
				if _, err := gitSuccess(ctx, e, true, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "-m", "lane work"); err != nil {
					t.Fatal(err)
				}
				tip, present, err := cleanupBranch(ctx, e)
				if err != nil || !present || tip == e.Workspace.Head {
					t.Fatal("unmerged fixture has no own lane commit")
				}
				e.Workspace.Head = tip
			}
			before, err := inspectNativeWorkspace(ctx, e)
			if err != nil || before.Dirty == nil {
				t.Fatal("native cleanup before observation failed")
			}
			job := nativeCleanupJob(t, e)
			switch mode {
			case "expired", "expiry-worktree", "expiry-branch":
				testCleanupExpiry(t, mode, e, job, before, persist)
				return
			case "unmerged":
				_, _, err := nativeWorkspaceAction(ctx, e, job, before, persist)
				var typed *api.Error
				_, statErr := os.Stat(filepath.Join(e.Parent, string(e.Workspace.ID), "owned.txt"))
				tip, present, readErr := cleanupBranch(ctx, e)
				if !errors.As(err, &typed) || typed.Code != api.ErrorCode("cleanup_branch_unmerged") || typed.Retryable || statErr != nil || readErr != nil || !present || tip != e.Workspace.Head {
					t.Fatal("acceptance: unmerged cleanup did not retain both namespaces with a terminal code")
				}
				var proof interface {
					CleanupRetention() (api.WorkspaceReadback, api.WorkspaceReadback, string, string)
				}
				if !errors.As(err, &proof) {
					t.Fatal("acceptance: unmerged cleanup lost its measured retention reason")
				}
				old, after, branch, common := proof.CleanupRetention()
				if !sameWorkspaceObservation(old, after) || branch != e.Workspace.Head || branch == common {
					t.Fatal("acceptance: unmerged cleanup lost its measured retention reason")
				}
				return
			case "gitlink":
				if _, err := gitSuccess(ctx, e, true, "update-index", "--add", "--cacheinfo", "160000,"+e.Workspace.Head+",nested"); err != nil {
					t.Fatal(err)
				}
				_, err := inspectNativeWorkspace(ctx, e)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown {
					t.Fatal("acceptance: cleanup ran status for a gitlink index")
				}
				return
			case "parent":
				e.Workspace.RootIdentity += "-replaced"
				if _, err := inspectNativeWorkspace(ctx, e); err == nil {
					t.Fatal("acceptance: cleanup accepted a replaced protected parent")
				}
				return
			case "changed":
				// Pass ancestry and index classification before changing real
				// work. HEAD stays pinned so ancestry cannot mask this control.
				if *before.Dirty {
					t.Fatal("changed fixture did not start clean")
				}
				if err := requireCleanupMerged(ctx, e, before); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("work added after cleanup preflights\n"), 0600); err != nil {
					t.Fatal(err)
				}
				changed, err := inspectNativeWorkspace(ctx, e)
				if err != nil || changed.Dirty == nil || !*changed.Dirty || changed.Head != before.Head || sameWorkspaceObservation(changed, before) {
					t.Fatal("changed fixture did not change the actual dirty-work decision")
				}
				_, _, err = nativeWorkspaceAction(ctx, e, job, before, persist)
				var typed *api.Error
				kept, readErr := os.ReadFile(name)
				after, inspectErr := inspectNativeWorkspace(ctx, e)
				if !errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != "native cleanup decision is unknown or changed" || typed.Owner != owner || readErr != nil || string(kept) != "work added after cleanup preflights\n" || inspectErr != nil || !sameWorkspaceObservation(changed, after) {
					t.Fatal("acceptance: cleanup removed a changed dirty-work decision")
				}
				return
			case "unforced":
				err := removeUnforcedWorktree(ctx, e, job)
				_, statErr := os.Stat(name)
				_, present, readErr := cleanupBranch(ctx, e)
				if err == nil || statErr != nil || readErr != nil || !present {
					t.Fatal("acceptance: unforced Git collection removed dirty work")
				}
				return
			case "journal":
				journalErr := errors.New("injected durable journal refusal")
				_, _, err := nativeWorkspaceAction(ctx, e, job, before, func(phase string) error {
					if err := persist(phase); err != nil {
						return err
					}
					return journalErr
				})
				_, statErr := os.Stat(filepath.Join(e.Parent, string(e.Workspace.ID)))
				_, present, readErr := cleanupBranch(ctx, e)
				if !errors.Is(err, journalErr) || statErr != nil || readErr != nil || !present {
					t.Fatal("acceptance: cleanup crossed a failed durable journal")
				}
				return
			}
			action, after, err := nativeWorkspaceAction(ctx, e, job, before, persist)
			if mode == "dirty" {
				bytes, readErr := os.ReadFile(name)
				if err != nil || action != "retain_dirty" || readErr != nil || !strings.Contains(string(bytes), "retained dirty") || !sameWorkspaceObservation(before, after) {
					t.Fatal("acceptance: dirty native workspace was removed or relabeled")
				}
			} else {
				_, statErr := os.Stat(filepath.Join(e.Parent, string(e.Workspace.ID)))
				_, present, branchErr := cleanupBranch(ctx, e)
				if err != nil || action != "remove_clean" || after.WorktreeState != "absent" || after.BranchState != "absent" || !errors.Is(statErr, os.ErrNotExist) || branchErr != nil || present {
					t.Fatal("acceptance: clean collection lacks actual branch and worktree absence")
				}
			}
		})
	}
}
