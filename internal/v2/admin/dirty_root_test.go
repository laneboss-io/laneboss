//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Execute real withdrawal, archive mode projection and dirty cleanup on a
// Git worktree. The installed service/worker setup is outside this component.
func TestDirtyFreeze(t *testing.T) {
	e, persist := nativeCleanFixture(t)
	ctx := context.Background()
	work := filepath.Join(e.Parent, string(e.Workspace.ID))
	tracked, untracked := filepath.Join(work, "README.md"), filepath.Join(work, "dirty.txt")
	if err := os.WriteFile(tracked, []byte("tracked baseline\n"), 0444); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "--", "README.md"},
		{"-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "-m", "baseline"}} {
		if _, err := gitSuccess(ctx, e, true, args...); err != nil {
			t.Fatal(err)
		}
	}
	tip, present, err := cleanupBranch(ctx, e)
	if err != nil || !present {
		t.Fatal("cannot read component baseline", err)
	}
	e.Workspace.Head = tip
	if _, err := gitSuccess(ctx, e, false, "update-ref", "HEAD", tip); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tracked, []byte("tracked baseline\nunsaved tracked work\n"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(untracked, []byte("unsaved untracked work\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(work)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	measure := func(prior map[string]api.ObjectEntry, freeze, frozen bool) ([]api.ObjectEntry, []storageInode) {
		t.Helper()
		ceiling := uint64(1 << 20)
		entries, _, inodes, err := walkArchive(ctx, root, "workspace", "component-archive", prior, freeze, frozen, &ceiling)
		if err != nil {
			t.Fatal(err)
		}
		return entries, inodes
	}
	live, _ := measure(nil, false, false)
	gitState := func() [][]byte {
		t.Helper()
		var result [][]byte
		for _, name := range []string{filepath.Join(e.GitDir, "HEAD"), filepath.Join(e.GitDir, "index"),
			filepath.Join(e.Repository, "HEAD"), filepath.Join(e.Repository, "refs/heads", e.Workspace.Branch)} {
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, raw)
		}
		return result
	}
	gitBefore := gitState()
	modes, err := walkRetainModes(ctx, root, e.Workspace.ID, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := retainModeTree(ctx, root, e.Workspace.ID, modes); err != nil {
		t.Fatal(err)
	}
	_, record, _ := storageFixture(t)
	record.Storage.Withdrawn = true
	record.Storage.Directories[0].ID = e.Workspace.ID
	record.Storage.OriginalModes = modes
	archived, inodes := measure(nil, false, false)
	if err := restoreArchiveModes(record, "workspace", archived, inodes, true); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(live, archived) {
		t.Fatal("archive lost original names, modes or dirty bytes")
	}
	prior := map[string]api.ObjectEntry{}
	for _, entry := range archived {
		prior[entry.Path] = entry
	}
	measure(prior, true, false)
	measure(prior, false, true)
	frozen, _ := measure(nil, false, false)
	if reflect.DeepEqual(live, frozen) {
		t.Fatal("cross-phase control did not reproduce the physical mode difference")
	}
	info, err := os.Stat(untracked)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("archive did not withdraw the actual untracked write mode", err)
	}
	before, err := inspectNativeWorkspace(ctx, e)
	if err != nil || before.Dirty == nil || !*before.Dirty {
		t.Fatal("native component lost dirty work", err)
	}
	action, after, err := nativeWorkspaceAction(ctx, e, nativeCleanupJob(t, e), before, persist)
	if err != nil || action != "retain_dirty" || !sameWorkspaceObservation(before, after) {
		t.Fatal("native dirty cleanup changed its disposition", err)
	}
	kept, _ := measure(nil, false, false)
	if !reflect.DeepEqual(frozen, kept) || !reflect.DeepEqual(gitBefore, gitState()) {
		t.Fatal("dirty cleanup changed retained modes, bytes, index, HEAD or branch")
	}
	t.Log("native phases: untracked 0600 -> 0400 at archive; original manifest modes/bytes preserved; clean changes no file, index, HEAD or ref")
	// Prove the byte comparison catches a real kept-file change. This test's
	// root observer can mutate its isolated canary; the installed item cannot.
	if err := os.WriteFile(untracked, []byte("changed canary\n"), 0400); err != nil {
		t.Fatal(err)
	}
	changed, _ := measure(nil, false, false)
	if reflect.DeepEqual(frozen, changed) {
		t.Fatal("retained byte comparison missed its changed-file control")
	}
	t.Log("RED control: an actual retained-file change is detected")
}
