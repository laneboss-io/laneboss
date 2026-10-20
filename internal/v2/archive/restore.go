package archive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func restoreFault(code api.ErrorCode, name string) error {
	return &api.Error{Code: code, Owner: "lb-v2-lifecycle", Message: name,
		Instead: "Keep the archive and any partial destination; select a fresh path inside an active authorized workspace after resolving the refusal."}
}

// Restore creates an independent worktree. Its Git objects and dirty files
// come exclusively from the frozen inventory, through checked bounded reads.
// It never opens the original workspace, repository or archive for writing.
type RestoreOptions struct {
	Roots          []string
	AllowNestedGit bool
	Report         *api.RestoreReceipt
}

func Restore(ctx context.Context, target string, tree api.ObjectManifest, read ReadObject, ceiling uint64, options ...RestoreOptions) (string, error) {
	if len(options) != 1 {
		return "", restoreFault(api.CodeForbidden, "restore_target_scope")
	}
	option := options[0]
	parent, err := restoreParent(target, option.Roots)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	base := filepath.Base(target)
	existing, err := EmptyRestoreTarget(parent, base)
	if err != nil {
		return "", err
	}
	skipped, err := RestorePolicy(tree, option.AllowNestedGit)
	if err != nil {
		return "", err
	}
	selected, pack, err := restoreInventory(tree)
	if err != nil {
		return "", err
	}
	// Verify the complete archive input before creating any destination. The
	// service also checks the persisted canonical tar with ReadBack.
	if err := Write(ctx, io.Discard, tree, read, ceiling); err != nil {
		return "", restoreFault(api.CodeIntegrity, "restore_archive_invalid: "+err.Error())
	}
	var gitPack bytes.Buffer
	if err := copyContent(ctx, &gitPack, pack, read, ceiling); err != nil {
		return "", err
	}
	info, err := parent.Stat(".")
	if err != nil || info.Mode().Perm()&0022 != 0 {
		return "", restoreFault(api.CodeForbidden, "restore_parent_writable")
	}
	if !existing {
		if err := parent.Mkdir(base, 0700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return "", restoreFault(api.CodeConflict, "restore_target_exists")
			}
			return "", restoreFault(api.CodeForbidden, "restore_target_unwritable")
		}
	}
	root, err := restoreChild(parent, base)
	if err != nil {
		return "", err
	}
	defer root.Close()
	return writeRestore(ctx, root, tree, selected, skipped, gitPack.Bytes(), read, ceiling, option)
}

// RestoreRoot fills an already held empty inode. The native helper's child
// receives this handle without authority to resolve a caller's host path.
func RestoreRoot(ctx context.Context, root *os.Root, tree api.ObjectManifest, read ReadObject, ceiling uint64, option RestoreOptions) (string, error) {
	file, err := root.Open(".")
	if err != nil {
		return "", err
	}
	items, readErr := file.ReadDir(1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(items) != 0 {
		return "", restoreFault(api.CodeConflict, "restore_target_exists")
	}
	skipped, err := RestorePolicy(tree, option.AllowNestedGit)
	if err != nil {
		return "", err
	}
	selected, pack, err := restoreInventory(tree)
	if err != nil {
		return "", err
	}
	if err := Write(ctx, io.Discard, tree, read, ceiling); err != nil {
		return "", restoreFault(api.CodeIntegrity, "restore_archive_invalid")
	}
	var gitPack bytes.Buffer
	if err := copyContent(ctx, &gitPack, pack, read, ceiling); err != nil {
		return "", err
	}
	return writeRestore(ctx, root, tree, selected, skipped, gitPack.Bytes(), read, ceiling, option)
}

func writeRestore(ctx context.Context, root *os.Root, tree api.ObjectManifest, selected []api.ObjectEntry, skipped map[string]bool, pack []byte, read ReadObject, ceiling uint64, option RestoreOptions) (string, error) {
	if err := restoreRepository(ctx, root, tree.Git, pack); err != nil {
		return "", err
	}
	var err error
	report := api.RestoreReceipt{ClearedModes: []string{}, SkippedPaths: []string{}}
	for _, entry := range selected {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		name := strings.TrimPrefix(entry.Path, "workspace/")
		if entry.Path == "workspace" {
			name = "."
		}
		if skipped[entry.Path] {
			report.SkippedPaths = append(report.SkippedPaths, name)
			continue
		}
		if entry.Mode&07000 != 0 {
			cleared := name
			if entry.Path == "workspace" {
				cleared = "."
			}
			report.ClearedModes = append(report.ClearedModes, cleared)
		}
		if entry.Path == "workspace" {
			continue
		}
		switch entry.Kind {
		case "directory":
			err = root.Mkdir(name, 0700)
		case "symlink":
			err = root.Symlink(entry.LinkTarget, name)
		case "file":
			var file *os.File
			file, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				err = copyContent(ctx, file, entry, read, ceiling)
				if err == nil {
					err = file.Chmod(os.FileMode(entry.Mode & 0777))
				}
				if err == nil {
					err = file.Sync()
				}
				err = errors.Join(err, file.Close())
			}
		}
		if err != nil {
			return "", err
		}
	}
	// Apply restrictive directory modes only after every child is written.
	for i := len(selected) - 1; i >= 0; i-- {
		entry := selected[i]
		if entry.Kind != "directory" || skipped[entry.Path] {
			continue
		}
		name := strings.TrimPrefix(entry.Path, "workspace/")
		if entry.Path == "workspace" {
			name = "."
		}
		if err := root.Chmod(name, os.FileMode(entry.Mode&0777)); err != nil {
			return "", err
		}
	}
	sort.Strings(report.ClearedModes)
	sort.Strings(report.SkippedPaths)
	if len(report.ClearedModes) == 0 {
		report.ClearedModes = nil
	}
	if len(report.SkippedPaths) == 0 {
		report.SkippedPaths = nil
	}
	if option.Report != nil {
		option.Report.ClearedModes, option.Report.SkippedPaths = report.ClearedModes, report.SkippedPaths
	}
	return tree.Git.Head, nil
}

func restoreInventory(tree api.ObjectManifest) ([]api.ObjectEntry, api.ObjectEntry, error) {
	if err := manifest.Archived(tree); err != nil {
		return nil, api.ObjectEntry{}, restoreFault(api.CodeIntegrity, "restore_manifest_invalid")
	}
	if tree.Git == nil {
		return nil, api.ObjectEntry{}, restoreFault(api.CodePrerequisite, "restore_git_missing")
	}
	if !manifest.GitHead(tree.Git.Head) || manifest.Relative(tree.Git.Branch) != nil {
		return nil, api.ObjectEntry{}, restoreFault(api.CodeIntegrity, "restore_git_invalid")
	}
	selected, err := manifest.SelectArchive(tree, "workspace")
	if err != nil {
		return nil, api.ObjectEntry{}, restoreFault(api.CodeIntegrity, "restore_workspace_invalid")
	}
	var pack api.ObjectEntry
	for _, entry := range tree.Entries {
		if entry.Path == "git/pack" {
			pack = entry
		}
	}
	if pack.Kind != "file" || pack.Content == nil {
		return nil, pack, restoreFault(api.CodeIntegrity, "restore_git_pack_missing")
	}
	known := map[string]bool{}
	for _, entry := range selected {
		known[entry.Path] = entry.Kind == "directory"
		if entry.Kind == "symlink" && entry.Mode&0777 != 0777 {
			return nil, pack, restoreFault(api.CodeIntegrity, "restore_manifest_invalid")
		}
	}
	if !known["workspace"] {
		return nil, pack, restoreFault(api.CodeIntegrity, "restore_workspace_missing")
	}
	for _, entry := range selected {
		if entry.Path != "workspace" && !known[path.Dir(entry.Path)] {
			return nil, pack, restoreFault(api.CodeIntegrity, "restore_directory_missing")
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
	return selected, pack, nil
}

func restoreRepository(ctx context.Context, root *os.Root, git *api.ArchiveGit, pack []byte) error {
	if os.Geteuid() == 0 {
		return restoreFault(api.CodeForbidden, "restore_git_privileged")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	// Enter the held inode and use relative paths: the native child cannot
	// traverse its staged tree's helper-private ancestor.
	location := "/dev/fd/" + strconv.Itoa(int(directory.Fd()))
	if runtime.GOOS == "linux" {
		location = "/proc/self/fd/" + strconv.Itoa(int(directory.Fd()))
	}
	run := func(input []byte, args ...string) ([]byte, error) {
		fixed := []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null",
			"-c", "protocol.allow=never", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
			"--git-dir=.git", "--work-tree=."}
		cmd := exec.CommandContext(ctx, "/usr/bin/git", append(fixed, args...)...)
		cmd.Dir = location
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "TMPDIR=.", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_ATTR_NOSYSTEM=1", "GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0"}
		cmd.Stdin = bytes.NewReader(input)
		var output bytes.Buffer
		cmd.Stdout = &output
		if err := cmd.Run(); err != nil {
			return nil, restoreFault(api.CodeIntegrity, "restore_git_failed")
		}
		return output.Bytes(), nil
	}
	format := "sha1"
	if len(git.Head) == 64 {
		format = "sha256"
	}
	for _, args := range [][]string{{"init", "--template=", "--object-format=" + format}, {"check-ref-format", "refs/heads/" + git.Branch}} {
		if _, err := run(nil, args...); err != nil {
			return err
		}
	}
	if _, err := run(pack, "index-pack", "--stdin", "--strict", "--threads=1"); err != nil {
		return err
	}
	kind, err := run(nil, "cat-file", "-t", git.Head)
	if err != nil || string(kind) != "commit\n" {
		return restoreFault(api.CodeIntegrity, "restore_head_missing")
	}
	for _, args := range [][]string{{"symbolic-ref", "HEAD", "refs/heads/" + git.Branch}, {"update-ref", "HEAD", git.Head}, {"read-tree", git.Head}} {
		if _, err := run(nil, args...); err != nil {
			return err
		}
	}
	// Publish only the fixed local configuration, even if a Git subprocess
	// changed it. Exclusive creation also refuses a racing link replacement.
	if err := root.Remove(".git/config"); err != nil {
		return err
	}
	file, err := root.OpenFile(".git/config", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, RestoreConfig(git.Head))
	return errors.Join(writeErr, file.Sync(), file.Close())
}

// RestoreConfig is derived only from the authenticated object format. No
// archived configuration, attributes, hooks or external transport is enabled.
func RestoreConfig(head string) string {
	version, extension := "0", ""
	if len(head) == 64 {
		version, extension = "1", "[extensions]\n\tobjectformat = sha256\n"
	}
	return "[core]\n\trepositoryformatversion = " + version + "\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = false\n" + extension
}
