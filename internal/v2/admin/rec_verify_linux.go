//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// Verification never executes Git as root and never repairs child ownership.
// The enclosing stage is still root-private and the child cgroup is empty.
func verifyRestored(ctx context.Context, root *os.File, uid, gid uint32, job *nativeRestore) error {
	skipped, err := archivejob.RestorePolicy(job.Input.Tree, job.Input.Request.AllowNestedGit)
	if err != nil {
		return err
	}
	expected := map[string]api.ObjectEntry{}
	cleared, omitted := []string{}, []string{}
	var pack api.ObjectEntry
	for _, entry := range job.Input.Tree.Entries {
		if entry.Path == "git/pack" {
			pack = entry
		}
		if entry.Path != "workspace" && !strings.HasPrefix(entry.Path, "workspace/") {
			continue
		}
		name := strings.TrimPrefix(entry.Path, "workspace/")
		if entry.Path == "workspace" {
			name = "."
		}
		if skipped[entry.Path] {
			omitted = append(omitted, name)
			continue
		}
		if entry.Mode&07000 != 0 {
			cleared = append(cleared, name)
		}
		entry.Mode &= 0777
		expected[entry.Path] = entry
	}
	if _, exists := expected["workspace"]; !exists {
		expected["workspace"] = api.ObjectEntry{Path: "workspace", Kind: "directory", Mode: 0700}
	}
	slices.Sort(cleared)
	slices.Sort(omitted)
	if job.Input.Tree.Git == nil || job.Report.Head != job.Input.Tree.Git.Head || !slices.Equal(cleared, job.Report.ClearedModes) || !slices.Equal(omitted, job.Report.SkippedPaths) {
		return failure(api.CodeIntegrity, "restore child receipt differs from its frozen input")
	}
	ceiling := job.Input.Ceiling
	actual, _, _, err := walkArchive(ctx, root, "workspace", "restore-check", nil, false, false, &ceiling)
	if err != nil {
		return err
	}
	for _, entry := range actual {
		want, exists := expected[entry.Path]
		if !exists || entry.Kind != want.Kind || entry.Mode != want.Mode || entry.LinkTarget != want.LinkTarget {
			return failure(api.CodeIntegrity, "restore child changed workspace names, modes or links")
		}
		if entry.Kind == "file" {
			digest := api.Digest("")
			if want.Content != nil {
				digest = want.Content.SHA256
			} else if want.Assembly != nil {
				digest = want.Assembly.SHA256
			}
			if entry.Content == nil || entry.Content.SHA256 != digest || entry.Content.Bytes != dataSize(want) {
				return failure(api.CodeIntegrity, "restore child changed frozen workspace bytes")
			}
		}
		delete(expected, entry.Path)
	}
	if len(expected) != 0 {
		return failure(api.CodeIntegrity, "restore child omitted frozen workspace output")
	}
	remaining, count, packs := job.Input.Ceiling*2+1<<20, 0, 0
	var walk func(*os.File, string, int) error
	walk = func(file *os.File, name string, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		count++
		var info unix.Stat_t
		if unix.Fstat(int(file.Fd()), &info) != nil || info.Uid != uid || info.Gid != gid || info.Mode&07000 != 0 || count > 65536 || depth > 70 {
			return failure(api.CodeIntegrity, "restore child output has unsafe owner or mode")
		}
		if err := dataNoAttributes(file); err != nil {
			return err
		}
		directory := info.Mode&unix.S_IFMT == unix.S_IFDIR
		if (name == ".git" || strings.HasPrefix(name, ".git/")) && !restoreGitPath(name, directory, job.Input.Tree.Git.Branch) {
			return failure(api.CodeIntegrity, "restore child added unexpected Git metadata")
		}
		if !directory {
			if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 || info.Size < 0 || uint64(info.Size) > remaining {
				return failure(api.CodeIntegrity, "restore child output is linked, special or oversized")
			}
			remaining -= uint64(info.Size)
			if strings.HasPrefix(name, ".git/objects/pack/") && strings.HasSuffix(name, ".pack") {
				packs++
				if info.Size != dataSize(pack) || dataHash(ctx, file, io.Discard, pack) != nil {
					return failure(api.CodeIntegrity, "restore child changed the supplied Git pack")
				}
			}
			return nil
		}
		items, err := file.ReadDir(65537)
		if err != nil && !errors.Is(err, io.EOF) || len(items) > 65536 {
			return failure(api.CodeIntegrity, "restore child directory exceeds its inventory bound")
		}
		for _, item := range items {
			childName := item.Name()
			if name != "." {
				childName = name + "/" + childName
			}
			var link unix.Stat_t
			if unix.Fstatat(int(file.Fd()), item.Name(), &link, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return failure(api.CodeIntegrity, "restore child inode changed")
			}
			if link.Mode&unix.S_IFMT == unix.S_IFLNK {
				if strings.HasPrefix(childName, ".git/") || link.Uid != uid || link.Gid != gid || link.Nlink != 1 {
					return failure(api.CodeIntegrity, "restore child left an unsafe link")
				}
				continue // The complete workspace walk checked its exact target.
			}
			child, err := archFile(file, item.Name(), item.IsDir())
			if err != nil {
				return err
			}
			err = errors.Join(walk(child, childName, depth+1), child.Close())
			if err != nil {
				return err
			}
		}
		return nil
	}
	view, err := archFile(root, ".", true)
	if err != nil {
		return err
	}
	err = errors.Join(walk(view, ".", 0), view.Close())
	if err != nil || packs != 1 {
		return errors.Join(err, failure(api.CodeIntegrity, "restore child Git inventory is incomplete"))
	}
	for name, want := range map[string]string{".git/config": archivejob.RestoreConfig(job.Input.Tree.Git.Head), ".git/HEAD": "ref: refs/heads/" + job.Input.Tree.Git.Branch + "\n", ".git/refs/heads/" + job.Input.Tree.Git.Branch: job.Input.Tree.Git.Head + "\n"} {
		file, err := archFile(root, name, false)
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, int64(len(want)+1)))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || string(raw) != want {
			return failure(api.CodeIntegrity, "restore child Git head differs from its frozen input")
		}
	}
	return nil
}

func restoreGitPath(name string, directory bool, branch string) bool {
	switch name {
	case ".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs", ".git/refs/heads", ".git/refs/tags", ".git/logs", ".git/logs/refs", ".git/logs/refs/heads":
		return directory
	case ".git/HEAD", ".git/config", ".git/description", ".git/index", ".git/logs/HEAD":
		return !directory
	}
	for _, prefix := range []string{".git/refs/heads/", ".git/logs/refs/heads/"} {
		if strings.HasPrefix(name, prefix) {
			tail := strings.TrimPrefix(name, prefix)
			return directory && strings.HasPrefix(branch, tail+"/") || !directory && tail == branch
		}
	}
	if directory || path.Dir(name) != ".git/objects/pack" {
		return false
	}
	ext := path.Ext(name)
	stem := strings.TrimSuffix(path.Base(name), ext)
	return (ext == ".pack" || ext == ".idx" || ext == ".rev") && strings.HasPrefix(stem, "pack-") && cleanupHead(strings.TrimPrefix(stem, "pack-"))
}
