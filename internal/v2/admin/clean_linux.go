//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func (m *leaseManager) cleanupEnrollment(target api.LifeRef, id api.ID) (cleanupEnrollment, leaseRecord, error) {
	var e cleanupEnrollment
	if !validID(id) || !validID(target.LifeID) || target.Run == 0 {
		return e, leaseRecord{}, failure(api.CodeInvalid, "invalid native cleanup selector")
	}
	raw, err := readProtected(workspaceRegistryFile(m.binding.Config, id), api.MaxFrameBytes)
	if err != nil {
		return e, leaseRecord{}, err
	}
	if err := decodeStrict(raw, &e); err != nil {
		return e, leaseRecord{}, err
	}
	w := e.Workspace
	if e.Schema != "laneboss.workspace-native.v2" || e.Config != m.binding.Config || w.ID != id || w.Target != target || !validID(e.LeaseID) || !validID(w.RootID) || !validID(w.RepositoryID) || w.ID == w.RootID || w.ID == w.RepositoryID || w.RootID == w.RepositoryID || w.Generation == 0 || w.RootIdentity == "" || w.DirectoryIdentity == "" || w.GitIdentity == "" || w.Branch != "lane/"+string(target.LifeID) {
		return e, leaseRecord{}, failure(api.CodeIntegrity, "protected workspace enrollment is foreign or incomplete")
	}
	p, err := m.find(e.LeaseID)
	if err != nil {
		return e, p, err
	}
	if p.BootID != m.bootID || p.Storage == nil || p.Storage.Binding.WorkspaceID != id || e.Parent != storageBase(m.binding, p) || e.GitDir != filepath.Join(e.Repository, "worktrees", string(id)) || w.DirectoryIdentity != p.Storage.Directories[0].Device+":"+p.Storage.Directories[0].Inode {
		return e, p, failure(api.CodeIntegrity, "cleanup enrollment differs from its retained native allocation")
	}
	if p.Storage.Workspace != nil && (p.Storage.Workspace.Phase != "published" || !reflect.DeepEqual(p.Storage.Workspace.Enrollment, e)) {
		return e, p, failure(api.CodeIntegrity, "workspace registry differs from its durable producer journal")
	}
	if err := verifyExecutable(e.GitPath, e.GitArtifact); err != nil {
		return e, p, err
	}
	return e, p, nil
}

type cleanupPins struct{ parent, repository *os.File }

func (p *cleanupPins) close() error { return errors.Join(p.parent.Close(), p.repository.Close()) }

func pinCleanup(e cleanupEnrollment) (*cleanupPins, error) {
	for _, name := range []string{e.Parent, e.Repository} {
		if err := protectedPath(name, true); err != nil {
			return nil, err
		}
	}
	parent, err := archiveRoot(e.Parent)
	if err != nil {
		return nil, err
	}
	repository, err := archiveRoot(e.Repository)
	if err != nil {
		parent.Close()
		return nil, err
	}
	pins := &cleanupPins{parent: parent, repository: repository}
	parentID, _, pe := dataIdentity(parent)
	repoID, _, re := dataIdentity(repository)
	if pe != nil || re != nil || parentID != e.Workspace.RootIdentity || repoID != e.Workspace.GitIdentity {
		pins.close()
		return nil, failure(api.CodeIntegrity, "cleanup parent or Git handle was replaced")
	}
	return pins, nil
}

type cleanupOutput struct{ bytes.Buffer }

func (b *cleanupOutput) Write(p []byte) (int, error) {
	if len(p) > api.MaxFrameBytes-b.Len() {
		return 0, failure(api.CodeBudget, "native Git output exceeds its bounded observation")
	}
	return b.Buffer.Write(p)
}

// Fixed built-ins, an empty inherited environment, disabled hooks/fsmonitor and
// a pinned administrator executable. No shell, lane-selected argv or force flag.
func cleanupGit(ctx context.Context, e cleanupEnrollment, worktree bool, args ...string) ([]byte, int, error) {
	if err := checkGitMetadata(e); err != nil {
		return nil, -1, err
	}
	if err := verifyExecutable(e.GitPath, e.GitArtifact); err != nil {
		return nil, -1, err
	}
	gitDir := e.Repository
	if worktree {
		gitDir = e.GitDir
		if err := protectedPath(gitDir, true); err != nil {
			return nil, -1, err
		}
	}
	fixed := append(nativeGitOptions(), "-c", "core.quotePath=false", "--git-dir="+gitDir)
	if worktree {
		fixed = append(fixed, "--work-tree="+filepath.Join(e.Parent, string(e.Workspace.ID)))
	}
	fixed = append(fixed, args...)
	command := exec.CommandContext(ctx, e.GitPath, fixed...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1"}
	var output, diagnostic cleanupOutput
	command.Stdout, command.Stderr = &output, &diagnostic
	err := command.Run()
	if err == nil {
		return append([]byte{}, output.Bytes()...), 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return append([]byte{}, output.Bytes()...), exit.ExitCode(), nil
	}
	if ctx.Err() != nil {
		return nil, -1, ctx.Err()
	}
	return nil, -1, failure(api.CodeContainmentUnknown, "native Git execution or bounded observation failed")
}

func checkGitMetadata(e cleanupEnrollment) error {
	for _, name := range []string{"config", "HEAD"} {
		if _, err := readProtected(filepath.Join(e.Repository, name), api.MaxFrameBytes); err != nil {
			return err
		}
	}
	for _, name := range []string{"refs", "refs/heads", "refs/heads/lane", "worktrees"} {
		full := filepath.Join(e.Repository, name)
		if _, err := os.Lstat(full); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return failure(api.CodeContainmentUnknown, "Git namespace parent is unreadable")
		}
		if err := protectedPath(full, true); err != nil {
			return err
		}
	}
	for _, name := range []string{"refs/heads/" + e.Workspace.Branch, "packed-refs"} {
		full := filepath.Join(e.Repository, name)
		if _, err := os.Lstat(full); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return failure(api.CodeContainmentUnknown, "Git namespace reference is unreadable")
		}
		if _, err := readProtected(full, api.MaxObjectBytes); err != nil {
			return err
		}
	}
	return nil
}

func gitSuccess(ctx context.Context, e cleanupEnrollment, worktree bool, args ...string) ([]byte, error) {
	output, code, err := cleanupGit(ctx, e, worktree, args...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, failure(api.CodeConflict, "unforced native Git operation refused; retain the original workspace and branch journal")
	}
	return output, nil
}

func cleanupBranch(ctx context.Context, e cleanupEnrollment) (string, bool, error) {
	// Quiet show-ref has documented exit 1 only for a missing exact ref. A
	// second hash read pins a present branch; other exits remain unknown.
	_, code, err := cleanupGit(ctx, e, false, "show-ref", "--verify", "--quiet", "refs/heads/"+e.Workspace.Branch)
	if err != nil {
		return "", false, err
	}
	if code == 1 {
		return "", false, nil
	}
	if code != 0 {
		return "", false, failure(api.CodeContainmentUnknown, "native branch namespace is unreadable")
	}
	output, err := gitSuccess(ctx, e, false, "rev-parse", "--verify", "refs/heads/"+e.Workspace.Branch)
	if err != nil {
		return "", false, err
	}
	head := strings.TrimSpace(string(output))
	if !cleanupHead(head) {
		return "", false, failure(api.CodeIntegrity, "native branch head is malformed")
	}
	return head, true, nil
}

func cleanupHead(head string) bool {
	if len(head) != 40 && len(head) != 64 {
		return false
	}
	for _, c := range head {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

func cleanupRegistered(ctx context.Context, e cleanupEnrollment) (bool, error) {
	output, err := gitSuccess(ctx, e, false, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return false, err
	}
	actual := filepath.Join(e.Parent, string(e.Workspace.ID))
	found := false
	for _, field := range bytes.Split(output, []byte{0}) {
		if bytes.HasPrefix(field, []byte("worktree ")) && string(field[len("worktree "):]) == actual {
			if found {
				return false, failure(api.CodeIntegrity, "worktree registry repeats the protected workspace")
			}
			found = true
		}
	}
	return found, nil
}

func inspectNativeWorkspace(ctx context.Context, e cleanupEnrollment) (api.WorkspaceReadback, error) {
	var result api.WorkspaceReadback
	pins, err := pinCleanup(e)
	if err != nil {
		return result, err
	}
	defer pins.close()
	id, err := randomID("workspace-read-")
	if err != nil {
		return result, err
	}
	result = api.WorkspaceReadback{ID: id, WorkspaceID: e.Workspace.ID, RootIdentity: e.Workspace.RootIdentity, GitIdentity: e.Workspace.GitIdentity}
	head, branch, err := cleanupBranch(ctx, e)
	if err != nil {
		return result, err
	}
	registered, err := cleanupRegistered(ctx, e)
	if err != nil {
		return result, err
	}
	var st unix.Stat_t
	err = unix.Fstatat(int(pins.parent.Fd()), string(e.Workspace.ID), &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		if registered {
			return result, failure(api.CodeContainmentUnknown, "absent worktree retains a Git registration; absence is uncertain")
		}
		result.WorktreeState = "absent"
	} else {
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || nativeIdentity(st) != e.Workspace.DirectoryIdentity || !registered {
			return result, failure(api.CodeIntegrity, "worktree directory or protected Git registration changed")
		}
		file, err := openStorageDirectory(pins.parent, string(e.Workspace.ID))
		if err != nil {
			return result, err
		}
		identity, info, identityErr := dataIdentity(file)
		closeErr := file.Close()
		if identityErr != nil || closeErr != nil {
			return result, failure(api.CodeIntegrity, "cleanup worktree has not withdrawn writable ownership")
		}
		if identity != e.Workspace.DirectoryIdentity || info.Uid != 0 || info.Gid != 0 || info.Mode&0022 != 0 {
			allowAndLog("cleanup_worktree_ownership")
		}
		// A linked worktree's administrative pointer is exact protected input.
		pointer, err := readProtected(filepath.Join(e.Parent, string(e.Workspace.ID), ".git"), 4096)
		if err != nil || string(pointer) != "gitdir: "+e.GitDir+"\n" {
			return result, failure(api.CodeIntegrity, "workspace Git pointer differs from its enrolled repository handle")
		}
		current, err := gitSuccess(ctx, e, true, "symbolic-ref", "--quiet", "HEAD")
		if err != nil {
			return result, err
		}
		if strings.TrimSpace(string(current)) != "refs/heads/"+e.Workspace.Branch {
			return result, failure(api.CodeIntegrity, "workspace now selects another branch")
		}
		current, err = gitSuccess(ctx, e, true, "rev-parse", "--verify", "HEAD")
		if err != nil {
			return result, err
		}
		if strings.TrimSpace(string(current)) != head || !branch {
			return result, failure(api.CodeIntegrity, "worktree and branch heads differ")
		}
		index, err := gitSuccess(ctx, e, true, "ls-files", "--stage", "-z")
		if err != nil {
			return result, err
		}
		if err := checkCleanupIndex(index); err != nil {
			return result, err
		}
		root, err := archiveRoot(filepath.Join(e.Parent, string(e.Workspace.ID)))
		if err != nil {
			return result, err
		}
		err = errors.Join(rejectNestedWorkspaceGit(ctx, root), root.Close())
		if err != nil {
			return result, err
		}
		current, err = gitSuccess(ctx, e, true, "ls-tree", "-r", "-z", "HEAD")
		if err != nil {
			return result, err
		}
		if err := checkWorkspaceTree(current); err != nil {
			return result, err
		}
		status, err := gitSuccess(ctx, e, true, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=all")
		if err != nil {
			return result, err
		}
		dirty := len(status) != 0
		result.WorktreeState, result.DirectoryIdentity, result.Head, result.Dirty = "present", identity, head, &dirty
	}
	result.BranchState = "absent"
	if branch {
		result.BranchState = "present"
	}
	if result.WorktreeState == "present" && e.Workspace.Head != "" && head != e.Workspace.Head {
		return result, failure(api.CodeConflict, "cleanup pinned Git head changed")
	}
	// Reopen both protected parents after all Git subprocesses have exited.
	check, err := pinCleanup(e)
	if err != nil {
		return result, err
	}
	if err := check.close(); err != nil {
		return result, err
	}
	result.ObservedAt = gateTimestamp()
	return result, nil
}

func (m *leaseManager) cleanupParent(ctx context.Context, job api.CleanupJob) (cleanupEnrollment, leaseRecord, error) {
	if err := api.ValidateCleanupJob(job, time.Now()); err != nil {
		return cleanupEnrollment{}, leaseRecord{}, err
	}
	e, p, err := m.cleanupEnrollment(job.Intent.Cause.Target, job.Intent.Workspace.ID)
	if err != nil {
		return e, p, err
	}
	w := e.Workspace
	w.Head = job.Intent.Workspace.Head
	if w != job.Intent.Workspace || p.Archive == nil || p.Archive.Phase != "frozen" || p.Archive.Freeze.Snapshot != job.Intent.Archive.Manifest || p.Receipt == nil || !reflect.DeepEqual(*p.Receipt, job.Intent.Release) || !p.Storage.Withdrawn {
		return e, p, failure(api.CodeForbidden, "cleanup differs from its native archive, release or protected workspace")
	}
	e.Workspace = w
	if p.Cleanup != nil {
		if p.Cleanup.Phase == "complete" && p.Cleanup.Removal != nil && p.Cleanup.Removal.Action == "retain_dirty" {
			fresh, err := inspectNativeWorkspace(ctx, e)
			if err != nil {
				return e, p, err
			}
			if err := validateCleanupSuccessorOrRetainedDirty(p.Cleanup, job, &fresh, time.Now()); err != nil {
				return e, p, err
			}
		} else if err := validateCleanupSuccessor(p.Cleanup, job, time.Now()); err != nil {
			return e, p, err
		}
	}
	// A completed journal authorizes only fresh namespace reads and replay.
	// Its released UID may now belong to another life; no process is restarted.
	if !cleanupReleasesUIDs(p) {
		if err := m.resources.Quiescent(ctx, p); err != nil {
			return e, p, err
		}
	}
	return e, p, nil
}

func syncCleanup(e cleanupEnrollment) error {
	pins, err := pinCleanup(e)
	if err != nil {
		return err
	}
	defer pins.close()
	for _, name := range []string{"refs", "refs/heads", "refs/heads/lane", "worktrees", "packed-refs"} {
		fd, err := fdpath.Open(int(pins.repository.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return failure(api.CodeContainmentUnknown, "cannot sync the protected Git removal namespace")
		}
		file := os.NewFile(uintptr(fd), "cleanup-sync")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
			file.Close()
			return failure(api.CodeIntegrity, "Git removal sync handle changed kind or owner")
		}
		if st.Uid != 0 || st.Mode&0022 != 0 {
			allowAndLog("cleanup_sync_owner")
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return err
		}
	}
	return errors.Join(pins.parent.Sync(), pins.repository.Sync())
}

func (m *leaseManager) removeCleanup(ctx context.Context, q cleanupQuery) (api.WorkspaceRemoval, error) {
	e, p, err := m.cleanupParent(ctx, q.Job)
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if p.Cleanup != nil && p.Cleanup.Removal != nil {
		if p.Cleanup.Removal.Action == "retain_dirty" &&
			(!reflect.DeepEqual(p.Cleanup.Job.Intent, q.Job.Intent) || !reflect.DeepEqual(p.Cleanup.Job.Claim.Record.Effect, q.Job.Claim.Record.Effect)) {
			fresh, err := inspectNativeWorkspace(ctx, e)
			if err != nil {
				return api.WorkspaceRemoval{}, err
			}
			if err := validateCleanupSuccessorOrRetainedDirty(p.Cleanup, q.Job, &fresh, time.Now()); err != nil {
				return api.WorkspaceRemoval{}, err
			}
			p, result, err := m.performCleanup(ctx, e, p, q)
			if err != nil {
				return api.WorkspaceRemoval{}, err
			}
			return m.finishCleanup(p, q.Job, result)
		}
		if err := validateCleanupRemovalJournal(p.Cleanup, q.Job, time.Now()); err != nil {
			return api.WorkspaceRemoval{}, err
		}
		fresh, err := inspectNativeWorkspace(ctx, e)
		if err != nil {
			return api.WorkspaceRemoval{}, err
		}
		if !sameWorkspaceObservation(fresh, p.Cleanup.Removal.After) {
			return api.WorkspaceRemoval{}, failure(api.CodeIntegrity, "cleanup replay differs from independently reopened namespaces")
		}
		return *p.Cleanup.Removal, nil
	}
	if p.Cleanup != nil && p.Cleanup.Phase == "retained_unmerged" {
		fresh, err := inspectNativeWorkspace(ctx, e)
		if err != nil {
			return api.WorkspaceRemoval{}, err
		}
		if p.Cleanup.Retained == nil || !sameWorkspaceObservation(fresh, *p.Cleanup.Retained) {
			return api.WorkspaceRemoval{}, failure(api.CodeIntegrity, "terminal retained cleanup changed its kept namespaces")
		}
		// Older retained journals may predate worker collection. Keep their
		// UID reservations until the same native collector succeeds.
		if err := m.collectArchiveWorker(ctx, &p); err != nil {
			return api.WorkspaceRemoval{}, err
		}
		return api.WorkspaceRemoval{}, p.Cleanup.Refusal
	}
	if p.Cleanup != nil {
		return api.WorkspaceRemoval{}, failure(api.CodeContainmentUnknown, "native cleanup operation was interrupted; retain its original journal")
	}
	p, result, err := m.performCleanup(ctx, e, p, q)
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	return m.finishCleanup(p, q.Job, result)
}

// The native result is measured before completion publication. Keeping this
// boundary explicit lets journal delay preserve the original measured authority.
func (m *leaseManager) performCleanup(ctx context.Context, e cleanupEnrollment, p leaseRecord, q cleanupQuery) (leaseRecord, api.WorkspaceRemoval, error) {
	before, err := inspectNativeWorkspace(ctx, e)
	if err != nil {
		return p, api.WorkspaceRemoval{}, err
	}
	if !sameWorkspaceObservation(before, q.Before) || before.WorktreeState != "present" || before.BranchState != "present" || before.Head != e.Workspace.Head || before.Dirty == nil {
		return p, api.WorkspaceRemoval{}, failure(api.CodeConflict, "cleanup dirty-work decision changed before removal")
	}
	if err := m.collectArchiveWorker(ctx, &p); err != nil {
		return p, api.WorkspaceRemoval{}, err
	}
	if err := requireCleanupMerged(ctx, e, before); err != nil {
		return p, api.WorkspaceRemoval{}, m.retainCleanupRefusal(&p, q.Job, err)
	}
	history := cleanupHistoryForSuccessor(p.Cleanup)
	p.Cleanup = &cleanupJournal{Job: q.Job, Phase: "decided", Before: before, History: history}
	if err := m.save(p); err != nil {
		return p, api.WorkspaceRemoval{}, err
	}
	result := api.WorkspaceRemoval{IntentID: q.Job.Intent.ID, ClaimID: q.Job.Claim.ClaimID, Before: before, Unforced: true}
	result.Action, result.After, err = nativeWorkspaceAction(ctx, e, q.Job, before, func(phase string) error {
		p.Cleanup.Phase = phase
		return m.save(p)
	})
	if err != nil {
		return p, api.WorkspaceRemoval{}, m.retainCleanupRefusal(&p, q.Job, err)
	}
	result.Synced = true
	return p, result, nil
}

func nativeWorkspaceAction(ctx context.Context, e cleanupEnrollment, job api.CleanupJob, before api.WorkspaceReadback, persist func(string) error) (string, api.WorkspaceReadback, error) {
	var zero api.WorkspaceReadback
	fresh, err := inspectNativeWorkspace(ctx, e)
	if err != nil {
		return "", zero, err
	}
	if !sameWorkspaceObservation(fresh, before) || before.Dirty == nil || before.WorktreeState != "present" || before.BranchState != "present" {
		return "", zero, failure(api.CodeConflict, "native cleanup decision is unknown or changed")
	}
	if err := requireCleanupMerged(ctx, e, before); err != nil {
		return "", zero, err
	}
	action := "retain_dirty"
	if *before.Dirty {
		if err := persist("retaining_dirty"); err != nil {
			return "", zero, err
		}
	} else {
		action = "remove_clean"
		if err := persist("removing"); err != nil {
			return "", zero, err
		}
		if err := removeUnforcedWorktree(ctx, e, job); err != nil {
			return "", zero, err
		}
		if err := persist("worktree_removed"); err != nil {
			return "", zero, err
		}
		// -d preserves Git's merged-branch decision, including abandoned work.
		if _, err := cleanupGitRemoval(ctx, e, job, "branch", "-d", "--", e.Workspace.Branch); err != nil {
			return "", zero, err
		}
	}
	if err := syncCleanup(e); err != nil {
		return "", zero, err
	}
	after, err := inspectNativeWorkspace(ctx, e)
	if err != nil {
		return "", zero, err
	}
	if action == "remove_clean" && (after.WorktreeState != "absent" || after.BranchState != "absent") || action == "retain_dirty" && !sameWorkspaceObservation(before, after) {
		return "", zero, failure(api.CodeIntegrity, "cleanup lacks independent worktree and branch disposition readback")
	}
	return action, after, nil
}

func removeUnforcedWorktree(ctx context.Context, e cleanupEnrollment, job api.CleanupJob) error {
	_, err := cleanupGitRemoval(ctx, e, job, "worktree", "remove", "--", filepath.Join(e.Parent, string(e.Workspace.ID)))
	return err
}

func (m *leaseManager) dispatchCleanup(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	var q cleanupQuery
	if err := decodeStrict(raw, &q); err != nil {
		return nil, err
	}
	if method == "cleanup_resolve" {
		e, _, err := m.cleanupEnrollment(q.Target, q.WorkspaceID)
		if err != nil {
			return nil, err
		}
		// The enrollment pins the imported base. A later cleanup pins the
		// lane's current tip only after independently measuring this registry.
		e.Workspace.Head = ""
		read, err := inspectNativeWorkspace(ctx, e)
		if err != nil {
			return nil, err
		}
		if read.WorktreeState != "present" || read.BranchState != "present" {
			return nil, failure(api.CodeConflict, "cleanup resolution lacks its protected current workspace and branch")
		}
		e.Workspace.Head = read.Head
		return e.Workspace, nil
	}
	if method == "cleanup_remove" {
		return m.removeCleanup(ctx, q)
	}
	e, p, err := m.cleanupParent(ctx, q.Job)
	if err != nil {
		return nil, err
	}
	if method == "cleanup_journal" {
		if p.Cleanup == nil || p.Cleanup.Removal == nil && p.Cleanup.Refusal == nil {
			return nil, failure(api.CodeContainmentUnknown, "cleanup has no authenticated native operation journal")
		}
		return *p.Cleanup, nil
	}
	if method == "cleanup_read" || method == "cleanup_inspect" {
		return inspectNativeWorkspace(ctx, e)
	}
	return nil, failure(api.CodeForbidden, "unknown native cleanup operation")
}

var _ io.Writer = (*cleanupOutput)(nil)
