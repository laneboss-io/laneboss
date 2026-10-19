//go:build linux

package admin

import (
	"bytes"
	"context"
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
)

func verifyWorkspacePointer(root *os.File, gitDir string) error {
	file, err := archFile(root, ".git", false)
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := readProtectedDescriptor(file, 4096, 0, 0)
	if err != nil || string(raw) != "gitdir: "+gitDir+"\n" {
		return failure(api.CodeIntegrity, "native workspace Git pointer differs from its producer journal")
	}
	return dataNoAttributes(file)
}

func workspaceLive(ctx context.Context, p leaseRecord, job dataJob, q dataMeasure) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if job.State != "measured" || job.Result == nil || job.Result.ResultReceipt != q.Receipt ||
		!sameDataReg(job.Reg, q.Reg) || job.Result.Data.Target != q.Reg.Reservation.Target ||
		q.Reg.ClaimGeneration < job.Reg.ClaimGeneration || q.Reg.ClaimGeneration == job.Reg.ClaimGeneration && q.Reg.ClaimID != job.Reg.ClaimID ||
		digestBytes(q.Output) != q.Receipt.Result.SHA256 || int64(len(q.Output)) != q.Receipt.Result.Bytes ||
		digestBytes(q.Manifest) != job.Result.Manifest.SHA256 || int64(len(q.Manifest)) != job.Result.Manifest.Bytes {
		return failure(api.CodeConflict, "native workspace requires its original measured result and current claim")
	}
	for _, stamp := range []api.Timestamp{q.Reg.ClaimExpires, q.Reg.Worker.ExpiresAt, q.Reg.Grants.ExpiresAt, q.Reg.Inputs.Grants.ExpiresAt} {
		expires, err := time.Parse(time.RFC3339Nano, string(stamp))
		if err != nil || !expires.After(time.Now()) {
			return failure(api.CodeForbidden, "native workspace materialization claim or grants expired")
		}
	}
	if p.Storage.Workspace != nil {
		j := p.Storage.Workspace
		if j.StageID != q.Reg.Request.StageID || j.InputSHA256 != job.Result.InputSHA256 || j.Result != q.Receipt ||
			q.Reg.ClaimGeneration < j.ClaimGeneration || q.Reg.ClaimGeneration == j.ClaimGeneration && q.Reg.ClaimID != j.ClaimID {
			return failure(api.CodeConflict, "native workspace retry changed its stable materialization or current attempt")
		}
	}
	return nil
}

// Runs fixed Git built-ins only, with no inherited environment, template,
// hooks, external attributes, filters, fsmonitor, replace objects or transport.
// The repository is new, private and helper-owned; project configuration is
// copied as data and is never a source of Git configuration.
func workspaceGit(ctx context.Context, e cleanupEnrollment, live func() error, args ...string) ([]byte, error) {
	return workspaceGitInput(ctx, e, live, nil, args...)
}

func workspaceGitInput(ctx context.Context, e cleanupEnrollment, live func() error, input io.Reader, args ...string) ([]byte, error) {
	if err := live(); err != nil {
		return nil, err
	}
	if err := admitWorkspaceGitWrite(ctx, args); err != nil {
		return nil, err
	}
	if err := verifyExecutable(e.GitPath, e.GitArtifact); err != nil {
		return nil, err
	}
	fixed := nativeGitOptions()
	command := exec.CommandContext(ctx, e.GitPath, append(fixed, args...)...)
	command.Stdin = input
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1",
		"GIT_AUTHOR_NAME=Laneboss", "GIT_AUTHOR_EMAIL=laneboss@invalid", "GIT_COMMITTER_NAME=Laneboss", "GIT_COMMITTER_EMAIL=laneboss@invalid", "GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z"}
	var output, diagnostic cleanupOutput
	command.Stdout, command.Stderr = &output, &diagnostic
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, failure(api.CodeConflict, "native workspace Git operation failed; retain its original producer journal")
	}
	if err := live(); err != nil {
		return nil, err
	}
	return append([]byte{}, output.Bytes()...), nil
}

func (m *leaseManager) ensureNativeWorkspace(ctx context.Context, p *leaseRecord, index int, q dataMeasure) (resultErr error) {
	defer func() {
		var typed *api.Error
		if errors.As(resultErr, &typed) && typed.Code == api.CodeBudget && p.Storage != nil && p.Storage.Workspace != nil && p.Storage.Workspace.Phase != "published" && p.Storage.Workspace.Phase != "budget_refused" {
			if err := m.discardOverBudgetWorkspace(ctx, p); err != nil {
				resultErr = err
			}
		}
		if resultErr != nil && !errors.As(resultErr, &typed) {
			resultErr = failure(api.CodeContainmentUnknown, "native workspace operation could not be measured or persisted; retain its original journal")
		}
	}()
	if err := m.requireActive(*p, storageReady); err != nil {
		return err
	}
	if index < 0 || index >= len(p.DataJobs) {
		return failure(api.CodeIntegrity, "native workspace has no retained data job")
	}
	job := p.DataJobs[index]
	live := func() error { return workspaceLive(ctx, *p, job, q) }
	if err := live(); err != nil {
		return err
	}
	if p.Storage.Workspace != nil && p.Storage.Workspace.Phase == "budget_refused" {
		return failure(api.CodeBudget, "native workspace byte quota was refused; its repository was collected")
	}
	pins := m.dataPins[job.Projection.OpenToken]
	if pins == nil {
		return failure(api.CodeContainmentUnknown, "native workspace lost its materialization descriptors")
	}
	if err := checkDataPins(ctx, *p, job, pins); err != nil {
		return err
	}
	if err := m.resources.Quiescent(ctx, *p); err != nil {
		return err
	}
	if err := m.resources.Quiescent(ctx, dataChild(*p, job)); err != nil {
		return err
	}
	manifest, err := dataManifest(q.Manifest, q.Reg.Plan.Budget.DiskBytes)
	if err != nil {
		return err
	}
	gitDir := ""
	if p.Storage.Workspace != nil {
		gitDir = p.Storage.Workspace.Enrollment.GitDir
	}
	if err := dataVerifyWorkspace(ctx, pins.roots[1], manifest, p.Lease.UID, p.Lease.GID, gitDir); err != nil {
		return err
	}
	if err := rejectNestedWorkspaceGit(ctx, pins.roots[1]); err != nil {
		return err
	}
	charge, err := workspaceImportCharge(manifest, q.Reg.Plan.Budget.DiskBytes)
	if err != nil {
		return err
	}
	if p.Storage.Workspace == nil {
		artifact, err := pinWorkspaceGit()
		if err != nil {
			return err
		}
		rootID, err := randomID("workspace-root-")
		if err != nil {
			return err
		}
		repositoryID, err := randomID("workspace-repository-")
		if err != nil {
			return err
		}
		parentID, _, err := dataIdentity(pins.parents[1])
		if err != nil {
			return err
		}
		e := cleanupEnrollment{Schema: "laneboss.workspace-native.v2", Config: m.binding.Config, LeaseID: p.Lease.ID,
			Parent: storageBase(m.binding, *p), GitPath: "/usr/bin/git", GitArtifact: artifact,
			Workspace: api.CleanupWorkspace{ID: p.Storage.Binding.WorkspaceID, RootID: rootID, RepositoryID: repositoryID, Target: q.Reg.Reservation.Target,
				Generation: p.Storage.Binding.Home.Generation, RootIdentity: parentID, DirectoryIdentity: job.Projection.WorkspaceIdentity, Branch: "lane/" + string(q.Reg.Reservation.Target.LifeID)}}
		e.Repository = filepath.Join(e.Parent, "repository-"+string(e.Workspace.ID))
		e.GitDir = filepath.Join(e.Repository, "worktrees", string(e.Workspace.ID))
		for _, name := range []string{e.Repository, workspaceEnrollmentPath(e)} {
			if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return failure(api.CodeConflict, "native workspace destination exists without its producer journal")
			}
		}
		p.Storage.Workspace = &workspaceJournal{ReservedBytes: charge, Enrollment: e, StageID: q.Reg.Request.StageID, InputSHA256: job.Result.InputSHA256, Result: q.Receipt, ClaimID: q.Reg.ClaimID, ClaimGeneration: q.Reg.ClaimGeneration, Phase: "reserved"}
		if err := m.save(*p); err != nil {
			return err
		}
	}
	j := p.Storage.Workspace
	if j.ReservedBytes != 0 && j.ReservedBytes != charge {
		return failure(api.CodeConflict, "native workspace byte quota reservation changed")
	}
	j.ReservedBytes = charge
	j.ClaimID, j.ClaimGeneration = q.Reg.ClaimID, q.Reg.ClaimGeneration
	if err := m.save(*p); err != nil {
		return err
	}
	e := &j.Enrollment
	persist := func(phase string) error {
		if err := live(); err != nil {
			return err
		}
		j.Phase = phase
		return m.save(*p)
	}
	if j.Phase == "reserved" {
		repository, err := dataDirectory(pins.parents[1], "repository-"+string(e.Workspace.ID))
		if err != nil {
			return err
		}
		if err := dataEmpty(repository); err != nil {
			repository.Close()
			return failure(api.CodeContainmentUnknown, "uninitialized workspace repository contains unknown work")
		}
		e.Workspace.GitIdentity, _, err = dataIdentity(repository)
		closeErr := repository.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
		if err := persist("repository"); err != nil {
			return err
		}
	}
	held, err := pinCleanup(*e)
	if err != nil {
		return err
	}
	defer held.close()
	ceiling := q.Reg.Plan.Budget.DiskBytes
	for _, entry := range manifest.Entries {
		ceiling -= uint64(dataSize(entry))
	}
	ctx = context.WithValue(ctx, workspaceQuotaContext{}, &workspaceWriteQuota{root: held.repository, ceiling: ceiling, reserve: charge})
	run := func(args ...string) ([]byte, error) { return workspaceGit(ctx, *e, live, args...) }
	if j.Phase == "repository" {
		if err := checkWorkspaceWriteQuota(ctx, held.repository, ceiling, charge); err != nil {
			return err
		}
		snapshot, err := workspaceSnapshot(ctx, held.repository, pins.roots[1], manifest)
		if err != nil {
			return err
		}
		defer snapshot.Close()
		if _, err := run("init", "--quiet", "--bare", "--template=", "--object-format=sha1", "--initial-branch=bootstrap", e.Repository); err != nil {
			return err
		}
		tree, err := importWorkspaceTree(ctx, *e, snapshot, manifest, live)
		if err != nil {
			return err
		}
		if err := dataVerify(ctx, snapshot, manifest, 0, 0); err != nil {
			return err
		}
		raw, err := run("--git-dir="+e.Repository, "commit-tree", tree, "-m", "Imported workspace snapshot")
		if err != nil {
			return err
		}
		head := strings.TrimSpace(string(raw))
		if !cleanupHead(head) {
			return failure(api.CodeIntegrity, "native workspace Git commit is malformed")
		}
		if _, err := run("--git-dir="+e.Repository, "update-ref", "refs/heads/bootstrap", head); err != nil {
			return err
		}
		e.Workspace.Head = head
		j.ImportedTree = tree
		if err := persist("imported"); err != nil {
			return err
		}
	}
	if j.Phase == "imported" {
		if err := removeWorkspaceDirectory(ctx, held.repository, "snapshot", ""); err != nil {
			return err
		}
		if err := linkProducedWorkspace(ctx, *e, pins.roots[1], run); err != nil {
			return err
		}
		if err := persist("linked"); err != nil {
			return err
		}
	}
	if err := verifyProducedWorkspace(ctx, *e, pins.roots[1]); err != nil {
		return err
	}
	if err := dataVerifyWorkspace(ctx, pins.roots[1], manifest, p.Lease.UID, p.Lease.GID, e.GitDir); err != nil {
		return err
	}
	if j.ImportedTree != "" {
		raw, err := run("--git-dir="+e.GitDir, "rev-parse", "--verify", "HEAD^{tree}")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(raw)) != j.ImportedTree {
			return failure(api.CodeIntegrity, "produced Git tree changed its measured manifest pin")
		}
	}
	remaining := j.ReservedBytes
	for _, entry := range manifest.Entries {
		remaining -= uint64(dataSize(entry)) // dataManifest already checked the sum.
	}
	if err := syncWorkspaceRepository(ctx, held.repository, remaining); err != nil {
		return err
	}
	pointer, err := archFile(pins.roots[1], ".git", false)
	if err != nil {
		return err
	}
	if err := errors.Join(pointer.Sync(), pointer.Close()); err != nil {
		return err
	}
	if err := errors.Join(pins.roots[1].Sync(), held.parent.Sync()); err != nil {
		return err
	}
	if err := live(); err != nil {
		return err
	}
	if err := publishWorkspaceEnrollment(*e); err != nil {
		return err
	}
	return persist("published")
}

func linkProducedWorkspace(ctx context.Context, e cleanupEnrollment, work *os.File, run func(...string) ([]byte, error)) error {
	stageParent := filepath.Join(e.Repository, "stage")
	if err := os.Mkdir(stageParent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := protectedPath(stageParent, true); err != nil {
		return err
	}
	stage := filepath.Join(stageParent, string(e.Workspace.ID))
	var st unix.Stat_t
	pointerErr := unix.Fstatat(int(work.Fd()), ".git", &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(pointerErr, unix.ENOENT) {
		if _, err := os.Lstat(e.GitDir); errors.Is(err, os.ErrNotExist) {
			head, present, err := cleanupBranch(ctx, e)
			if err != nil || present && head != e.Workspace.Head {
				return failure(api.CodeIntegrity, "native workspace retry found a foreign branch")
			}
			args := []string{"--git-dir=" + e.Repository, "worktree", "add", "--quiet", "--no-checkout"}
			if !present {
				args = append(args, "-b", e.Workspace.Branch, stage, e.Workspace.Head)
			} else {
				args = append(args, stage, e.Workspace.Branch)
			}
			if _, err := run(args...); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		staged, err := archiveRoot(stage)
		if err != nil {
			return err
		}
		if err := verifyWorkspacePointer(staged, e.GitDir); err != nil {
			staged.Close()
			return err
		}
		err = unix.Renameat2(int(staged.Fd()), ".git", int(work.Fd()), ".git", unix.RENAME_NOREPLACE)
		err = errors.Join(err, staged.Sync(), staged.Close(), work.Sync())
		if err != nil {
			return err
		}
	} else if pointerErr != nil {
		return pointerErr
	}
	if err := verifyWorkspacePointer(work, e.GitDir); err != nil {
		return err
	}
	if _, err := run("--git-dir="+e.Repository, "worktree", "repair", "--", filepath.Join(e.Parent, string(e.Workspace.ID))); err != nil {
		return err
	}
	if _, err := run("--git-dir="+e.GitDir, "read-tree", e.Workspace.Head); err != nil {
		return err
	}
	if err := unix.Rmdir(stage); err != nil && !errors.Is(err, unix.ENOENT) {
		return failure(api.CodeContainmentUnknown, "native workspace staging worktree contains unknown work")
	}
	return nil
}

func verifyProducedWorkspace(ctx context.Context, e cleanupEnrollment, work *os.File) error {
	identity, _, err := dataIdentity(work)
	if err != nil || identity != e.Workspace.DirectoryIdentity {
		return failure(api.CodeIntegrity, "native workspace changed its allocated inode")
	}
	if err := verifyWorkspacePointer(work, e.GitDir); err != nil {
		return err
	}
	if err := rejectNestedWorkspaceGit(ctx, work); err != nil {
		return err
	}
	registered, err := cleanupRegistered(ctx, e)
	if err != nil {
		return err
	}
	head, present, err := cleanupBranch(ctx, e)
	if err != nil || !registered || !present || head != e.Workspace.Head {
		return failure(api.CodeIntegrity, "native workspace has no exact Git branch and worktree registration")
	}
	raw, err := gitSuccess(ctx, e, true, "symbolic-ref", "--quiet", "HEAD")
	if err != nil || strings.TrimSpace(string(raw)) != "refs/heads/"+e.Workspace.Branch {
		return failure(api.CodeIntegrity, "native workspace points at another Git branch")
	}
	raw, err = gitSuccess(ctx, e, true, "ls-files", "--stage", "-z")
	if err != nil {
		return err
	}
	if err := checkCleanupIndex(raw); err != nil {
		return err
	}
	raw, err = gitSuccess(ctx, e, true, "ls-tree", "-r", "-z", "HEAD")
	if err != nil {
		return err
	}
	if err := checkWorkspaceTree(raw); err != nil {
		return err
	}
	raw, err = gitSuccess(ctx, e, true, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=all")
	if err != nil {
		return err
	}
	if len(raw) != 0 {
		return failure(api.CodeConflict, "native workspace import differs from its measured tree")
	}
	return nil
}

func workspaceEnrollmentPath(e cleanupEnrollment) string {
	return workspaceRegistryFile(e.Config, e.Workspace.ID)
}

func publishWorkspaceEnrollment(e cleanupEnrollment) error {
	if !validConfig(e.Config) || !validID(e.Workspace.ID) {
		return failure(api.CodeInvalid, "invalid native workspace registry selector")
	}
	path := workspaceEnrollmentPath(e)
	state := (installation{Config: e.Config}).statePath()
	if err := protectedPath(state, true); err != nil {
		return err
	}
	stateRoot, err := dataParent(state)
	if err != nil {
		return err
	}
	defer stateRoot.Close()
	parent, err := dataDirectory(stateRoot, "workspaces")
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := protectedPath(filepath.Dir(path), true); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		raw, err := readProtected(path, api.MaxFrameBytes)
		if err != nil {
			return err
		}
		var actual cleanupEnrollment
		if decodeStrict(raw, &actual) != nil || !reflect.DeepEqual(actual, e) {
			return failure(api.CodeIdempotencyConflict, "native workspace registry retry changed its published enrollment")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := canonicalValue(e)
	if err != nil {
		return err
	}
	name, err := randomID("pending-")
	if err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), string(name), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "workspace-enrollment")
	n, err := file.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	// The shipped unit uses UMask=0077. Set the publication metadata on the
	// held file explicitly, before syncing or exposing its final name.
	if err == nil {
		err = unix.Fchown(fd, 0, 0)
	}
	if err == nil {
		err = unix.Fchmod(fd, 0444)
	}
	if err = errors.Join(err, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := unix.Renameat2(int(parent.Fd()), string(name), int(parent.Fd()), filepath.Base(path), unix.RENAME_NOREPLACE); err != nil {
		return failure(api.CodeConflict, "native workspace registry publication raced another record")
	}
	if err := parent.Sync(); err != nil {
		return err
	}
	actual, err := readProtected(path, api.MaxFrameBytes)
	if err != nil || !bytes.Equal(actual, raw) {
		return failure(api.CodeIntegrity, "native workspace registry failed exact protected readback")
	}
	return nil
}
