//go:build linux

package admin

import (
	"bytes"
	"context"
	"os/exec"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

type archivePackOutput struct {
	bytes.Buffer
	limit uint64
}

func (b *archivePackOutput) Write(data []byte) (int, error) {
	if uint64(len(data)) > b.limit-uint64(b.Len()) {
		return 0, failure(api.CodeBudget, "archive Git pack exceeds its retained byte budget")
	}
	return b.Buffer.Write(data)
}

// Git objects are read at the protected, recorded head. pack-objects writes
// only stdout; it never changes the retained repository or opens launch access.
func archiveGitPack(ctx context.Context, r leaseRecord) (*api.ArchiveGit, []byte, error) {
	if r.Storage == nil || r.Storage.Workspace == nil {
		return nil, nil, failure(api.CodePrerequisite, "archive has no recorded Git producer")
	}
	e := r.Storage.Workspace.Enrollment
	if r.Storage.Workspace.Phase != "published" || !cleanupHead(e.Workspace.Head) {
		return nil, nil, failure(api.CodeIntegrity, "archive Git producer has no published head")
	}
	pins, err := pinCleanup(e)
	if err != nil {
		return nil, nil, err
	}
	defer pins.close()
	head, present, err := cleanupBranch(ctx, e)
	if err != nil || !present || head != e.Workspace.Head {
		return nil, nil, failure(api.CodeIntegrity, "archive Git branch differs from its recorded head")
	}
	if err := verifyExecutable(e.GitPath, e.GitArtifact); err != nil {
		return nil, nil, err
	}
	args := append(nativeGitOptions(), "--git-dir="+e.Repository, "pack-objects", "--stdout", "--revs", "--threads=1", "--window=0", "--no-reuse-delta", "--no-reuse-object")
	cmd := exec.CommandContext(ctx, e.GitPath, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0"}
	cmd.Stdin = strings.NewReader(head + "\n")
	output := &archivePackOutput{limit: min(r.Request.Budget.DiskBytes, uint64(api.MaxObjectBytes))}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return nil, nil, failure(api.CodeIntegrity, "archive Git pack could not be read completely")
	}
	return &api.ArchiveGit{Head: head, Branch: e.Workspace.Branch}, output.Bytes(), nil
}
