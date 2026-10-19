//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type workspaceMutationStore struct {
	leaseStorage
	change  func() error
	changed bool
}

type workspaceCountReader struct {
	io.Reader
	bytes int
}

func (r *workspaceCountReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += n
	return n, err
}

func (s *workspaceMutationStore) Save(p leaseRecord) error {
	if err := s.leaseStorage.Save(p); err != nil {
		return err
	}
	if p.Storage.Workspace != nil && p.Storage.Workspace.Phase == "repository" && !s.changed {
		s.changed = true
		return s.change()
	}
	return nil
}

func TestWorkspaceConcurrentImport(t *testing.T) {
	m, p, index, q := workspaceProducerFixture(t)
	work := m.dataPins[p.DataJobs[index].Projection.OpenToken].roots[1]
	mutation := &workspaceMutationStore{leaseStorage: m.store, change: func() error {
		return os.WriteFile(filepath.Join(dataFD(work), "README.md"), []byte("changed during native import\n"), 0444)
	}}
	m.store = mutation
	err := m.ensureNativeWorkspace(context.Background(), &p, index, q)
	var typed *api.Error
	if !mutation.changed || !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
		t.Fatal("concurrent workspace change was accepted as the measured Git tree", err)
	}
	if p.Storage.Workspace.Phase == "published" {
		t.Fatal("concurrent import published enrollment")
	}
}

func workspaceTestBudget(t *testing.T, p *leaseRecord, index int, q *dataMeasure, budget uint64) {
	t.Helper()
	job := &p.DataJobs[index]
	job.Reg.Plan.Budget.DiskBytes = budget
	var input dataInput
	if err := decodeStrict(job.Input, &input); err != nil {
		t.Fatal(err)
	}
	input.Budget = job.Reg.Plan.Budget
	job.Input = mustCanaryJSON(t, input)
	job.Reg.Worker.Input.SHA256, job.Reg.Worker.Input.Bytes = digestBytes(job.Input), int64(len(job.Input))
	job.Reg.Plan.Input = job.Reg.Worker.Input
	job.Spec.Handoff.Spec.Worker = &job.Reg.Plan
	job.Spec.Handoff.Spec.Budget = job.Reg.Plan.Budget
	job.Spec.Original = mustCanaryJSON(t, job.Spec.Handoff.Spec)
	job.Spec.Handoff.SpecSHA256 = digestBytes(job.Spec.Original)
	job.Spec.Handoff.Original.SHA256, job.Spec.Handoff.Original.Bytes = digestBytes(job.Spec.Original), int64(len(job.Spec.Original))
	job.Gate.Prepared.SpecSHA256 = job.Spec.Handoff.SpecSHA256
	job.Result.InputSHA256 = job.Reg.Worker.Input.SHA256
	q.Reg = job.Reg
}

func TestWorkspaceBudgetBeforeWrite(t *testing.T) {
	m, p, index, q := workspaceProducerFixture(t)
	workspaceTestBudget(t, &p, index, &q, 100)
	if err := m.save(p); err != nil {
		t.Fatal("bounded materialization prerequisite is invalid", err)
	}
	err := m.ensureNativeWorkspace(context.Background(), &p, index, q)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeBudget {
		t.Fatal("over-budget import did not refuse with a budget result", err)
	}
	repository := filepath.Join(storageBase(m.binding, p), "repository-"+string(p.Storage.Binding.WorkspaceID))
	if _, err := os.Lstat(repository); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("over-budget import left a repository behind")
	}
	if _, err := os.Lstat(filepath.Join(storageBase(m.binding, p), string(p.Storage.Binding.WorkspaceID), ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("over-budget import left a Git pointer behind")
	}
}

func TestWorkspaceNestedRepository(t *testing.T) {
	m, p, index, q := workspaceProducerFixture(t)
	ctx := context.Background()
	if err := m.ensureNativeWorkspace(ctx, &p, index, q); err != nil {
		t.Fatal(err)
	}
	e := p.Storage.Workspace.Enrollment
	root := m.dataPins[p.DataJobs[index].Projection.OpenToken].roots[1]
	nested := filepath.Join(e.Parent, string(e.Workspace.ID), "nested-repository")
	marker := filepath.Join(nested, "marker")
	command := exec.Command(e.GitPath, "init", "--quiet", nested)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	monitor := filepath.Join(nested, "monitor")
	if err := os.WriteFile(monitor, []byte("#!/bin/sh\nprintf armed > '"+marker+"'\nprintf '\\000'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(nested, ".git", "config")
	file, err := os.OpenFile(config, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString("\n[core]\n\tfsmonitor = " + monitor + "\n")
	if closeErr := file.Close(); err != nil || closeErr != nil {
		t.Fatal("could not arm nested configuration")
	}
	positive := exec.Command(e.GitPath, "-C", nested, "status", "--porcelain")
	positive.Env = command.Env
	if err := positive.Run(); err != nil {
		t.Fatal("nested command positive control failed", err)
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "armed" {
		t.Fatal("nested configuration marker was not armed", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	err = verifyProducedWorkspace(ctx, e, root)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || !strings.Contains(typed.Message, "nested") {
		t.Fatal("nested Git configuration reached native workspace verification", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("nested Git configuration executed during native verification")
	}
}

func TestWorkspaceGitlink(t *testing.T) {
	m, p, index, q := workspaceProducerFixture(t)
	ctx := context.Background()
	if err := m.ensureNativeWorkspace(ctx, &p, index, q); err != nil {
		t.Fatal(err)
	}
	e := p.Storage.Workspace.Enrollment
	if _, err := gitSuccess(ctx, e, true, "update-index", "--add", "--cacheinfo", "160000,"+e.Workspace.Head+",nested-link"); err != nil {
		t.Fatal(err)
	}
	err := verifyProducedWorkspace(ctx, e, m.dataPins[p.DataJobs[index].Projection.OpenToken].roots[1])
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || !strings.Contains(typed.Message, "gitlink") {
		t.Fatal("native verification reached status with a gitlink index", err)
	}
}

func TestWorkspaceBudgetCleanup(t *testing.T) {
	m, p, index, q := workspaceProducerFixture(t)
	fault := &workspaceFaultStore{leaseStorage: m.store, phase: "linked"}
	m.store = fault
	if err := m.ensureNativeWorkspace(context.Background(), &p, index, q); err == nil || !fault.failed {
		t.Fatal("budget cleanup fixture did not retain its interrupted native stage", err)
	}
	p, err := m.find(p.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	e := p.Storage.Workspace.Enrollment
	repository, err := archiveRoot(e.Repository)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	ctx := context.WithValue(context.Background(), workspaceQuotaContext{}, &workspaceWriteQuota{root: repository, ceiling: q.Reg.Plan.Budget.DiskBytes, reserve: p.Storage.Workspace.ReservedBytes})
	live := func() error { return workspaceLive(ctx, p, p.DataJobs[index], q) }
	positive := &workspaceCountReader{Reader: strings.NewReader("quota positive control\n")}
	if _, err := workspaceGitInput(ctx, e, live, positive, "--git-dir="+e.Repository, "hash-object", "--no-filters", "-w", "--stdin"); err != nil || positive.bytes == 0 {
		t.Fatal("native quota positive control did not consume actual object bytes", err)
	}
	file, err := os.OpenFile(filepath.Join(e.Repository, "overflow"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(q.Reg.Plan.Budget.DiskBytes + 1)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	blocked := &workspaceCountReader{Reader: strings.NewReader("this object must not be read\n")}
	_, err = workspaceGitInput(ctx, e, live, blocked, "--git-dir="+e.Repository, "hash-object", "--no-filters", "-w", "--stdin")
	var refused *api.Error
	if !errors.As(err, &refused) || refused.Code != api.CodeBudget || blocked.bytes != 0 {
		t.Fatal("over-budget Git command consumed object bytes before quota admission", err)
	}
	err = m.ensureNativeWorkspace(context.Background(), &p, index, q)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeBudget {
		t.Fatal("late native quota readback did not retain the budget refusal", err)
	}
	for _, name := range []string{e.Repository, filepath.Join(e.Parent, string(e.Workspace.ID), ".git")} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("late over-budget import left native repository state behind")
		}
	}
	retained, err := m.find(p.Lease.ID)
	if err != nil || retained.Storage.Workspace.Phase != "budget_refused" {
		t.Fatal("quota collection lost its durable refused result", err)
	}
	if err := m.ensureNativeWorkspace(context.Background(), &retained, index, q); !errors.As(err, &typed) || typed.Code != api.CodeBudget {
		t.Fatal("quota-refused retry recreated a repository", err)
	}
}
