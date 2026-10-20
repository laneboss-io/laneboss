//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (m *leaseManager) restoreOwner(ctx context.Context, q restoreBegin) (leaseRecord, string, error) {
	raw, err := json.Marshal(q.Caller)
	if err != nil {
		return leaseRecord{}, "", err
	}
	roots, err := m.restoreRoots(ctx, raw)
	if err != nil {
		return leaseRecord{}, "", err
	}
	parent, err := archivejob.RestoreDestination(q.Request.Path, roots)
	if err != nil {
		return leaseRecord{}, "", err
	}
	_, err = archivejob.EmptyRestoreTarget(parent, filepath.Base(q.Request.Path))
	closeErr := parent.Close()
	if err != nil || closeErr != nil {
		return leaseRecord{}, "", errors.Join(err, closeErr)
	}
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, "", err
	}
	for _, r := range records {
		if r.Storage == nil {
			continue
		}
		root := filepath.Join(storageBase(m.binding, r), string(r.Storage.Binding.WorkspaceID))
		rel, err := filepath.Rel(root, q.Request.Path)
		if err == nil && rel != "." && filepath.IsLocal(rel) && slices.Contains(roots, root) {
			return r, root, nil
		}
	}
	return leaseRecord{}, "", failure(api.CodeForbidden, "restore_target_scope")
}

func (m *leaseManager) dispatchRestore(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if method == "restore_begin" {
		var q restoreBegin
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		if q.Request.AllowNestedGit && q.Caller.Actor.Kind != "human" {
			return nil, failure(api.CodeForbidden, "restore_owner_required")
		}
		if err := manifest.Archived(q.Tree); err != nil {
			return nil, err
		}
		if _, err := archivejob.RestorePolicy(q.Tree, q.Request.AllowNestedGit); err != nil {
			return nil, err
		}
		r, root, err := m.restoreOwner(ctx, q)
		if err != nil {
			return nil, err
		}
		if m.restores == nil {
			m.restores = map[api.ID]*nativeRestore{}
		}
		for id, job := range m.restores {
			if time.Since(job.Created) > 5*time.Minute {
				if job.Stage != "" {
					if err := os.RemoveAll(job.Stage); err != nil {
						return nil, err
					}
				}
				delete(m.restores, id)
			}
		}
		if len(m.restores) != 0 {
			return nil, failure(api.CodeConflict, "a native restore is already staged")
		}
		q.Ceiling = min(q.Ceiling, r.Request.Budget.DiskBytes, uint64(128<<20))
		job := &nativeRestore{Input: q, Lease: r.Lease.ID, Root: root, Refs: map[api.ID]api.BlobRef{}, Bodies: map[api.ID][]byte{}, Created: time.Now()}
		var total uint64
		for _, e := range q.Tree.Entries {
			for _, ref := range manifest.ContentRefs(e) {
				if old, exists := job.Refs[ref.ID]; exists {
					if old != ref {
						return nil, failure(api.CodeIntegrity, "restore source pin overlaps")
					}
					continue
				}
				total += uint64(ref.Bytes)
				if total > q.Ceiling {
					return nil, failure(api.CodeBudget, "restore exceeds active workspace budget")
				}
				job.Refs[ref.ID] = ref
				job.Bodies[ref.ID] = []byte{}
			}
		}
		id, err := randomID("rec-")
		if err != nil {
			return nil, err
		}
		m.restores[id] = job
		return id, nil
	}
	if method == "restore_chunk" {
		var q restoreChunk
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		job := m.restores[q.ID]
		if job == nil || job.Stage != "" {
			return nil, failure(api.CodeForbidden, "restore stage is unavailable")
		}
		ref, ok := job.Refs[q.ObjectID]
		body := job.Bodies[q.ObjectID]
		if !ok || q.Offset != int64(len(body)) || len(q.Data) == 0 || len(q.Data) > api.MaxChunkBytes || int64(len(q.Data)) > ref.Bytes-q.Offset {
			return nil, failure(api.CodeForbidden, "restore chunk escaped its inventory")
		}
		job.Bodies[q.ObjectID] = append(body, q.Data...)
		return true, nil
	}
	var q restoreSelect
	if err := decodeStrict(raw, &q); err != nil {
		return nil, err
	}
	job := m.restores[q.ID]
	if job == nil || q.Caller != job.Input.Caller {
		return nil, failure(api.CodeForbidden, "restore stage belongs to another caller")
	}
	if method == "restore_abort" {
		if job.Stage != "" {
			if err := os.RemoveAll(job.Stage); err != nil {
				return nil, err
			}
		}
		delete(m.restores, q.ID)
		return true, nil
	}
	r, root, err := m.restoreOwner(ctx, job.Input)
	if err != nil {
		return nil, err
	}
	if r.Lease.ID != job.Lease || root != job.Root {
		return nil, failure(api.CodeForbidden, "restore destination owner changed")
	}
	if method == "restore_stage" {
		if job.Stage != "" {
			if job.Ready {
				return job.Report, nil
			}
			return nil, failure(api.CodeIntegrity, "restore staging is incomplete")
		}
		for id, ref := range job.Refs {
			if int64(len(job.Bodies[id])) != ref.Bytes || digestBytes(job.Bodies[id]) != ref.SHA256 {
				return nil, failure(api.CodeIntegrity, "restore source bytes changed")
			}
		}
		enrollment := r.Storage.Workspace.Enrollment
		if enrollment.GitPath != "/usr/bin/git" {
			return nil, failure(api.CodeIntegrity, "restore Git executable differs from its native producer")
		}
		if err := verifyExecutable(enrollment.GitPath, enrollment.GitArtifact); err != nil {
			return nil, err
		}
		job.Stage, err = os.MkdirTemp(storageBase(m.binding, r), "restore-")
		if err != nil {
			return nil, err
		}
		job.Report, err = m.runRestore(ctx, r, job)
		if err != nil {
			cleanupErr := os.RemoveAll(job.Stage)
			if cleanupErr == nil {
				job.Stage = ""
			}
			return nil, errors.Join(err, cleanupErr)
		}
		file, err := archiveRoot(filepath.Join(job.Stage, "result"))
		if err != nil {
			return nil, err
		}
		err = verifyRestored(ctx, file, r.Lease.UID, r.Lease.GID, job)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		job.Bodies = nil
		job.Ready = true
		return job.Report, nil
	}
	if method != "restore_publish" || !job.Ready || job.Stage == "" || job.Report.Head == "" {
		return nil, failure(api.CodeForbidden, "restore has no complete staged tree")
	}
	parent, err := archivejob.RestoreDestination(job.Input.Request.Path, []string{root})
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	exists, err := archivejob.EmptyRestoreTarget(parent, filepath.Base(job.Input.Request.Path))
	if err != nil {
		return nil, err
	}
	dest, err := parent.Open(".")
	if err != nil {
		return nil, err
	}
	defer dest.Close()
	stage, err := archiveRoot(job.Stage)
	if err != nil {
		return nil, err
	}
	defer stage.Close()
	flags := uint(unix.RENAME_NOREPLACE)
	if exists {
		flags = 0
	}
	if err := unix.Renameat2(int(stage.Fd()), "result", int(dest.Fd()), filepath.Base(job.Input.Request.Path), flags); err != nil {
		return nil, failure(api.CodeConflict, "restore_target_exists")
	}
	if err := dest.Sync(); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(job.Stage); err != nil {
		return nil, err
	}
	delete(m.restores, q.ID)
	return true, nil
}
