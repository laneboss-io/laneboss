//go:build linux

package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func orgOpen(root *os.File, name string, flags int) (*os.File, error) {
	fd, err := fdpath.Open(int(root.Fd()), name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "org-publication"), nil
}

func orgDirectory(root *os.File, name string, create bool) (*os.File, error) {
	if create {
		if err := unix.Mkdirat(int(root.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	}
	file, err := orgOpen(root, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !private(info, true) {
		file.Close()
		return nil, fault(api.CodeIntegrity, "org publication directory owner or mode changed")
	}
	if create && root.Sync() != nil {
		file.Close()
		return nil, fault(api.CodeIntegrity, "org directory creation is not durable")
	}
	return file, nil
}

func (s *Service) orgRoot(create bool) (*os.File, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	parent, err := s.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return orgDirectory(parent, "org", create)
}

func orgParents(root *os.File, name string, create bool) (*os.File, string, error) {
	if manifest.Relative(name) != nil || name == "." {
		return nil, "", fault(api.CodeIntegrity, "invalid canonical org path")
	}
	current, err := orgOpen(root, ".", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(name, "/")
	for _, part := range parts[:len(parts)-1] {
		next, openErr := orgDirectory(current, part, create)
		closeErr := current.Close()
		if openErr != nil || closeErr != nil {
			if next != nil {
				next.Close()
			}
			return nil, "", errors.Join(openErr, closeErr)
		}
		current = next
	}
	return current, parts[len(parts)-1], nil
}

func orgRead(root *os.File, name string, limit int64, mode uint32) ([]byte, error) {
	file, err := orgOpen(root, name, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var facts unix.Stat_t
	if unix.Fstat(int(file.Fd()), &facts) != nil || facts.Mode&unix.S_IFMT != unix.S_IFREG || facts.Mode&07777 != mode || facts.Uid != uint32(os.Geteuid()) || facts.Nlink != 1 || facts.Size < 0 || facts.Size > limit {
		return nil, fault(api.CodeIntegrity, "canonical org file changed its type, owner, mode, links or bound")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != facts.Size {
		return nil, fault(api.CodeIntegrity, "canonical org file could not be read completely")
	}
	return raw, nil
}

func orgWrite(root *os.File, name string, raw []byte, mode uint32) error {
	parent, base, err := orgParents(root, name, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, unix.EEXIST) {
		actual, readErr := orgRead(parent, base, int64(len(raw)), mode)
		if readErr != nil || string(actual) != string(raw) {
			return fault(api.CodeIntegrity, "unfinished publication differs from its exact approved bytes")
		}
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "canonical-org-output")
	n, writeErr := file.Write(raw)
	if writeErr == nil && n != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Chmod(os.FileMode(mode))
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	return errors.Join(writeErr, file.Close(), parent.Sync())
}

func orgLink(root *os.File, name string) (string, error) {
	buffer := make([]byte, 1025)
	n, err := unix.Readlinkat(int(root.Fd()), name, buffer)
	if err != nil {
		return "", err
	}
	if n == len(buffer) {
		return "", fault(api.CodeIntegrity, "canonical pointer exceeds its fixed bound")
	}
	return string(buffer[:n]), nil
}

func orgInventory(root *os.File, files []api.ResourceFile) error {
	expected := map[string]bool{}
	for _, file := range files {
		name := file.Source.Path
		if expected[name] {
			return fault(api.CodeIntegrity, "canonical inventory contains duplicate paths")
		}
		expected[name] = true
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			expected[parent] = true
		}
		raw, err := orgRead(root, name, file.Content.Bytes, file.Mode)
		if err != nil || int64(len(raw)) != file.Content.Bytes || api.Digest(hash(raw)) != file.Content.SHA256 {
			return fault(api.CodeIntegrity, "canonical readback differs from approved bytes or modes")
		}
	}
	var walk func(*os.File, string) error
	walk = func(directory *os.File, prefix string) error {
		// Reopen for an independent directory offset on every readback.
		reader, err := orgOpen(directory, ".", unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		entries, readErr := reader.ReadDir(-1)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		for _, entry := range entries {
			name := path.Join(prefix, entry.Name())
			if !expected[name] || entry.Type()&os.ModeSymlink != 0 {
				return fault(api.CodeIntegrity, "canonical generation contains an unreviewed path or symlink")
			}
			if entry.IsDir() {
				child, err := orgDirectory(directory, entry.Name(), false)
				if err != nil {
					return err
				}
				err = errors.Join(walk(child, name), child.Close())
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(root, "")
}

func orgFiles(snapshot api.OrgSnapshot) []api.ResourceFile {
	result := append([]api.ResourceFile{}, snapshot.Sources...)
	return append(result, snapshot.Derived...)
}

func readOrgMarker(root *os.File, generation string) (orgPublicationMarker, error) {
	var marker orgPublicationMarker
	raw, err := orgRead(root, generation+"/marker.json", api.MaxFrameBytes, 0600)
	if err != nil {
		return marker, err
	}
	if err := api.DecodeObject(raw, &marker); err != nil {
		return marker, err
	}
	if marker.Schema != "laneboss.org-publication.v2" {
		return marker, fault(api.CodeIntegrity, "canonical publication marker has an unknown schema")
	}
	return marker, nil
}

func (s *Service) publicationReadback(job orgApply) (orgPublicationMarker, error) {
	var zero orgPublicationMarker
	root, err := s.orgRoot(false)
	if err != nil {
		return zero, fault(api.CodePrerequisite, "canonical publication marker has not been installed")
	}
	defer root.Close()
	return readOrgPublication(root, job)
}

func readOrgPublication(root *os.File, job orgApply) (orgPublicationMarker, error) {
	var zero orgPublicationMarker
	generation := "generations/gen-" + string(job.Deferred.OperationID)
	current, err := orgLink(root, "current")
	if err != nil || current != generation+"/tree" {
		return zero, fault(api.CodeIntegrity, "canonical pointer does not name the original publication")
	}
	marker, err := readOrgMarker(root, generation)
	if err != nil {
		return zero, err
	}
	want, err := publicationMarker(job, marker.Receipt)
	if err != nil || !sameValue(marker, want) || marker.Receipt.ID != api.ID("application-"+hash([]byte(job.Deferred.OperationID))[:32]) || marker.Receipt.ChangeID != job.Change.ID || marker.Receipt.ApprovalID != job.Approval.ID || marker.Receipt.ManifestSHA256 != job.Change.ManifestSHA256 || marker.Receipt.OldGeneration != job.Change.BaseGeneration || marker.Receipt.NewGeneration != job.Change.BaseGeneration+1 || marker.Receipt.SimulatedPresence != job.SimulatedPresence {
		return zero, fault(api.CodeIntegrity, "canonical marker differs from the exact approved operation")
	}
	if _, err := time.Parse(time.RFC3339Nano, string(marker.Receipt.AppliedAt)); err != nil {
		return zero, fault(api.CodeIntegrity, "canonical publication has an invalid measured time")
	}
	tree, err := orgOpen(root, generation+"/tree", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return zero, err
	}
	if err := errors.Join(orgInventory(tree, orgFiles(marker.Snapshot)), tree.Close()); err != nil {
		return zero, err
	}
	return marker, nil
}

// Verify already holds mu; borrow its root directly instead of taking a second
// read lock behind a waiting writer. Publication itself performs I/O outside mu.
func (s *Service) verifyCurrentOrgPublication(job orgApply, receipt api.ChangeReceipt) error {
	parent, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer parent.Close()
	root, err := orgDirectory(parent, "org", false)
	if err != nil {
		return err
	}
	defer root.Close()
	marker, err := readOrgPublication(root, job)
	if err != nil {
		return err
	}
	if marker.Receipt != receipt {
		return fault(api.CodeIntegrity, "current canonical marker differs from its completed receipt")
	}
	return nil
}

func (s *Service) PublishChange(ctx context.Context, scope api.Scope, request api.PublishChangeRequest) (api.ChangeReceipt, error) {
	s.orgMu.Lock()
	defer s.orgMu.Unlock()
	var zero api.ChangeReceipt
	job, err := s.currentOrgApply(ctx, scope, request)
	if err != nil {
		return zero, err
	}
	root, err := s.orgRoot(true)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	generation := "generations/gen-" + string(job.Deferred.OperationID)
	current, linkErr := orgLink(root, "current")
	if linkErr != nil && !errors.Is(linkErr, unix.ENOENT) {
		return zero, fault(api.CodeIntegrity, "canonical org pointer is not a protected symlink")
	}
	if current == generation+"/tree" {
		marker, err := s.publicationReadback(job)
		return marker.Receipt, err
	}
	if current == "" && job.Change.BaseGeneration != 1 {
		return zero, fault(api.CodePrerequisite, "approved canonical base generation is missing")
	}
	if current != "" {
		if !strings.HasPrefix(current, "generations/gen-") || !strings.HasSuffix(current, "/tree") || path.Clean(current) != current {
			return zero, fault(api.CodeIntegrity, "canonical org pointer has an invalid target")
		}
		old, err := readOrgMarker(root, strings.TrimSuffix(current, "/tree"))
		if err != nil || !sameValue(old.Snapshot, job.Snapshot) {
			return zero, fault(api.CodeConflict, "canonical filesystem base differs from the approved source snapshot")
		}
	}
	parents, err := orgDirectory(root, "generations", true)
	if err != nil {
		return zero, err
	}
	leaf, err := orgDirectory(parents, "gen-"+string(job.Deferred.OperationID), true)
	closeErr := parents.Close()
	if err != nil || closeErr != nil {
		if leaf != nil {
			leaf.Close()
		}
		return zero, errors.Join(err, closeErr)
	}
	defer leaf.Close()
	tree, err := orgDirectory(leaf, "tree", true)
	if err != nil {
		return zero, err
	}
	defer tree.Close()
	receipt := api.ChangeReceipt{ID: api.ID("application-" + hash([]byte(job.Deferred.OperationID))[:32]), ChangeID: job.Change.ID, ApprovalID: job.Approval.ID, OldGeneration: job.Change.BaseGeneration, NewGeneration: job.Change.BaseGeneration + 1, ManifestSHA256: job.Change.ManifestSHA256, AppliedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), SimulatedPresence: job.SimulatedPresence}
	if retained, err := readOrgMarker(root, generation); err == nil {
		receipt = retained.Receipt
	} else if !errors.Is(err, unix.ENOENT) {
		return zero, err
	}
	marker, err := publicationMarker(job, receipt)
	if err != nil {
		return zero, err
	}
	var total int64
	for _, file := range orgFiles(marker.Snapshot) {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if _, err := s.currentOrgApply(ctx, scope, request); err != nil {
			return zero, err
		}
		s.mu.RLock()
		metadata, raw, readErr := objectRow(ctx, s.db, file.Content.ID)
		s.mu.RUnlock()
		if readErr != nil {
			return zero, readErr
		}
		if metadata.Ref != file.Content {
			return zero, fault(api.CodeIntegrity, "publication source differs from its retained bytes")
		}
		total += int64(len(raw))
		if total > 64<<20 {
			return zero, fault(api.CodeBudget, "org generation exceeds the bounded publisher byte budget")
		}
		if err := orgWrite(tree, file.Source.Path, raw, file.Mode); err != nil {
			return zero, err
		}
	}
	if err := orgInventory(tree, orgFiles(marker.Snapshot)); err != nil {
		return zero, err
	}
	raw, err := json.Marshal(marker)
	if err == nil {
		raw, err = api.CanonicalJSON(raw)
	}
	if err != nil {
		return zero, err
	}
	if err := orgWrite(leaf, "marker.json", raw, 0600); err != nil {
		return zero, err
	}
	if err := errors.Join(tree.Sync(), leaf.Sync(), root.Sync()); err != nil {
		return zero, err
	}
	if _, err := s.currentOrgApply(ctx, scope, request); err != nil {
		return zero, err
	}
	next := "next-" + string(job.Deferred.OperationID)
	if err := unix.Symlinkat(generation+"/tree", int(root.Fd()), next); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return zero, err
		}
		if actual, err := orgLink(root, next); err != nil || actual != generation+"/tree" {
			return zero, fault(api.CodeIntegrity, "publication recovery found a conflicting pointer")
		}
	}
	if err := unix.Renameat(int(root.Fd()), next, int(root.Fd()), "current"); err != nil {
		return zero, err
	}
	if err := root.Sync(); err != nil {
		return zero, err
	}
	measured, err := s.publicationReadback(job)
	return measured.Receipt, err
}

func (s *Service) ReconcileChange(ctx context.Context, scope api.Scope, request api.PublishChangeRequest) (api.ChangeReceipt, error) {
	return s.PublishChange(ctx, scope, request)
}

// Hold orgMu while measuring this and sealing a failure. A lost connection or
// deadline alone cannot establish that the canonical pointer stayed at base.
func (s *Service) publicationUnchanged(job orgApply) error {
	root, err := s.orgRoot(false)
	if errors.Is(err, unix.ENOENT) && job.Change.BaseGeneration == 1 {
		return nil
	}
	if err != nil {
		return fault(api.CodeContainmentUnknown, "unpublished canonical base cannot be measured")
	}
	defer root.Close()
	current, err := orgLink(root, "current")
	if errors.Is(err, unix.ENOENT) && job.Change.BaseGeneration == 1 {
		return nil
	}
	if err != nil {
		return fault(api.CodeContainmentUnknown, "canonical pointer outcome is unknown")
	}
	if current == "generations/gen-"+string(job.Deferred.OperationID)+"/tree" {
		return fault(api.CodeUnavailable, "canonical publication may already have succeeded; reconcile its original marker")
	}
	if !strings.HasPrefix(current, "generations/gen-") || !strings.HasSuffix(current, "/tree") || path.Clean(current) != current {
		return fault(api.CodeIntegrity, "canonical base pointer has an invalid target")
	}
	marker, err := readOrgMarker(root, strings.TrimSuffix(current, "/tree"))
	if err != nil || !sameValue(marker.Snapshot, job.Snapshot) {
		return fault(api.CodeContainmentUnknown, "canonical pointer no longer proves the unchanged approved base")
	}
	tree, err := orgOpen(root, current, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	return errors.Join(orgInventory(tree, orgFiles(job.Snapshot)), tree.Close())
}
