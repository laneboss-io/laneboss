//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// ReadCleanupRuntimeManifest returns the exact CURRENT protected namespace.
// It does not establish historical provenance or claim that vendor bytes from
// an older pin still exist; the store must independently prove that history.
func (s *Service) ReadCleanupRuntimeManifest(ctx context.Context) (ref api.BlobRef, runtime api.RuntimeManifest, resultErr error) {
	files := s.files
	if files == nil {
		var err error
		files, err = openEnrollmentFiles(s.binding)
		if err != nil {
			return ref, runtime, err
		}
		defer func() {
			if err := files.root.Close(); err != nil {
				ref, runtime, resultErr = api.BlobRef{}, api.RuntimeManifest{}, failure(api.CodeIntegrity, "cannot close cleanup runtime root")
			}
		}()
	}
	runtime, resultErr = loadRuntimeInventory(ctx, files, s.binding, s.deps.RuntimeManifest)
	if resultErr != nil {
		return api.BlobRef{}, api.RuntimeManifest{}, resultErr
	}
	return s.deps.RuntimeManifest, runtime, nil
}

// ReadCleanupRuntime resolves an exact artifact pin in the installed runtime.
// Vendor bytes remain protected files: they acquire neither SQL blob allowance
// nor lane deletion authority. Each call reopens and hashes the actual file.
func (s *Service) ReadCleanupRuntime(ctx context.Context, ref api.BlobRef) (result api.CleanupObject, resultErr error) {
	files := s.files
	if files == nil {
		var err error
		files, err = openEnrollmentFiles(s.binding)
		if err != nil {
			return api.CleanupObject{}, err
		}
		defer func() {
			if err := files.root.Close(); err != nil {
				result, resultErr = api.CleanupObject{}, failure(api.CodeIntegrity, "cannot close cleanup runtime root")
			}
		}()
	}
	manifest, err := loadRuntimeInventory(ctx, files, s.binding, s.deps.RuntimeManifest)
	if err != nil {
		return api.CleanupObject{}, err
	}
	var selected *api.RuntimeObject
	for _, object := range manifest.Objects {
		if object.Content.ID != ref.ID || !vendorRuntime(object) {
			continue
		}
		if selected != nil || object.Content != ref {
			return api.CleanupObject{}, failure(api.CodeIntegrity, "cleanup runtime reference differs from its unique installed pin")
		}
		copy := object
		selected = &copy
	}
	if selected == nil {
		return api.CleanupObject{}, failure(api.CodeNotFound, "cleanup reference is outside the installed vendor inventory")
	}
	object := *selected
	path := filepath.Join(string(object.RootID), object.RelativePath)
	file, before, err := files.open(path, runtimeLimit(object))
	if err != nil {
		return api.CleanupObject{}, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			result, resultErr = api.CleanupObject{}, failure(api.CodeIntegrity, "cannot close cleanup runtime file")
		}
	}()
	if err := hashRuntime(file, object); err != nil {
		return api.CleanupObject{}, err
	}
	opened, err := file.Stat()
	if err != nil {
		return api.CleanupObject{}, failure(api.CodeIntegrity, "cleanup runtime file cannot be measured")
	}
	named, err := files.root.Lstat(path)
	var after unix.Stat_t
	if err != nil || !os.SameFile(opened, named) || unix.Fstat(int(file.Fd()), &after) != nil || !sameRuntimeStat(before, after) {
		return api.CleanupObject{}, failure(api.CodeIntegrity, "cleanup runtime file changed during measurement")
	}
	root, err := files.root.OpenFile(string(object.RootID), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return api.CleanupObject{}, failure(api.CodeIntegrity, "cleanup runtime root cannot be measured")
	}
	var parent unix.Stat_t
	statErr, closeErr := unix.Fstat(int(root.Fd()), &parent), root.Close()
	if statErr != nil || closeErr != nil || parent.Uid != files.owner || parent.Mode&0022 != 0 {
		return api.CleanupObject{}, failure(api.CodeIntegrity, "cleanup runtime root has unsafe metadata")
	}
	identity, err := json.Marshal(struct {
		Manifest api.BlobRef
		Ref      api.BlobRef
		Device   uint64
		Inode    uint64
		Mode     uint32
		UID, GID uint32
		Links    uint64
	}{s.deps.RuntimeManifest, ref, uint64(after.Dev), after.Ino, after.Mode, after.Uid, after.Gid, uint64(after.Nlink)})
	if err != nil {
		return api.CleanupObject{}, err
	}
	rootIdentity, err := json.Marshal(struct {
		Config   string
		Manifest api.BlobRef
		Root     api.ID
		Device   uint64
		Inode    uint64
	}{s.deps.Config, s.deps.RuntimeManifest, object.RootID, uint64(parent.Dev), parent.Ino})
	if err != nil {
		return api.CleanupObject{}, err
	}
	if err := contextError(ctx); err != nil {
		return api.CleanupObject{}, err
	}
	return api.CleanupObject{Ref: ref, RootID: api.ID("runtime-" + s.deps.Config), RootIdentity: string(digestBytes(rootIdentity)),
		Identity: string(digestBytes(identity)), Role: "runtime"}, nil
}
