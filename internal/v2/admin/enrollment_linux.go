//go:build linux

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func loadLaunchEnrollment(ctx context.Context, binding installation, runtimeRef, enrollmentRef api.BlobRef) (api.LaunchEnrollment, api.RuntimeManifest, error) {
	files, err := openEnrollmentFiles(binding)
	if err != nil {
		return api.LaunchEnrollment{}, api.RuntimeManifest{}, err
	}
	defer files.root.Close()
	return loadLaunchFiles(ctx, files, binding, runtimeRef, enrollmentRef)
}

func (s *Service) loadLaunchEnrollment(ctx context.Context) (api.LaunchEnrollment, api.RuntimeManifest, error) {
	if s.deps.LaunchEnrollment == nil {
		return api.LaunchEnrollment{}, api.RuntimeManifest{}, failure(api.CodePrerequisite, "launch enrollment is not installed")
	}
	if s.files != nil {
		return loadLaunchFiles(ctx, s.files, s.binding, s.deps.RuntimeManifest, *s.deps.LaunchEnrollment)
	}
	return loadLaunchEnrollment(ctx, s.binding, s.deps.RuntimeManifest, *s.deps.LaunchEnrollment)
}

func loadLaunchFiles(ctx context.Context, files *enrollmentFiles, binding installation, runtimeRef, enrollmentRef api.BlobRef) (api.LaunchEnrollment, api.RuntimeManifest, error) {
	manifest, err := loadRuntimeFiles(ctx, files, binding, runtimeRef)
	if err != nil {
		return api.LaunchEnrollment{}, manifest, err
	}
	data, _, err := files.read("launch-enrollment.json", enrollmentRef.Bytes)
	if err != nil {
		return api.LaunchEnrollment{}, manifest, err
	}
	if enrollmentRef.Class != "manifest" || !validID(enrollmentRef.ID) || int64(len(data)) != enrollmentRef.Bytes || digestBytes(data) != enrollmentRef.SHA256 {
		return api.LaunchEnrollment{}, manifest, failure(api.CodeIntegrity, "launch enrollment differs from installed reference")
	}
	var enrollment api.LaunchEnrollment
	if err := api.DecodeObject(data, &enrollment); err != nil {
		return enrollment, manifest, err
	}
	if err := api.ValidateLaunchEnrollment(enrollment, binding.Config, runtimeRef); err != nil {
		return enrollment, manifest, err
	}
	for _, runtime := range enrollment.Runtimes {
		if err := enrolledExecutable(manifest, runtime.Executable); err != nil {
			return enrollment, manifest, err
		}
	}
	if enrollment.Supervisor != nil {
		if err := enrolledExecutable(manifest, *enrollment.Supervisor); err != nil {
			return enrollment, manifest, err
		}
	}
	return enrollment, manifest, nil
}

func readEnrolledFile(path string, ref api.BlobRef) ([]byte, error) {
	if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Class != "manifest" || ref.Bytes < 1 || ref.Bytes > api.MaxObjectBytes {
		return nil, failure(api.CodeInvalid, "invalid protected enrollment reference")
	}
	data, err := readProtected(path, ref.Bytes)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != ref.Bytes || digestBytes(data) != ref.SHA256 {
		return nil, failure(api.CodeIntegrity, "protected enrollment bytes differ from installed reference")
	}
	return data, nil
}

// All roots and relative names come from the protected release bundle. None
// is interpreted as a caller path, a blob ID path or a logical workspace path.
func loadInstalledRuntime(ctx context.Context, binding installation, ref api.BlobRef) (api.RuntimeManifest, error) {
	files, err := openEnrollmentFiles(binding)
	if err != nil {
		return api.RuntimeManifest{}, err
	}
	defer files.root.Close()
	return loadRuntimeFiles(ctx, files, binding, ref)
}

func openEnrollmentFiles(binding installation) (*enrollmentFiles, error) {
	base := filepath.Join(filepath.Dir(binding.binaryPath()), "runtime", binding.Config)
	if err := protectedPath(base, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot pin installed runtime root")
	}
	return &enrollmentFiles{root: root, base: base}, nil
}

func loadRuntimeFiles(ctx context.Context, files *enrollmentFiles, binding installation, ref api.BlobRef) (api.RuntimeManifest, error) {
	manifest, err := loadRuntimeInventory(ctx, files, binding, ref)
	if err != nil {
		return manifest, err
	}
	for _, object := range manifest.Objects {
		if err := contextError(ctx); err != nil {
			return manifest, err
		}
		file, _, err := files.open(filepath.Join(string(object.RootID), object.RelativePath), runtimeLimit(object))
		if err != nil {
			return manifest, err
		}
		checkErr := hashRuntime(file, object)
		closeErr := file.Close()
		if checkErr != nil {
			return manifest, checkErr
		}
		if closeErr != nil {
			return manifest, failure(api.CodeIntegrity, "cannot close runtime input")
		}
	}
	return manifest, nil
}

// Read and validate the exact protected manifest and root inventory. A caller
// must still open and hash each selected file before reporting its presence.
func loadRuntimeInventory(ctx context.Context, files *enrollmentFiles, binding installation, ref api.BlobRef) (api.RuntimeManifest, error) {
	var manifest api.RuntimeManifest
	if err := contextError(ctx); err != nil {
		return manifest, err
	}
	data, _, err := files.read("manifest.json", ref.Bytes)
	if err != nil {
		return manifest, err
	}
	if !validID(ref.ID) || ref.Class != "manifest" || ref.Bytes < 1 || ref.Bytes > api.MaxObjectBytes || int64(len(data)) != ref.Bytes || digestBytes(data) != ref.SHA256 {
		return manifest, failure(api.CodeIntegrity, "runtime manifest differs from installed reference")
	}
	if err := api.DecodeObject(data, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Schema != "laneboss.runtime.v2" || manifest.Generation == 0 || manifest.Generation > 1<<53-1 ||
		manifest.Artifact.SHA256 != binding.Artifact.SHA256 || manifest.Artifact.Version != binding.Release.Version ||
		len(manifest.Objects) == 0 || len(manifest.Objects) > 128 {
		return manifest, failure(api.CodeIntegrity, "runtime manifest differs from the installed release")
	}
	rootData, _, err := files.read("roots.json", api.MaxFrameBytes)
	if err != nil {
		return manifest, err
	}
	var rootList struct {
		Roots []enrolledRoot `json:"roots"`
	}
	if err := api.DecodeObject(append(append([]byte(`{"roots":`), rootData...), '}'), &rootList); err != nil {
		return manifest, err
	}
	roots := map[api.ID]string{}
	for _, root := range rootList.Roots {
		if !validID(root.ID) || roots[root.ID] != "" || root.Path != filepath.Join(files.base, string(root.ID)) {
			return manifest, failure(api.CodeIntegrity, "runtime root is duplicated or outside protected enrollment")
		}
		roots[root.ID] = string(root.ID)
	}
	ids, destinations := map[api.ID]bool{}, map[string]bool{}
	var total int64
	for _, object := range manifest.Objects {
		if err := contextError(ctx); err != nil {
			return manifest, err
		}
		if !validID(object.ID) || ids[object.ID] || roots[object.RootID] == "" || object.Role == "" ||
			object.RelativePath == "" || object.RelativePath == "." || object.RelativePath == ".." ||
			filepath.IsAbs(object.RelativePath) || filepath.Clean(object.RelativePath) != object.RelativePath ||
			strings.HasPrefix(object.RelativePath, "../") || strings.ContainsRune(object.RelativePath, 0) ||
			object.Mode != 0444 && object.Mode != 0555 || !runtimeRef(object) || !api.RuntimeAliasesValid(object) {
			return manifest, failure(api.CodeIntegrity, "invalid enrolled runtime object")
		}
		path := filepath.Join(roots[object.RootID], object.RelativePath)
		if destinations[path] {
			return manifest, failure(api.CodeIntegrity, "runtime objects alias an enrolled destination")
		}
		destinations[path], ids[object.ID] = true, true
		if !vendorRuntime(object) {
			total += object.Content.Bytes
		}
		if total > 256<<20 {
			return manifest, failure(api.CodeIntegrity, "runtime inventory exceeds its bounded byte budget")
		}
	}
	for _, executable := range []api.Executable{manifest.Artifact, manifest.Bootstrap} {
		if err := enrolledExecutable(manifest, executable); err != nil {
			return manifest, err
		}
	}
	return manifest, nil
}

func (files *enrollmentFiles) read(name string, limit int64) ([]byte, unix.Stat_t, error) {
	if limit > api.MaxObjectBytes {
		return nil, unix.Stat_t{}, failure(api.CodeIntegrity, "installed object exceeds its byte bound")
	}
	file, info, err := files.open(name, limit)
	if err != nil {
		return nil, info, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	var after unix.Stat_t
	if err != nil || unix.Fstat(int(file.Fd()), &after) != nil || !sameRuntimeStat(info, after) || int64(len(data)) != info.Size {
		return nil, info, failure(api.CodeIntegrity, "enrolled runtime input changed while reading")
	}
	return data, info, nil
}

func hashRuntime(file *os.File, object api.RuntimeObject) error {
	var before, after unix.Stat_t
	if !runtimeRef(object) || unix.Fstat(int(file.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&07777 != object.Mode || before.Nlink != 1 || before.Size != object.Content.Bytes {
		return failure(api.CodeIntegrity, "runtime object bytes or mode differ")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, object.Content.Bytes+1))
	if err != nil || unix.Fstat(int(file.Fd()), &after) != nil || !sameRuntimeStat(before, after) || n != object.Content.Bytes ||
		api.Digest(hex.EncodeToString(hash.Sum(nil))) != object.Content.SHA256 {
		return failure(api.CodeIntegrity, "runtime object bytes or mode differ")
	}
	return nil
}

func sameRuntimeStat(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size && before.Mode == after.Mode &&
		before.Uid == after.Uid && before.Gid == after.Gid && before.Nlink == after.Nlink && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

func (files *enrollmentFiles) open(name string, limit int64) (*os.File, unix.Stat_t, error) {
	var info unix.Stat_t
	if files == nil || files.root == nil || limit < 1 || limit > api.MaxVendorBytes || filepath.IsAbs(name) || filepath.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsRune(name, 0) {
		return nil, info, failure(api.CodeIntegrity, "invalid root-relative installed input")
	}
	parts := strings.Split(name, string(filepath.Separator))
	parent := files.root
	opened := []*os.Root{}
	defer func() {
		for index := len(opened) - 1; index >= 0; index-- {
			opened[index].Close()
		}
	}()
	for index := 0; index < len(parts); index++ {
		directory, err := parent.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, info, failure(api.CodePrerequisite, "cannot pin installed input parent")
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(int(directory.Fd()), &stat)
		closeErr := directory.Close()
		if statErr != nil || closeErr != nil || stat.Uid != files.owner || stat.Mode&0022 != 0 {
			return nil, info, failure(api.CodeIntegrity, "installed input has an untrusted or writable ancestor")
		}
		if index == len(parts)-1 {
			break
		}
		entry, err := parent.Lstat(parts[index])
		if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			return nil, info, failure(api.CodeIntegrity, "installed input parent is linked or not a directory")
		}
		next, err := parent.OpenRoot(parts[index])
		if err != nil {
			return nil, info, failure(api.CodePrerequisite, "cannot open enrolled runtime directory")
		}
		opened = append(opened, next)
		parent = next
	}
	file, err := parent.OpenFile(parts[len(parts)-1], os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, info, failure(api.CodePrerequisite, "cannot open enrolled runtime input")
	}
	if unix.Fstat(int(file.Fd()), &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != files.owner ||
		info.Mode&07022 != 0 || info.Nlink != 1 || info.Size < 1 || info.Size > limit {
		file.Close()
		return nil, info, failure(api.CodeIntegrity, "enrolled runtime input has unsafe metadata")
	}
	_, capErr := unix.Fgetxattr(int(file.Fd()), "security.capability", nil)
	if capErr == nil || !errors.Is(capErr, unix.ENODATA) && !errors.Is(capErr, unix.ENOTSUP) {
		file.Close()
		return nil, info, failure(api.CodeIntegrity, "enrolled runtime input has file capabilities or unknown metadata")
	}
	return file, info, nil
}
