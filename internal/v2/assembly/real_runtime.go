package assembly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

type realRuntime struct {
	Wrapper, Claude         api.Executable
	WrapperPath, ClaudePath string
}

// This is independent of the stand-in descriptor. Only administrator-owned,
// manifest-pinned objects can select the real adapter. The helper projects
// these basename objects at /runtime/<id>; host verification uses host paths.
func loadRealRuntime(installed Installation) (*realRuntime, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, installError("real runtime release cannot resolve")
	}
	dir := filepath.Join(filepath.Dir(self), "runtime", installed.Config)
	raw, err := readProtected(filepath.Join(dir, "manifest.json"), api.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	if installed.RuntimeManifest.Class != "manifest" || installed.RuntimeManifest.Bytes != int64(len(raw)) || installed.RuntimeManifest.SHA256 != runDigest(raw) {
		return nil, installError("real runtime manifest pin differs")
	}
	var manifest api.RuntimeManifest
	if err := api.DecodeObject(raw, &manifest); err != nil {
		return nil, err
	}
	if manifest.Schema != "laneboss.runtime.v2" || manifest.Generation == 0 || manifest.Artifact.SHA256 != installed.ArtifactSHA256 {
		return nil, installError("real runtime release differs")
	}
	selected := map[string]api.RuntimeObject{}
	seen := map[api.ID]bool{}
	for _, object := range manifest.Objects {
		if !fixtureObjectID.MatchString(string(object.ID)) || seen[object.ID] {
			return nil, installError("real runtime object repeats or is invalid")
		}
		seen[object.ID] = true
		if object.Role != "claudock" && object.Role != "claude" {
			if object.Content.Bytes < 1 || object.Content.Bytes > api.MaxObjectBytes {
				return nil, installError("real runtime object exceeds the store object bound")
			}
			continue
		}
		if selected[object.Role].ID != "" || object.ID != api.ID(object.Role) || object.Mode != 0555 ||
			object.RelativePath != object.Role || object.Content.Class != "artifact" ||
			object.Content.Bytes < 1 || object.Content.Bytes > api.MaxVendorBytes || !isDigest(object.Content.SHA256) {
			return nil, installError("real runtime requires unique pinned basename executables")
		}
		selected[object.Role] = object
	}
	if len(selected) == 0 {
		return nil, nil
	}
	if len(selected) != 2 {
		return nil, installError("real runtime requires both vendor executables")
	}
	enrollment, err := realSessionEnrollment(installed, dir, manifest)
	if err != nil {
		return nil, err
	}
	raw, err = readProtected(filepath.Join(dir, "roots.json"), api.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	var roots []runtimeRoot
	if err := json.Unmarshal(raw, &roots); err != nil {
		return nil, installError("real runtime roots cannot decode")
	}
	paths := map[api.ID]string{}
	for _, root := range roots {
		if !fixtureObjectID.MatchString(string(root.ID)) || paths[root.ID] != "" || root.Path != filepath.Join(dir, string(root.ID)) {
			return nil, installError("real runtime root differs from the installed projection")
		}
		if err := protectedParents(root.Path, 0); err != nil {
			return nil, err
		}
		paths[root.ID] = root.Path
	}
	result := &realRuntime{}
	for role, object := range selected {
		root := paths[object.RootID]
		if root == "" {
			return nil, installError("real runtime object root is absent")
		}
		path := filepath.Join(root, object.RelativePath)
		if err := hashVendor(path, object.Content); err != nil {
			return nil, err
		}
		pin := api.Executable{ID: object.ID, SHA256: object.Content.SHA256}
		if role == "claudock" {
			pin.Version = enrollment.Executable.Version
			result.Wrapper, result.WrapperPath = pin, path
		} else {
			pin.Version = enrollment.SessionExecutable.Version
			result.Claude, result.ClaudePath = pin, path
		}
	}
	return result, nil
}

func realSessionEnrollment(installed Installation, dir string, manifest api.RuntimeManifest) (api.LaunchRuntime, error) {
	ref := installed.LaunchEnrollment
	if ref == nil || ref.Class != "manifest" || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return api.LaunchRuntime{}, installError("real runtime requires protected session executable enrollment")
	}
	raw, err := readProtected(filepath.Join(dir, "launch-enrollment.json"), api.MaxFrameBytes)
	if err != nil {
		return api.LaunchRuntime{}, err
	}
	if ref.Bytes != int64(len(raw)) || ref.SHA256 != runDigest(raw) {
		return api.LaunchRuntime{}, installError("real runtime session enrollment pin differs")
	}
	var enrollment api.LaunchEnrollment
	if api.DecodeObject(raw, &enrollment) != nil || api.ValidateLaunchEnrollment(enrollment, installed.Config, installed.RuntimeManifest) != nil {
		return api.LaunchRuntime{}, installError("real runtime session enrollment is invalid")
	}
	for _, selected := range enrollment.Runtimes {
		if selected.Driver == api.DriverClaudock {
			if _, err := api.RuntimeSessionExecutable(selected, manifest); err != nil {
				return api.LaunchRuntime{}, err
			}
			return selected, nil
		}
	}
	return api.LaunchRuntime{}, installError("real runtime has no Claudock session enrollment")
}

// Vendor bytes stay in the protected installation, outside the object store.
// Bound the stream and check the opened inode and name before trusting its pin.
func hashVendor(path string, ref api.BlobRef) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || ref.Bytes < 1 || ref.Bytes > api.MaxVendorBytes {
		return installError("real runtime executable path or size differs")
	}
	if err := protectedParents(filepath.Dir(path), 0); err != nil {
		return err
	}
	valid := func(info os.FileInfo) bool {
		if info == nil || !info.Mode().IsRegular() || info.Size() != ref.Bytes || info.Mode().Perm() != 0555 ||
			info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !owned(info, 0) {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Nlink == 1
	}
	before, err := os.Lstat(path)
	if err != nil || !valid(before) {
		return installError("real runtime executable byte or mode pin differs")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return installError("real runtime executable cannot open")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !valid(opened) || !os.SameFile(before, opened) || before.ModTime() != opened.ModTime() {
		return installError("real runtime executable changed during open")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, ref.Bytes+1))
	after, statErr := file.Stat()
	named, pathErr := os.Lstat(path)
	if err != nil || statErr != nil || pathErr != nil || n != ref.Bytes || !valid(after) || !valid(named) ||
		!os.SameFile(before, after) || !os.SameFile(before, named) || before.ModTime() != after.ModTime() || before.ModTime() != named.ModTime() ||
		api.Digest(hex.EncodeToString(hash.Sum(nil))) != ref.SHA256 {
		return installError("real runtime executable byte or mode pin differs")
	}
	return nil
}

// Run reads lifecycle's immutable input-runner stage, not the request argument
// or lane files. Each use reloads the actual effect claim and reservation.
func (r *enrolledRunner) realRun(ctx context.Context, target api.LifeRef) (claudock.LaunchSelector, api.RunnerRequest, api.LaunchStorage, error) {
	var selector claudock.LaunchSelector
	var request api.RunnerRequest
	var storage api.LaunchStorage
	lease, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !api.EffectLeaseClaimed(lease) || lease.Record.Effect.PlanLaunch == nil {
		return selector, request, storage, runError(api.CodeForbidden, "real runner requires its current planning claim")
	}
	claim := api.PlanningClaim(lease.Record.Effect.PlanLaunch.ReservationID, lease)
	scope := api.Scope{Config: r.config, Source: "worker", Actor: api.Actor{Kind: "service", ID: claim.ClaimantID}}
	current, err := r.deps.Store.Effect(ctx, scope, claim.EffectID)
	if err != nil {
		return selector, request, storage, err
	}
	if err := api.CheckPlanningClaim(current, claim, r.config, r.deps.Clock.Now()); err != nil {
		return selector, request, storage, err
	}
	record, err := r.deps.Store.LaunchPlan(ctx, scope, claim.ReservationID)
	if err != nil {
		return selector, request, storage, err
	}
	if api.ValidateLaunchPlanRecord(record) != nil || record.Inputs == nil || record.Reservation.Target != target || record.Reservation.Driver != api.DriverClaudock {
		return selector, request, storage, runError(api.CodeIntegrity, "real runner reservation differs")
	}
	scope.PolicyGeneration = record.Reservation.PolicyGeneration
	id := api.ID(runDigest([]byte("launch\x00" + string(claim.ReservationID) + "\x00input-runner")))
	meta, err := r.deps.Store.ObjectMetadata(ctx, scope, id)
	if err != nil {
		return selector, request, storage, err
	}
	if meta.Ref.ID != id || meta.Ref.Class != "manifest" || meta.Origin != "service" || meta.ACL.Config != r.config ||
		meta.ACL.LifeID != target.LifeID || meta.ACL.Owner.Kind != "service" || meta.ACL.Generation == 0 ||
		len(meta.ACL.Participants) != 0 || meta.ACL.Audience != "service" && meta.ACL.Audience != "owner" ||
		meta.SourceOperationID != record.Reservation.OperationID {
		return selector, request, storage, runError(api.CodeIntegrity, "real runner input lacks protected provenance")
	}
	raw, err := r.runBytes(ctx, scope, meta.Ref, record.Reservation.OperationID, target.LifeID)
	if err != nil {
		return selector, request, storage, err
	}
	if api.DecodeObject(raw, &request) != nil || request.Target != target || request.Executable != record.Inputs.Sources.Runtime.Executable {
		return selector, request, storage, runError(api.CodeIntegrity, "real runner input differs from its reservation")
	}
	broker, ok := r.deps.Credentials.(interface {
		VerifyRunnerSlot(context.Context, api.LaunchClaim, api.RunnerRequest) (api.LaunchStorage, error)
	})
	if !ok {
		return selector, request, storage, api.NotImplemented("lb-v2-secrets", "VerifyRunnerSlot")
	}
	storage, err = broker.VerifyRunnerSlot(ctx, claim, request)
	if err != nil {
		return selector, request, storage, err
	}
	selector = claudock.LaunchSelector{Scope: scope, ReservationID: claim.ReservationID, EffectID: claim.EffectID,
		ClaimID: claim.ClaimID, HelperLeaseID: storage.LeaseID}
	return selector, request, storage, nil
}
