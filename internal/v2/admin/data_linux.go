//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func dataParent(path string) (*os.File, error) {
	return dataParentMode(path, 0, 0700)
}

func dataParentMode(path string, gid, mode uint32) (*os.File, error) {
	fd, err := fdpath.Open(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "protected data parent is unavailable")
	}
	file := os.NewFile(uintptr(fd), "protected-data-parent")
	_, info, err := dataIdentity(file)
	if err != nil || info.Uid != 0 || info.Gid != gid || info.Mode&07777 != mode {
		file.Close()
		return nil, failure(api.CodeIntegrity, "data parent is not private helper storage")
	}
	if err := dataNoAttributes(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func dataDirectory(parent *os.File, name string) (*os.File, error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	file, err := openStorageDirectory(parent, name)
	if err != nil {
		return nil, err
	}
	_, info, err := dataIdentity(file)
	if err != nil || info.Uid != 0 || info.Gid != 0 || info.Mode&07777 != 0700 {
		file.Close()
		return nil, failure(api.CodeIntegrity, "data directory is not helper-owned")
	}
	if err := dataNoAttributes(file); err != nil {
		file.Close()
		return nil, err
	}
	if err := parent.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func dataOpenStageAbsent(ctx context.Context, binding installation, job dataJob) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	_, err := os.Lstat(laneStagePath(binding, job.Reg.Request.StageID))
	if !errors.Is(err, os.ErrNotExist) {
		return api.WithHelperReason(failure(api.CodeContainmentUnknown, "data reservation already has a staging attempt; preserve its original ownership"), "data_retry")
	}
	return nil
}

func (m *leaseManager) pinData(ctx context.Context, parent leaseRecord, job dataJob, supplied ...[]dataCopyPayload) (_ *dataPins, _ api.StorageProjection, _ []byte, resultErr error) {
	source := job.Reg.Inputs.Sources.Project
	if source.HistoryScope != "tree" || source.Base != string(source.Object.SHA256) {
		return nil, api.StorageProjection{}, nil, failure(api.CodeUnsupported, "data job requires an enrolled immutable tree; protected Git export is not installed")
	}
	state, err := dataParent(m.binding.statePath())
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	defer state.Close()
	sources, err := openStorageDirectory(state, "sources")
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	defer sources.Close()
	cache, err := openStorageDirectory(sources, string(source.Object.SHA256))
	if err != nil {
		return nil, api.StorageProjection{}, nil, failure(api.CodePrerequisite, "approved data source is absent from the protected source cache")
	}
	defer cache.Close()
	for _, file := range []*os.File{sources, cache} {
		_, info, e := dataIdentity(file)
		if e != nil || info.Uid != 0 || info.Gid != 0 || info.Mode&07777 != 0700 {
			return nil, api.StorageProjection{}, nil, failure(api.CodeIntegrity, "source cache is not exclusively helper-owned")
		}
		if e := dataNoAttributes(file); e != nil {
			return nil, api.StorageProjection{}, nil, e
		}
	}
	manifestFile, err := dataFile(cache, "manifest.json", false)
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	var facts unix.Stat_t
	if unix.Fstat(int(manifestFile.Fd()), &facts) != nil || facts.Mode&unix.S_IFMT != unix.S_IFREG || facts.Mode&07022 != 0 || facts.Uid != 0 || facts.Gid != 0 || facts.Nlink != 1 || facts.Size != source.Object.Bytes || facts.Size > api.MaxFrameBytes {
		manifestFile.Close()
		return nil, api.StorageProjection{}, nil, failure(api.CodeIntegrity, "source manifest metadata differs from enrollment")
	}
	raw, readErr := io.ReadAll(io.LimitReader(manifestFile, api.MaxFrameBytes+1))
	closeErr := manifestFile.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != source.Object.Bytes || digestBytes(raw) != source.Object.SHA256 {
		return nil, api.StorageProjection{}, nil, failure(api.CodeIntegrity, "source manifest bytes differ from enrollment")
	}
	manifest, err := dataManifest(raw, job.Reg.Plan.Budget.DiskBytes)
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	original, err := openStorageDirectory(cache, "tree")
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	defer original.Close()
	if err := dataVerify(ctx, original, manifest, 0, 0); err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	// An existing stage directory cannot be adopted after an interrupted open.
	stagePath := laneStagePath(m.binding, job.Reg.Request.StageID)
	if err := createLaneStage(stagePath, job.Lease.GID); err != nil {
		return nil, api.StorageProjection{}, nil, failure(api.CodeContainmentUnknown, "data staging directory exists or cannot be reserved")
	}
	pins := &dataPins{manifest: append([]byte(nil), raw...)}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackDataCopies(pins), pins.close())
		}
	}()
	pins.parents[0], err = dataLaneParent(stagePath, job.Lease.GID)
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	if err := unix.Mkdirat(int(pins.parents[0].Fd()), "source", 0700); err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	pins.names[0] = "source"
	pins.roots[0], err = openStorageDirectory(pins.parents[0], "source")
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	if err := dataStage(ctx, original, pins.roots[0], manifest, job.Lease.UID, job.Lease.GID); err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	pins.parents[1], err = dataLaneParent(laneStagePath(m.binding, parent.Lease.ID), parent.Lease.GID)
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	for i := 1; i < 3; i++ {
		item := parent.Storage.Directories[i-1]
		pins.names[i] = string(item.ID)
		pins.roots[i], err = openStorageDirectory(pins.parents[1], pins.names[i])
		if err != nil {
			return nil, api.StorageProjection{}, nil, err
		}
		identity, info, e := dataIdentity(pins.roots[i])
		if e != nil || identity != item.Device+":"+item.Inode || info.Uid != parent.Lease.UID || info.Gid != parent.Lease.GID || info.Mode&07777 != 0700 {
			return nil, api.StorageProjection{}, nil, failure(api.CodeIntegrity, "data destination changed its allocated owner or inode")
		}
		if err := dataNoAttributes(pins.roots[i]); err != nil {
			return nil, api.StorageProjection{}, nil, err
		}
		if err := dataEmpty(pins.roots[i]); err != nil {
			return nil, api.StorageProjection{}, nil, err
		}
	}
	// Both destination emptiness checks precede ownership changes. The durable
	// reservation retains any partial failure; it never returns a live token.
	for _, file := range pins.roots[1:] {
		if err := unix.Fchown(int(file.Fd()), int(job.Lease.UID), int(job.Lease.GID)); err != nil {
			return nil, api.StorageProjection{}, nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, api.StorageProjection{}, nil, err
		}
	}
	if err := setDataParentGroup(pins.parents[1], parent.Lease.GID, job.Lease.GID); err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	token, err := randomID("open-")
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	evidenceID, err := randomID("roots-")
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	storage := parent.Storage.Binding
	storage.ReservationID = job.Reg.Reservation.ID
	storage.Target = job.Reg.Reservation.Target
	projection := api.StorageProjection{StageID: job.Reg.Request.StageID, Storage: storage, WorkerLeaseID: job.Reg.Worker.ID, OpenToken: token, Generation: m.binding.Generation}
	var payloads []dataCopyPayload
	if len(supplied) == 1 {
		payloads = supplied[0]
	}
	copies, err := pinDataCopies(ctx, m.binding, job, pins, payloads)
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	projection.Copies, err = api.EncodeDataCopyProjections(copies)
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	identities := []*string{&projection.SourceIdentity, &projection.WorkspaceIdentity, &projection.HomeIdentity}
	for i, destination := range identities {
		identity, _, e := dataIdentity(pins.roots[i])
		if e != nil {
			return nil, api.StorageProjection{}, nil, e
		}
		*destination = identity
	}
	evidence, err := json.Marshal(struct {
		Schema     string                `json:"schema"`
		Projection api.StorageProjection `json:"projection"`
		Lease      api.HelperLease       `json:"worker_lease"`
		Source     api.BlobRef           `json:"source"`
		Boot       string                `json:"boot"`
		Opened     api.Timestamp         `json:"opened"`
	}{"laneboss.data-roots.v2", projection, job.Lease, source.Object, m.bootID, gateTimestamp()})
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	evidence, err = api.CanonicalJSON(evidence)
	if err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	projection.Evidence = api.BlobRef{ID: evidenceID, SHA256: digestBytes(evidence), Bytes: int64(len(evidence)), Class: "manifest"}
	if err := pins.parents[0].Sync(); err != nil {
		return nil, api.StorageProjection{}, nil, err
	}
	return pins, projection, evidence, nil
}

func checkDataPins(ctx context.Context, parent leaseRecord, job dataJob, pins *dataPins) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	for index, directory := range pins.parents {
		gid := job.Lease.GID
		if index == 1 && job.State == "measured" {
			gid = parent.Lease.GID
		}
		_, info, err := dataIdentity(directory)
		if err != nil || info.Uid != 0 || info.Gid != gid || info.Mode&07777 != 0710 {
			return failure(api.CodeContainmentUnknown, "data staging parent changed its exclusive traversal group")
		}
		if err := dataNoAttributes(directory); err != nil {
			return err
		}
	}
	identities := []string{job.Projection.SourceIdentity, job.Projection.WorkspaceIdentity, job.Projection.HomeIdentity}
	seen := map[string]bool{}
	for i, file := range pins.roots {
		identity, info, err := dataIdentity(file)
		if err != nil {
			return err
		}
		uid, gid := job.Lease.UID, job.Lease.GID
		if i > 0 && job.State == "measured" {
			uid, gid = parent.Lease.UID, parent.Lease.GID
		}
		if identity != identities[i] || seen[identity] || info.Uid != uid || info.Gid != gid || info.Mode&07777 != 0700 {
			return failure(api.CodeContainmentUnknown, "held data root identity, owner or mode changed")
		}
		seen[identity] = true
		parentIndex := 1
		if i == 0 {
			parentIndex = 0
		}
		if err := checkOpenedStorageDirectory(file, pins.parents[parentIndex], pins.names[i]); err != nil {
			return err
		}
		if err := dataNoAttributes(file); err != nil {
			return err
		}
	}
	return checkDataCopyPins(ctx, parent, job, pins)
}

func checkUnstartedDataRoots(ctx context.Context, parent leaseRecord, job dataJob, pins *dataPins) error {
	if err := checkDataPins(ctx, parent, job, pins); err != nil {
		return err
	}
	for _, root := range pins.roots[1:] {
		if err := dataEmpty(root); err != nil {
			return err
		}
	}
	for _, copy := range pins.copies {
		if err := dataEmpty(copy.Destination); err != nil {
			return err
		}
	}
	return nil
}

func dataHome(job dataJob) api.ObjectManifest {
	return api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: job.Projection.Storage.Home.Home.VendorDirectory, Kind: "directory", Mode: 0700}}}
}

func (m *leaseManager) returnData(ctx context.Context, parent leaseRecord, job dataJob, manifest []byte) error {
	pins := m.dataPins[job.Projection.OpenToken]
	if pins == nil {
		return failure(api.CodeContainmentUnknown, "data return lost its root descriptors")
	}
	object, err := dataManifest(manifest, job.Reg.Plan.Budget.DiskBytes)
	if err != nil {
		return err
	}
	if err := dataReturn(ctx, pins.roots[1], object, parent.Lease.UID, parent.Lease.GID); err != nil {
		return err
	}
	if err := dataReturn(ctx, pins.roots[2], dataHome(job), parent.Lease.UID, parent.Lease.GID); err != nil {
		return err
	}
	for _, copy := range pins.copies {
		if err := dataReturn(ctx, copy.Destination, copy.Projection.Manifest, parent.Lease.UID, parent.Lease.GID); err != nil {
			return err
		}
	}
	return setDataParentGroup(pins.parents[1], job.Lease.GID, parent.Lease.GID)
}

func (m *leaseManager) readDataResult(ctx context.Context, parent leaseRecord, job dataJob, q dataMeasure, observation api.ProcessObservation) (api.LaunchDataResult, error) {
	var zero api.LaunchDataResult
	if err := dataTerminal(observation, dataHandle(job)); err != nil {
		return zero, err
	}
	if job.State != "opened" && job.State != "measured" {
		return zero, failure(api.CodeConflict, "data output precedes native release")
	}
	if err := dataCanonical(q.Output); err != nil {
		return zero, err
	}
	var input dataInput
	var data api.LaunchData
	if err := api.DecodeObject(job.Input, &input); err != nil {
		return zero, err
	}
	if err := api.DecodeObject(q.Output, &data); err != nil {
		return zero, err
	}
	receipt := q.Receipt
	r := job.Reg
	if receipt.LeaseID != r.Worker.ID || receipt.StageID != r.Request.StageID || receipt.Generation != r.Worker.Generation+1 || receipt.CommittedSeq == 0 || receipt.CommittedSeq > 1<<53-1 ||
		receipt.Result.Class != "worker_result" || !validID(receipt.Result.ID) || receipt.Result.Bytes != int64(len(q.Output)) || receipt.Result.SHA256 != digestBytes(q.Output) ||
		data.ReservationID != r.Reservation.ID || data.Target != r.Reservation.Target || data.LeaseID != parent.Lease.ID || data.Source != r.Inputs.Sources.Project || data.Home != job.Projection.Storage.Home ||
		data.Workspace.ID != job.Projection.Storage.WorkspaceID || data.Workspace.ProjectID != data.Source.ProjectID || data.Workspace.Base != data.Source.Base || data.Workspace.Branch != "lane/"+string(data.Target.LifeID) || data.Workspace.LogicalCWD != "/work/main" || data.Workspace.Snapshot != input.Output ||
		data.Materialization.GrantSetID != r.Reservation.GrantSetID || data.Materialization.Manifest != input.Output || input.Output.Class != "manifest" || input.Output.Bytes != int64(len(q.Manifest)) || input.Output.SHA256 != digestBytes(q.Manifest) ||
		len(data.Materialization.Objects) == 0 || observation.Handle != dataHandle(job) || job.Gate.Record == nil || job.Gate.Record.HostUID != job.Lease.UID || job.Lease.UID == parent.Lease.UID {
		return zero, failure(api.CodeIntegrity, "data result differs from its acknowledged input, native worker or output manifest")
	}
	object := data.Materialization.Objects[0]
	if object.GrantID != data.Source.GrantID || object.WorkspaceID != data.Workspace.ID || object.SourceIdentity != job.Projection.SourceIdentity || object.DestinationIdentity != job.Projection.WorkspaceIdentity || object.SnapshotSHA256 != input.Output.SHA256 {
		return zero, failure(api.CodeIntegrity, "data result replaced its held source or destination")
	}
	pins := m.dataPins[job.Projection.OpenToken]
	if pins == nil {
		return zero, failure(api.CodeContainmentUnknown, "read-back lost its descriptors")
	}
	if err := verifyDataCopies(ctx, parent, job, pins, data.Materialization.Objects); err != nil {
		return zero, err
	}
	source, err := dataManifest(pins.manifest, r.Plan.Budget.DiskBytes)
	if err != nil {
		return zero, err
	}
	output, err := dataManifest(q.Manifest, r.Plan.Budget.DiskBytes)
	if err != nil {
		return zero, err
	}
	if !sameDataTree(source, output) {
		return zero, failure(api.CodeIntegrity, "data output tree differs from the authorized source")
	}
	uid, gid := job.Lease.UID, job.Lease.GID
	if job.State == "measured" {
		uid, gid = parent.Lease.UID, parent.Lease.GID
	}
	if err := dataVerify(ctx, pins.roots[0], source, job.Lease.UID, job.Lease.GID); err != nil {
		return zero, err
	}
	gitDir := ""
	if parent.Storage != nil && parent.Storage.Workspace != nil {
		gitDir = parent.Storage.Workspace.Enrollment.GitDir
	}
	if err := dataVerifyWorkspace(ctx, pins.roots[1], output, uid, gid, gitDir); err != nil {
		return zero, err
	}
	if err := dataVerify(ctx, pins.roots[2], dataHome(job), uid, gid); err != nil {
		return zero, err
	}
	// This digest is emitted only after hashing actual source/workspace files
	// and checking the exact home inventory through the original descriptors.
	readBack := digestBytes(q.Manifest)
	return api.LaunchDataResult{ResultReceipt: receipt, ReadBackSHA256: readBack, StageID: r.Request.StageID, WorkerLeaseID: r.Worker.ID, EffectID: r.Worker.EffectID, OperationID: r.Reservation.OperationID, InputSHA256: r.Worker.Input.SHA256, Data: data, Manifest: input.Output, Observation: observation}, nil
}

func dataFD(file *os.File) string { return "/proc/self/fd/" + strconv.Itoa(int(file.Fd())) }
