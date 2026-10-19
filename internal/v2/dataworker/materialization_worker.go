package dataworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"reflect"
	"sort"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// MaterializationJob is an in-process dependency bundle for the confined
// worker, not a serialized capability or public endpoint. The native bootstrap
// supplies its own principal/connection, granted object reader and already
// opened helper projections. No input or argv selects these roots or readers.
type MaterializationJob struct {
	Principal               api.WorkerPrincipal
	Scope                   api.Scope
	Bootstrap               api.WorkerBootstrap
	Source, Workspace, Home *os.Root
	Copies                  map[api.ID]MaterializationCopyRoots
	Read                    func(context.Context, api.BlobReadRequest) (api.BlobChunk, error)
	Clock                   api.Clock
}

type MaterializationCopyRoots struct {
	Source, Destination *os.Root
}

func RunMaterialization(ctx context.Context, job MaterializationJob) (api.WorkerResultReceipt, error) {
	var zero api.WorkerResultReceipt
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if missing(job.Bootstrap) || missing(job.Clock) || job.Read == nil || job.Source == nil || job.Workspace == nil || job.Home == nil {
		return zero, lstate.Error(api.CodePrerequisite, "materialization requires authenticated bootstrap and opened job roots")
	}
	p := job.Principal
	if job.Scope.Actor != p.Record.Actor || job.Scope.Config != p.Endpoint.Config || job.Scope.LaunchID != p.Record.ID ||
		job.Scope.EndpointGeneration != p.Endpoint.EndpointGeneration || job.Scope.Request.Method != "" || p.Lease.Kind != "materialize" {
		return zero, lstate.Error(api.CodeForbidden, "materialization worker cannot borrow its requester identity")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerInputRead, job.Clock.Now()); err != nil {
		return zero, err
	}
	envelope, err := job.Bootstrap.WorkerInput(ctx, job.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerInput(p, envelope, job.Clock.Now()); err != nil {
		return zero, err
	}
	var input MaterializationInput
	if err := api.DecodeObject(envelope.Bytes, &input); err != nil {
		return zero, err
	}
	if err := workerMaterializationInput(input, p, job.Clock.Now()); err != nil {
		return zero, err
	}
	copies, err := api.DecodeDataCopyProjections(input.Storage.Copies)
	if err != nil {
		return zero, err
	}
	if len(job.Copies) != len(copies) {
		return zero, lstate.Error(api.CodeForbidden, "materialization lacks its exact opened copy projections")
	}
	if input.Source.HistoryScope != "tree" {
		return zero, &api.Error{Code: api.CodeUnsupported, Owner: "lb-v2-admin", Message: "reachable Git materialization needs a protected pinned Git runtime and granted history export",
			Instead: "Install the granted Git export/runtime mapping; do not run ambient Git or copy a shared object database."}
	}
	if input.Source.Base != string(input.Source.Object.SHA256) {
		return zero, manifest.Invalid("tree materialization base differs from its immutable source manifest")
	}
	for _, item := range []struct {
		root     *os.Root
		identity string
	}{{job.Source, input.Storage.SourceIdentity}, {job.Workspace, input.Storage.WorkspaceIdentity}, {job.Home, input.Storage.HomeIdentity}} {
		identity, _, err := rootIdentity(item.root)
		if err != nil {
			return zero, err
		}
		if identity != item.identity {
			return zero, lstate.Error(api.CodeIntegrity, "materialization root differs from the helper-held identity")
		}
	}
	if input.Storage.SourceIdentity == input.Storage.WorkspaceIdentity || input.Storage.SourceIdentity == input.Storage.HomeIdentity || input.Storage.WorkspaceIdentity == input.Storage.HomeIdentity {
		return zero, manifest.Invalid("materialization roots must be independent")
	}
	if err := emptyJobRoot(job.Workspace); err != nil {
		return zero, err
	}
	if err := emptyJobRoot(job.Home); err != nil {
		return zero, err
	}
	var source, output api.ObjectManifest
	for _, item := range []struct {
		ref   api.BlobRef
		value *api.ObjectManifest
	}{{input.Source.Object, &source}, {input.Output, &output}} {
		raw, err := readWorkerObject(ctx, job.Read, item.ref)
		if err != nil {
			return zero, err
		}
		if err := api.DecodeObject(raw, item.value); err != nil {
			return zero, err
		}
		if err := manifest.Object(*item.value); err != nil {
			return zero, err
		}
		// Held destination roots must remain private. Refuse an incompatible
		// explicit root before any copy rather than failing after partial work.
		for _, entry := range item.value.Entries {
			if entry.Path == "." && entry.Mode != 0700 {
				return zero, manifest.Invalid("materialization root mode must be 0700")
			}
		}
	}
	if !sameCopyTree(source, output) {
		return zero, lstate.Error(api.CodeIntegrity, "materialization output candidate differs from the authorized source tree")
	}
	var total uint64
	for _, tree := range append([]api.ObjectManifest{output}, copyManifests(copies)...) {
		for _, entry := range tree.Entries {
			var size int64
			if entry.Content != nil {
				size = entry.Content.Bytes
			}
			if entry.Assembly != nil {
				size = entry.Assembly.Bytes
			}
			if size < 0 || uint64(size) > input.Budget.DiskBytes-total {
				return zero, lstate.Error(api.CodeBudget, "materialization copies exceed the shared disk ceiling")
			}
			total += uint64(size)
		}
	}
	if err := copyJobTree(ctx, job.Source, job.Workspace, source, input.Budget.DiskBytes); err != nil {
		return zero, err
	}
	if err := verifyJobTree(ctx, job.Workspace, output, input.Budget.DiskBytes); err != nil {
		return zero, err
	}
	if err := prepareJobHome(ctx, job.Home, input.Storage.Storage.Home.Home.VendorDirectory); err != nil {
		return zero, err
	}
	for _, copy := range copies {
		roots, found := job.Copies[copy.Grant.ID]
		if !found || roots.Source == nil || roots.Destination == nil {
			return zero, lstate.Error(api.CodeForbidden, "materialization copy has no helper-opened roots")
		}
		for _, item := range []struct {
			root     *os.Root
			identity string
		}{{roots.Source, copy.SourceIdentity}, {roots.Destination, copy.DestinationIdentity}} {
			identity, _, err := rootIdentity(item.root)
			if err != nil || identity != item.identity {
				return zero, lstate.Error(api.CodeIntegrity, "materialization copy root changed its pinned identity")
			}
		}
		if err := manifest.Object(copy.Manifest); err != nil {
			return zero, err
		}
		if err := emptyJobRoot(roots.Destination); err != nil {
			return zero, err
		}
		if err := copyJobTree(ctx, roots.Source, roots.Destination, copy.Manifest, input.Budget.DiskBytes); err != nil {
			return zero, err
		}
		if err := verifyJobTree(ctx, roots.Destination, copy.Manifest, input.Budget.DiskBytes); err != nil {
			return zero, err
		}
	}
	for _, root := range []*os.Root{job.Workspace, job.Home} {
		identity, _, err := rootIdentity(root)
		if err != nil {
			return zero, err
		}
		expected := input.Storage.WorkspaceIdentity
		if root == job.Home {
			expected = input.Storage.HomeIdentity
		}
		if identity != expected {
			return zero, lstate.Error(api.CodeIntegrity, "materialization root identity changed during copy")
		}
	}
	data := api.LaunchData{ReservationID: input.Reservation.ID, Target: input.Reservation.Target, LeaseID: input.Storage.Storage.LeaseID, Source: input.Source,
		Workspace: api.Workspace{ID: input.Storage.Storage.WorkspaceID, ProjectID: input.Source.ProjectID, Base: input.Source.Base,
			Branch: "lane/" + string(input.Reservation.Target.LifeID), LogicalCWD: "/work/main", Snapshot: input.Output}, Home: input.Storage.Storage.Home,
		Materialization: api.Materialization{GrantSetID: input.Reservation.GrantSetID, Manifest: input.Output, Objects: []api.MaterializedObject{{GrantID: input.Source.GrantID,
			SourceIdentity: input.Storage.SourceIdentity, DestinationIdentity: input.Storage.WorkspaceIdentity, SnapshotSHA256: input.Output.SHA256, WorkspaceID: input.Storage.Storage.WorkspaceID}}}}
	for _, copy := range copies {
		if _, err := manifest.Expiry(copy.Grant.ExpiresAt, job.Clock.Now()); err != nil {
			return zero, err
		}
		receipt, err := copy.Receipt(data.Workspace.ID)
		if err != nil {
			return zero, err
		}
		data.Materialization.Objects = append(data.Materialization.Objects, receipt)
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return zero, err
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return zero, err
	}
	if len(canonical) > api.MaxFrameBytes {
		return zero, manifest.Invalid("materialization result exceeds its worker acknowledgement bound")
	}
	if err := workerGrantCeilings(input.Grants, input.Grants.Data[0], input.Reservation, input.Source, p.Lease, job.Clock.Now()); err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerResultAppend, job.Clock.Now()); err != nil {
		return zero, err
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: canonical}
	receipt, err := job.Bootstrap.WorkerResult(ctx, job.Scope, submission)
	if err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerResult(p, submission, receipt, job.Clock.Now()); err != nil {
		return zero, err
	}
	return receipt, nil
}

func workerMaterializationInput(input MaterializationInput, p api.WorkerPrincipal, now time.Time) error {
	r, g, s := input.Reservation, input.Grants, input.Source
	if err := api.ValidateLaunchReservation(r); err != nil {
		return err
	}
	if err := manifest.Budget(input.Budget); err != nil {
		return err
	}
	if err := manifest.Blob(input.Output); err != nil {
		return err
	}
	if err := manifest.Blob(s.Object); err != nil {
		return err
	}
	if err := manifest.Relative(input.Storage.Storage.Home.Home.VendorDirectory); err != nil {
		return err
	}
	if err := launchStorage(api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: input.Storage.Storage.LeaseID}, r, input.Storage.Storage); err != nil {
		return err
	}
	sealed := g
	sealed.SHA256 = ""
	digest, err := manifest.HashValue(sealed)
	if err != nil {
		return err
	}
	cause, plan := p.Claim.Record.Effect.Context, p.Claim.Record.Effect.Worker
	if input.Schema != "laneboss.materialize-input.v2" || input.StageID != p.StageID || r.Config != p.Endpoint.Config || r.Target != p.Lease.Target ||
		r.OperationID != p.Lease.OperationID || cause == nil || cause.RequestedBy != r.RequestedBy || cause.CauseRequestID != r.RequestID || cause.CancellationEpoch != r.CancellationEpoch ||
		plan == nil || plan.Kind != "materialize" || input.Budget != plan.Budget || input.Storage.StageID != p.StageID || input.Storage.WorkerLeaseID != p.Lease.ID ||
		!manifest.ValidID(input.Storage.OpenToken) || input.Storage.Storage.ReservationID != r.ID || input.Storage.Storage.Target != r.Target ||
		!manifest.ValidID(input.Storage.Storage.LeaseID) || !manifest.ValidID(input.Storage.Storage.WorkspaceID) ||
		input.Storage.Storage.Home.LifeID != r.Target.LifeID || input.Storage.Storage.Home.Home.WorkspaceID != input.Storage.Storage.WorkspaceID ||
		input.Storage.Storage.Home.Home.VendorDirectory == "." || g.ID != p.Lease.GrantSetID || g.ID == r.GrantSetID || g.LifeID != r.Target.LifeID || g.Revoked ||
		g.PolicyGeneration != r.PolicyGeneration || g.SHA256 != digest || g.SHA256 != p.Record.GrantsSHA256 || len(g.Data) != 1 ||
		len(g.Resources)+len(g.Secrets)+len(g.Profiles)+len(g.Network)+len(g.Channels) != 0 || input.Output.Class != "manifest" || input.Output.ID == s.Object.ID ||
		s.Object.Class != "manifest" || !manifest.ValidID(s.GrantID) || !manifest.ValidID(s.ProjectID) {
		return lstate.Error(api.CodeForbidden, "materialization sealed input widens or replaces its native worker job")
	}
	d := g.Data[0]
	if err := workerGrantCeilings(g, d, r, s, p.Lease, now); err != nil {
		return err
	}
	if d.ParentGrantID != s.GrantID || d.SourceObjectID != s.Object.ID || d.SourceSHA256 != s.Object.SHA256 || d.Destination != "/job/source" ||
		d.Access != "ro" || d.Delivery != "bind_ro" || d.Delegate || d.PublicationID != "" || d.RelativePath != "." || d.HistoryScope != s.HistoryScope {
		return lstate.Error(api.CodeForbidden, "materialization worker has no exact read-only project grant")
	}
	copies, err := api.DecodeDataCopyProjections(input.Storage.Copies)
	if err != nil {
		return err
	}
	for _, copy := range copies {
		if _, err := manifest.Expiry(copy.Grant.ExpiresAt, now); err != nil {
			return err
		}
		if err := manifest.Object(copy.Manifest); err != nil {
			return err
		}
	}
	return nil
}

func copyManifests(copies []api.DataCopyProjection) []api.ObjectManifest {
	result := make([]api.ObjectManifest, 0, len(copies))
	for _, copy := range copies {
		result = append(result, copy.Manifest)
	}
	return result
}

func readWorkerObject(ctx context.Context, read func(context.Context, api.BlobReadRequest) (api.BlobChunk, error), ref api.BlobRef) ([]byte, error) {
	if err := manifest.Blob(ref); err != nil {
		return nil, err
	}
	data := make([]byte, 0, min(ref.Bytes, api.MaxChunkBytes))
	for {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(data))))
		if limit == 0 {
			limit = 1
		}
		chunk, err := read(ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) > limit || manifest.Hash(chunk.Data) != chunk.SHA256 || int64(len(data)+len(chunk.Data)) > ref.Bytes {
			return nil, lstate.Error(api.CodeIntegrity, "materialization object chunk changed")
		}
		if len(chunk.Data) == 0 {
			break
		}
		data = append(data, chunk.Data...)
	}
	if int64(len(data)) != ref.Bytes || manifest.Hash(data) != ref.SHA256 {
		return nil, lstate.Error(api.CodeIntegrity, "materialization object bytes differ from their sealed reference")
	}
	return data, nil
}

func rootIdentity(root *os.Root) (string, uint64, error) {
	info, err := root.Stat(".")
	if err != nil {
		return "", 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return "", 0, manifest.Invalid("materialization root has no directory identity")
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), uint64(stat.Dev), nil
}

func emptyJobRoot(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 {
		return lstate.Error(api.CodeIntegrity, "materialization destination is not a private directory")
	}
	directory, err := openJobPath(root, ".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if len(entries) != 0 {
		return errors.Join(lstate.Error(api.CodeConflict, "materialization destination already contains retained work"), closeErr)
	}
	return closeErr
}

func contentSize(entry api.ObjectEntry) int64 {
	if entry.Content != nil {
		return entry.Content.Bytes
	}
	if entry.Assembly != nil {
		return entry.Assembly.Bytes
	}
	return 0
}

func sameCopyTree(a, b api.ObjectManifest) bool {
	shape := func(value api.ObjectManifest) []api.ObjectEntry {
		result := append([]api.ObjectEntry{}, value.Entries...)
		for i := range result {
			if result[i].Content != nil {
				v := *result[i].Content
				v.ID = ""
				result[i].Content = &v
			}
			if result[i].Assembly != nil {
				v := *result[i].Assembly
				v.Parts = append([]api.BlobRef{}, v.Parts...)
				for j := range v.Parts {
					v.Parts[j].ID = ""
				}
				result[i].Assembly = &v
			}
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
		return result
	}
	return reflect.DeepEqual(shape(a), shape(b))
}

func copyJobTree(ctx context.Context, source, destination *os.Root, object api.ObjectManifest, ceiling uint64) error {
	_, device, err := rootIdentity(source)
	if err != nil {
		return err
	}
	_, destinationDevice, err := rootIdentity(destination)
	if err != nil {
		return err
	}
	entries := append([]api.ObjectEntry{}, object.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	dirs := map[string]bool{}
	for _, entry := range entries {
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			dirs[parent] = true
		}
		if entry.Kind == "directory" && entry.Path != "." {
			dirs[entry.Path] = true
		}
	}
	ordered := make([]string, 0, len(dirs))
	for name := range dirs {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		info, err := source.Lstat(name)
		if err != nil {
			return err
		}
		facts, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || !ok || uint64(facts.Dev) != device {
			return lstate.Error(api.CodeIntegrity, "materialization source directory crosses its held root")
		}
		directory, err := openJobPath(source, name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		actual, statErr := directory.Stat()
		if statErr != nil {
			return errors.Join(statErr, directory.Close())
		}
		if !os.SameFile(info, actual) {
			return errors.Join(lstate.Error(api.CodeIntegrity, "materialization source directory changed before open"), directory.Close())
		}
		if err := directory.Close(); err != nil {
			return err
		}
		if err := mkdirJobPath(destination, name); err != nil {
			return err
		}
	}
	var total uint64
	for _, entry := range entries {
		if err := checkContext(ctx); err != nil {
			return err
		}
		if entry.Kind != "file" {
			continue
		}
		size := contentSize(entry)
		if size < 0 || uint64(size) > ceiling-total {
			return lstate.Error(api.CodeBudget, "materialization source exceeds the job disk ceiling")
		}
		total += uint64(size)
		before, err := source.Lstat(entry.Path)
		if err != nil {
			return err
		}
		beforeFacts, ok := before.Sys().(*syscall.Stat_t)
		if !before.Mode().IsRegular() || !ok || beforeFacts.Nlink != 1 || uint64(beforeFacts.Dev) != device || before.Size() != size {
			return lstate.Error(api.CodeIntegrity, "materialization source is not a single regular file before open")
		}
		file, err := openJobPath(source, entry.Path, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			return errors.Join(err, file.Close())
		}
		facts, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || facts.Nlink != 1 || uint64(facts.Dev) != device || !os.SameFile(before, info) || info.Size() != size {
			return errors.Join(lstate.Error(api.CodeIntegrity, "materialization source file is changed, aliased or outside its root"), file.Close())
		}
		output, err := openJobPath(destination, entry.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.Join(err, file.Close())
		}
		copyErr := copyMeasuredFile(ctx, file, output, entry)
		if copyErr == nil {
			copyErr = output.Chmod(os.FileMode(entry.Mode))
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		if err := errors.Join(copyErr, output.Close(), file.Close()); err != nil {
			return err
		}
	}
	for _, entry := range entries {
		if entry.Kind == "symlink" {
			target, err := readlinkJobPath(source, entry.Path)
			if err != nil {
				return err
			}
			if target != entry.LinkTarget {
				return lstate.Error(api.CodeIntegrity, "materialization source link changed")
			}
			if err := symlinkJobPath(destination, target, entry.Path); err != nil {
				return err
			}
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.Kind != "directory" || entry.Path == "." {
			continue
		}
		before, err := destination.Lstat(entry.Path)
		if err != nil {
			return err
		}
		if !before.IsDir() {
			return lstate.Error(api.CodeIntegrity, "materialization directory changed before permission handoff")
		}
		directory, err := openJobPath(destination, entry.Path, os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		info, err := directory.Stat()
		if err != nil {
			return errors.Join(err, directory.Close())
		}
		facts, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || !ok || uint64(facts.Dev) != destinationDevice || !os.SameFile(before, info) {
			return errors.Join(lstate.Error(api.CodeIntegrity, "materialization directory changed during permission handoff"), directory.Close())
		}
		if err := errors.Join(directory.Chmod(os.FileMode(entry.Mode)), directory.Close()); err != nil {
			return err
		}
	}
	return nil
}

type materializationReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r materializationReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func copyMeasuredFile(ctx context.Context, input *os.File, output io.Writer, entry api.ObjectEntry) error {
	whole := sha256.New()
	buffer := make([]byte, 64*1024)
	for _, ref := range manifest.ContentRefs(entry) {
		part := sha256.New()
		n, err := io.CopyBuffer(io.MultiWriter(output, part, whole), io.LimitReader(materializationReader{ctx, input}, ref.Bytes), buffer)
		if err != nil {
			return err
		}
		if n != ref.Bytes || api.Digest(hex.EncodeToString(part.Sum(nil))) != ref.SHA256 {
			return lstate.Error(api.CodeIntegrity, "materialization actual file bytes differ from their granted content")
		}
	}
	var extra [1]byte
	n, err := input.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return lstate.Error(api.CodeIntegrity, "materialization file exceeds its granted content")
	}
	if entry.Assembly != nil && api.Digest(hex.EncodeToString(whole.Sum(nil))) != entry.Assembly.SHA256 {
		return lstate.Error(api.CodeIntegrity, "materialization assembled file digest changed")
	}
	return nil
}

func verifyJobTree(ctx context.Context, root *os.Root, object api.ObjectManifest, ceiling uint64) error {
	expected := map[string]api.ObjectEntry{}
	for _, entry := range object.Entries {
		expected[entry.Path] = entry
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			if _, ok := expected[parent]; !ok {
				expected[parent] = api.ObjectEntry{Path: parent, Kind: "directory", Mode: 0700}
			}
		}
	}
	var total uint64
	err := fs.WalkDir(jobDirectoryFS{root}, ".", func(name string, dir fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := checkContext(ctx); err != nil {
			return err
		}
		if name == "." {
			if entry, ok := expected["."]; ok {
				info, err := root.Stat(".")
				if err != nil {
					return err
				}
				if uint32(info.Mode().Perm()) != entry.Mode {
					return lstate.Error(api.CodeIntegrity, "materialization root mode differs from its private output snapshot")
				}
			}
			delete(expected, ".")
			return nil
		}
		entry, ok := expected[name]
		if !ok {
			return lstate.Error(api.CodeIntegrity, "materialization read-back found ungranted output")
		}
		delete(expected, name)
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		switch entry.Kind {
		case "directory":
			if !info.IsDir() || uint32(info.Mode().Perm()) != entry.Mode {
				return lstate.Error(api.CodeIntegrity, "materialization output directory changed kind")
			}
		case "symlink":
			target, err := readlinkJobPath(root, name)
			if err != nil {
				return err
			}
			if target != entry.LinkTarget {
				return lstate.Error(api.CodeIntegrity, "materialization output link changed")
			}
		case "file":
			size := contentSize(entry)
			if uint64(size) > ceiling-total {
				return lstate.Error(api.CodeBudget, "materialization output exceeds its read-back ceiling")
			}
			total += uint64(size)
			facts, ok := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || !ok || facts.Nlink != 1 || info.Size() != size || uint32(info.Mode().Perm()) != entry.Mode {
				return lstate.Error(api.CodeIntegrity, "materialization output file identity or mode changed")
			}
			file, err := openJobPath(root, name, os.O_RDONLY, 0)
			if err != nil {
				return err
			}
			actual, statErr := file.Stat()
			if statErr != nil {
				return errors.Join(statErr, file.Close())
			}
			if !os.SameFile(info, actual) {
				return errors.Join(lstate.Error(api.CodeIntegrity, "materialization read-back file was replaced"), file.Close())
			}
			return errors.Join(copyMeasuredFile(ctx, file, io.Discard, entry), file.Close())
		default:
			return manifest.Invalid("materialization output kind is unsupported")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		return lstate.Error(api.CodeIntegrity, "materialization read-back omitted a granted output")
	}
	return nil
}
