package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// This fixture starts after service authentication. It stores and reloads
// actual object/journal bytes and measures its owned filesystem/process scope.
// It is not authenticated helper, OS-isolation or vendor-login evidence.
type launchCaseStore struct {
	api.StateStore
	mu            sync.Mutex
	root          string
	grants        api.GrantSet
	workerGrants  *api.GrantSet
	policy        api.EffectivePolicy
	lane          *api.Lane
	planID        api.ID
	priorPlanID   api.ID
	priorLaunchID api.ID
	effectID      api.ID
	events        []api.Event
	objects       map[api.ID]api.ObjectMetadata
	operations    map[api.ID]api.Operation
	lease         api.WorkerLease
	fail          map[string]error
	blobFault     string
}

func (f *launchCaseStore) save(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(f.root, name), data, 0600)
}
func (f *launchCaseStore) read(name string, value any) error {
	data, err := os.ReadFile(filepath.Join(f.root, name))
	if errors.Is(err, os.ErrNotExist) {
		return wire.Error(api.CodeNotFound, "fixture retained record is absent")
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
func (f *launchCaseStore) putObject(t *testing.T, id api.ID, class string, value any, operation api.ID) api.BlobRef {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("cannot encode retained fixture object")
	}
	data, err = api.CanonicalJSON(data)
	if err != nil {
		t.Fatal("cannot canonicalize retained fixture object")
	}
	return f.putRawObject(t, id, class, data, operation)
}

func (f *launchCaseStore) putRawObject(t *testing.T, id api.ID, class string, data []byte, operation api.ID) api.BlobRef {
	t.Helper()
	sum := sha256.Sum256(data)
	ref := api.BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: api.Digest(hex.EncodeToString(sum[:]))}
	if err := os.WriteFile(filepath.Join(f.root, string(id)+".blob"), data, 0600); err != nil {
		t.Fatal("cannot retain fixture object bytes")
	}
	f.objects[id] = api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: "service-case", Owner: api.Actor{Kind: "service", ID: "service-a"}, Audience: "service", Generation: 1}, Origin: "service", SourceOperationID: operation}
	f.operations[operation] = api.Operation{ID: operation, Status: "succeeded"}
	return ref
}
func (f *launchCaseStore) Lane(_ context.Context, _ api.Scope, target api.LifeRef) (api.Lane, error) {
	if f.lane == nil || f.lane.LifeID != target.LifeID || f.lane.Run != target.Run {
		return api.Lane{}, wire.Error(api.CodeNotFound, "fixture life is reserved but not yet ready")
	}
	return *f.lane, nil
}
func (f *launchCaseStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	if f.workerGrants != nil && id == f.workerGrants.ID {
		return *f.workerGrants, nil
	}
	if id != f.grants.ID {
		return api.GrantSet{}, wire.Error(api.CodeNotFound, "fixture grant selector differs")
	}
	return f.grants, nil
}
func (f *launchCaseStore) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	copy := f.policy
	copy.SHA256 = ""
	digest, err := valueDigest(copy)
	if err != nil {
		return api.EffectivePolicy{}, err
	}
	copy.SHA256 = digest
	return copy, nil
}
func (f *launchCaseStore) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	return f.Policy(ctx, scope)
}
func (f *launchCaseStore) PendingEffects(context.Context, api.CursorRequest) ([]api.Effect, error) {
	if err := f.fail["pending"]; err != nil {
		return nil, err
	}
	var e api.EffectRecord
	if err := f.read("effect.json", &e); err != nil {
		return nil, err
	}
	return []api.Effect{e.Effect}, nil
}
func (f *launchCaseStore) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	if err := f.fail["effect"]; err != nil {
		return api.EffectRecord{}, err
	}
	if id != f.effectID && id != f.lease.EffectID {
		return api.EffectRecord{}, wire.Error(api.CodeNotFound, "fixture effect selector differs")
	}
	name := "effect.json"
	if id != f.effectID {
		name = "worker-effect.json"
	}
	var value api.EffectRecord
	err := f.read(name, &value)
	return value, err
}
func (f *launchCaseStore) LaunchPlan(_ context.Context, _ api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	if err := f.fail["plan"]; err != nil {
		return api.LaunchPlanRecord{}, err
	}
	if id != f.planID {
		if id != f.priorPlanID {
			return api.LaunchPlanRecord{}, wire.Error(api.CodeNotFound, "fixture plan selector differs")
		}
		var prior api.LaunchPlanRecord
		err := f.read("prior-plan.json", &prior)
		return prior, err
	}
	var value api.LaunchPlanRecord
	err := f.read("plan.json", &value)
	return value, err
}
func (f *launchCaseStore) LaunchBinding(_ context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	if err := f.fail["binding"]; err != nil {
		return api.LaunchBindingRequest{}, err
	}
	var value api.LaunchBindingRequest
	name := "binding.json"
	if id == f.priorLaunchID {
		name = "prior-binding.json"
	}
	err := f.read(name, &value)
	if err == nil && value.Record.ID != id {
		return api.LaunchBindingRequest{}, wire.Error(api.CodeNotFound, "fixture binding selector differs")
	}
	return value, err
}
func (f *launchCaseStore) Events(_ context.Context, _ api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	values := []api.Event{}
	for _, e := range f.events {
		if request.LifeID == "" || e.LifeID == request.LifeID && e.Run == request.Run {
			values = append(values, e)
		}
	}
	return api.EventPage{Events: values, Complete: true}, nil
}
func (f *launchCaseStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	v, ok := f.objects[id]
	if !ok {
		return v, wire.Error(api.CodeNotFound, "fixture protected object is absent")
	}
	return v, nil
}
func (f *launchCaseStore) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	_, ok := f.objects[request.ObjectID]
	if !ok {
		return api.BlobChunk{}, wire.Error(api.CodeNotFound, "fixture object is absent")
	}
	data, err := os.ReadFile(filepath.Join(f.root, string(request.ObjectID)+".blob"))
	if err != nil {
		return api.BlobChunk{}, err
	}
	limit := request.Limit
	if limit == 0 {
		limit = api.MaxChunkBytes
	}
	if request.Offset < 0 || request.Offset > int64(len(data)) || limit < 1 || limit > api.MaxChunkBytes {
		return api.BlobChunk{}, wire.Error(api.CodeInvalid, "fixture blob read exceeds the actual chunk bounds")
	}
	end := min(int64(len(data)), request.Offset+int64(limit))
	part := append([]byte(nil), data[request.Offset:end]...)
	sum := sha256.Sum256(part)
	chunk := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: api.Digest(hex.EncodeToString(sum[:]))}
	switch f.blobFault {
	case "offset":
		chunk.Offset++
	case "hash":
		chunk.SHA256 = digestFixture("wrong chunk bytes")
	case "empty":
		chunk.Data = []byte{}
	case "foreign":
		chunk.ObjectID = "foreign-object"
	case "overlong":
		chunk.Data = append(chunk.Data, 0)
	}
	return chunk, nil
}
func (f *launchCaseStore) Operation(_ context.Context, _ api.Scope, id api.ID) (api.Operation, error) {
	value, ok := f.operations[id]
	if !ok {
		return value, wire.Error(api.CodeNotFound, "fixture producer operation is absent")
	}
	return value, nil
}
func (f *launchCaseStore) WorkerLease(_ context.Context, _ api.Scope, id api.ID) (api.WorkerLease, error) {
	if id != f.lease.ID {
		return api.WorkerLease{}, wire.Error(api.CodeNotFound, "fixture worker lease is absent")
	}
	return f.lease, nil
}

func (f *launchCaseStore) ContinuationIntent(_ context.Context, _ api.Scope, id api.ID) (api.ContinuationIntent, error) {
	if err := f.fail["continuation"]; err != nil {
		return api.ContinuationIntent{}, err
	}
	var intent api.ContinuationIntent
	if err := f.read("continuation.json", &intent); err != nil {
		return intent, err
	}
	if intent.ID != id {
		return api.ContinuationIntent{}, wire.Error(api.CodeNotFound, "fixture continuation selector differs")
	}
	return intent, nil
}
func (f *launchCaseStore) RetainObject(_ context.Context, scope api.Scope, request api.RetainObjectRequest) (api.BlobRef, error) {
	if request.Intent.Kind != api.InternalObjectRetain || request.Intent.Config != scope.Config || request.Object.ACL.Owner.Kind != "service" && request.Object.ACL.Owner.Kind != "worker" {
		return api.BlobRef{}, wire.Error(api.CodeForbidden, "fixture object retention lacks installed service authority")
	}
	if request.Object.ACL.Owner.Kind == "worker" {
		var principal api.WorkerPrincipal
		if err := f.read("usage-principal.json", &principal); err != nil {
			return api.BlobRef{}, err
		}
		if request.Object.ACL.Owner != principal.Record.Actor || request.Intent.EffectID != principal.Lease.EffectID || request.Intent.CauseOperationID != principal.Lease.OperationID || request.Object.ACL.LifeID != principal.Lease.Target.LifeID {
			return api.BlobRef{}, wire.Error(api.CodeForbidden, "fixture usage object is outside its actual worker claim")
		}
	}
	sum := sha256.Sum256(request.Object.Bytes)
	if api.Digest(hex.EncodeToString(sum[:])) != request.Object.SHA256 {
		return api.BlobRef{}, wire.Error(api.CodeIntegrity, "fixture retained object hash differs")
	}
	ref := api.BlobRef{ID: request.Object.ObjectKey, SHA256: request.Object.SHA256, Bytes: int64(len(request.Object.Bytes)), Class: request.Object.Class}
	if prior, exists := f.objects[ref.ID]; exists {
		actual, err := os.ReadFile(filepath.Join(f.root, string(ref.ID)+".blob"))
		if err != nil {
			return api.BlobRef{}, err
		}
		if prior.Ref != ref || !reflect.DeepEqual(prior.ACL, request.Object.ACL) || prior.Origin != request.Object.Origin || prior.SourceOperationID != request.Intent.CauseOperationID || !reflect.DeepEqual(actual, request.Object.Bytes) {
			return api.BlobRef{}, wire.Error(api.CodeConflict, "fixture immutable object retry changed its retained bytes or authority")
		}
		return prior.Ref, nil
	}
	if err := os.WriteFile(filepath.Join(f.root, string(ref.ID)+".blob"), request.Object.Bytes, 0600); err != nil {
		return api.BlobRef{}, err
	}
	f.objects[ref.ID] = api.ObjectMetadata{Ref: ref, ACL: request.Object.ACL, Origin: request.Object.Origin, SourceOperationID: request.Intent.CauseOperationID}
	return ref, nil
}

type launchCaseHelper struct {
	api.HelperControl
	store             *launchCaseStore
	root              string
	clock             api.Clock
	process           *exec.Cmd
	processGeneration string
	exited            bool
	fail              map[string]error
	releases          int
}

// This resolver checks the actual persisted fixture grant set and digest. It
// does not stand in for production ancestry/delegation or authentication.
type launchCaseResolver struct {
	api.GrantResolver
	store *launchCaseStore
	clock api.Clock
}

func (r *launchCaseResolver) Resolve(ctx context.Context, _ api.Scope, request api.GrantResolveRequest) (api.GrantSet, error) {
	if request.ReservationID != r.store.planID {
		return api.GrantSet{}, wire.Error(api.CodeForbidden, "fixture grant resolution selected another reservation")
	}
	return r.Revalidate(ctx, r.store.grants)
}

func (r *launchCaseResolver) Revalidate(ctx context.Context, input api.GrantSet) (api.GrantSet, error) {
	if err := wire.Context(ctx); err != nil {
		return api.GrantSet{}, err
	}
	copy := input
	copy.SHA256 = ""
	digest, err := valueDigest(copy)
	if err != nil {
		return api.GrantSet{}, err
	}
	stored, lookupErr := r.store.Grants(ctx, input.ID)
	if lookupErr != nil {
		return api.GrantSet{}, lookupErr
	}
	if !reflect.DeepEqual(input, stored) || digest != input.SHA256 || input.Revoked || !future(input.ExpiresAt, r.clock.Now()) {
		return api.GrantSet{}, wire.Error(api.CodeForbidden, "fixture grants failed retained digest revalidation")
	}
	return input, nil
}

func (h *launchCaseHelper) ResolveRuntime(_ context.Context, handoff api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	if err := h.fail["runtime"]; err != nil {
		return api.ResolvedRuntime{}, err
	}
	var retained api.PreparedSpecHandoff
	if err := h.store.read("handoff.json", &retained); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if !reflect.DeepEqual(handoff, retained) {
		return api.ResolvedRuntime{}, wire.Error(api.CodeForbidden, "fixture runtime has no matching registered spec")
	}
	blob, err := h.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: handoff.Spec.RuntimeManifest.ID})
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	var manifest api.RuntimeManifest
	if err := api.DecodeObject(blob.Data, &manifest); err != nil {
		return api.ResolvedRuntime{}, err
	}
	data, err := os.ReadFile(filepath.Join(h.root, "runtime.bin"))
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	sum := sha256.Sum256(data)
	if api.Digest(hex.EncodeToString(sum[:])) != manifest.Bootstrap.SHA256 {
		return api.ResolvedRuntime{}, wire.Error(api.CodeIntegrity, "fixture runtime file differs from its enrolled digest")
	}
	var storage api.LaunchStorage
	if err := h.store.read("storage.json", &storage); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if storage.LeaseID != handoff.Spec.UIDLeaseID || storage.Target != handoff.Spec.Target || storage.WorkspaceID != handoff.Spec.Workspace.ID {
		return api.ResolvedRuntime{}, wire.Error(api.CodeForbidden, "fixture runtime has foreign allocated storage")
	}
	for _, name := range []string{"work", "home", "history"} {
		info, err := os.Lstat(filepath.Join(h.root, name))
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return api.ResolvedRuntime{}, wire.Error(api.CodeIntegrity, "fixture runtime storage disappeared")
		}
	}
	digest, err := valueDigest(handoff.Spec)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	if digest != handoff.SpecSHA256 || digest != handoff.Original.SHA256 {
		return api.ResolvedRuntime{}, wire.Error(api.CodeIntegrity, "fixture runtime spec digest differs")
	}
	return api.ResolvedRuntime{Manifest: manifest, Workspace: handoff.Spec.Workspace, Home: storage.Home.Home,
		SpecReceipt: api.PreparedSpecReceipt{SpecID: handoff.Spec.ID, Config: handoff.Config, Target: handoff.Spec.Target, LeaseID: storage.LeaseID, SpecSHA256: digest, RuntimeManifest: handoff.Spec.RuntimeManifest, OperationID: handoff.OperationID}}, nil
}

func (h *launchCaseHelper) ResolveLaunchSources(_ context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	if err := h.fail["sources"]; err != nil {
		return api.LaunchSources{}, err
	}
	var record api.LaunchPlanRecord
	if err := h.store.read("plan.json", &record); err != nil {
		return api.LaunchSources{}, err
	}
	if record.Inputs == nil || record.Reservation.Config != "service-case" || record.Reservation.ID != request.ReservationID || record.Reservation.GrantSetID != request.GrantSetID {
		return api.LaunchSources{}, wire.Error(api.CodeForbidden, "fixture source lookup differs from retained reservation")
	}
	var enrollment api.LaunchEnrollment
	if err := h.store.read("enrollment.json", &enrollment); err != nil {
		return api.LaunchSources{}, err
	}
	manifestRef := h.store.objects["runtime-object"].Ref
	if err := api.ValidateLaunchEnrollment(enrollment, "service-case", manifestRef); err != nil {
		return api.LaunchSources{}, err
	}
	result := api.LaunchSources{ReservationID: request.ReservationID}
	for _, project := range enrollment.Projects {
		if project.ProjectID != record.Inputs.Sources.Project.ProjectID {
			continue
		}
		for _, grant := range h.store.grants.Data {
			if grant.Destination == "/work/main" && grant.SourceObjectID == project.Object.ID && grant.SourceSHA256 == project.Object.SHA256 && grant.HistoryScope == project.HistoryScope {
				result.Project = api.ProjectLaunchSource{EnrollmentID: project.ID, Generation: project.Generation, ProjectID: project.ProjectID, GrantID: grant.ID, Object: project.Object, Base: project.Base, HistoryScope: project.HistoryScope}
			}
		}
	}
	for _, runtime := range enrollment.Runtimes {
		if runtime.Driver == record.Inputs.Sources.Runtime.Driver {
			result.Runtime = runtime
		}
	}
	if result.Project.EnrollmentID == "" || result.Runtime.EnrollmentID == "" {
		return result, wire.Error(api.CodeNotFound, "fixture installed source selection is absent")
	}
	for _, ref := range []api.BlobRef{result.Project.Object, result.Runtime.Manifest} {
		blob, err := h.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: ref.ID})
		if err != nil {
			return result, err
		}
		sum := sha256.Sum256(blob.Data)
		if api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256 || int64(len(blob.Data)) != ref.Bytes {
			return result, wire.Error(api.CodeIntegrity, "fixture installed source object bytes changed")
		}
	}
	return result, nil
}
func (h *launchCaseHelper) ResolveLaunchStorage(_ context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	if err := h.fail["storage"]; err != nil {
		return api.LaunchStorage{}, err
	}
	var storage api.LaunchStorage
	if err := h.store.read("storage.json", &storage); err != nil {
		return storage, err
	}
	if storage.ReservationID != request.ReservationID || storage.LeaseID != request.LeaseID || h.store.grants.ID != request.GrantSetID {
		return storage, wire.Error(api.CodeForbidden, "fixture storage selector differs")
	}
	for _, name := range []string{"work", "home", "history"} {
		info, err := os.Lstat(filepath.Join(h.root, name))
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return storage, wire.Error(api.CodeIntegrity, "fixture allocated registry object is absent or unsafe")
		}
	}
	return storage, nil
}
func (h *launchCaseHelper) ObserveGate(_ context.Context, request api.HelperObserveRequest) (api.ProcessObservation, error) {
	if err := h.fail["observe"]; err != nil {
		return api.ProcessObservation{}, err
	}
	var binding api.LaunchBindingRequest
	if err := h.store.read("binding.json", &binding); err != nil {
		return api.ProcessObservation{}, err
	}
	if request.LeaseID != binding.Record.UIDLeaseID || request.Handle.Target != binding.Record.Target || request.Handle.ContainmentID != binding.Record.ContainmentID || request.Handle.Generation != binding.Record.ProcessGeneration || h.process == nil {
		return api.ProcessObservation{}, wire.Error(api.CodeContainmentUnknown, "fixture process does not belong to the retained allocation")
	}
	var survivors uint64
	state := "running"
	var exit *int
	if h.exited {
		if h.process.ProcessState == nil {
			return api.ProcessObservation{}, wire.Error(api.CodeContainmentUnknown, "fixture process exit is unknown")
		}
		state = "exited"
		code := h.process.ProcessState.ExitCode()
		exit = &code
	} else {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", h.process.Process.Pid))
		if err != nil {
			return api.ProcessObservation{}, wire.Error(api.CodeContainmentUnknown, "fixture kernel process generation is unknown")
		}
		fields := strings.Fields(string(data[strings.LastIndex(string(data), ")")+2:]))
		if len(fields) < 20 || fields[19] != h.processGeneration {
			return api.ProcessObservation{}, wire.Error(api.CodeContainmentUnknown, "fixture kernel process generation changed")
		}
		survivors = 1
	}
	return api.ProcessObservation{Handle: request.Handle, State: state, ExitCode: exit, Survivors: &survivors, PromptStatus: "done", ObservedAt: api.Timestamp(h.clock.Now().UTC().Format(time.RFC3339Nano))}, nil
}
func (h *launchCaseHelper) Release(ctx context.Context, request api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	if err := h.fail["release"]; err != nil {
		return api.ReleaseReceipt{}, err
	}
	actual, err := h.ObserveGate(ctx, api.HelperObserveRequest{LeaseID: request.LeaseID, Handle: request.Observation.Handle})
	if err != nil {
		return api.ReleaseReceipt{}, err
	}
	counts := map[string]uint64{}
	for _, name := range []string{"connections", "jobs", "exports"} {
		entries, err := os.ReadDir(filepath.Join(h.root, name))
		if err != nil {
			return api.ReleaseReceipt{}, err
		}
		counts[name] = uint64(len(entries))
	}
	if actual.Survivors == nil || *actual.Survivors != 0 || counts["connections"]+counts["jobs"]+counts["exports"] != 0 {
		return api.ReleaseReceipt{}, wire.Error(api.CodeContainmentUnknown, "fixture helper independently measured live resources")
	}
	h.releases++
	connections, jobs, exports := counts["connections"], counts["jobs"], counts["exports"]
	return api.ReleaseReceipt{ID: api.ID("release-" + strconv.Itoa(h.releases)), LeaseID: request.LeaseID, ContainmentID: actual.Handle.ContainmentID, Backend: "linux-bwrap-landlock",
		OperationID: request.Cause.CauseOperationID, EffectID: request.Cause.EffectID, Quiescence: actual, LiveConnections: &connections, QueuedJobs: &jobs, WritableExports: &exports, ObservedAt: actual.ObservedAt}, nil
}

type launchCaseControl struct {
	api.LaunchControlSource
	helper     *launchCaseHelper
	omitRecord bool
}

func (c *launchCaseControl) Handoff(_ context.Context, spec api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	if err := c.helper.fail["handoff"]; err != nil {
		return api.PreparedSpecHandoff{}, err
	}
	var retained api.PreparedSpecHandoff
	if err := c.helper.store.read("handoff.json", &retained); err != nil {
		return retained, err
	}
	if !reflect.DeepEqual(spec, retained.Spec) {
		return api.PreparedSpecHandoff{}, wire.Error(api.CodeForbidden, "fixture handoff differs from retained spec")
	}
	blob, err := c.helper.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: retained.Original.ID})
	if err != nil {
		return retained, err
	}
	var original api.LaunchSpec
	if err := api.DecodeObject(blob.Data, &original); err != nil {
		return retained, err
	}
	if !reflect.DeepEqual(original, spec) {
		return retained, wire.Error(api.CodeIntegrity, "fixture handoff original bytes differ")
	}
	return retained, nil
}

func (c *launchCaseControl) Release(_ context.Context, id api.ID, observation api.ProcessObservation) (api.HelperReleaseRequest, error) {
	if id == "" || observation.Handle.Target.LifeID == "" {
		return api.HelperReleaseRequest{}, wire.Error(api.CodeInvalid, "fixture release selector is incomplete")
	}
	return api.HelperReleaseRequest{LeaseID: id, Observation: observation, Cause: api.InternalIntent{ID: "release-intent", Kind: api.InternalHelperRelease, Config: "service-case", Actor: api.Actor{Kind: "service", ID: "service-a"},
		RequestedBy: api.Actor{Kind: "human", ID: "human-a"}, CauseOperationID: "release-operation", CauseRequestID: "release-request", EffectID: "release-effect", Target: observation.Handle.Target}}, nil
}
func (c *launchCaseControl) RecordRelease(_ context.Context, request api.HelperReleaseRequest, receipt api.ReleaseReceipt) error {
	if c.omitRecord {
		return nil
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	store := c.helper.store
	store.mu.Lock()
	defer store.mu.Unlock()
	store.events = append(store.events, api.Event{Schema: api.SchemaVersion, ID: receipt.ID, Config: "service-case", Seq: api.Sequence(len(store.events) + 1), Kind: "helper.released", Actor: request.Cause.Actor,
		RequestedBy: request.Cause.RequestedBy, RequestID: request.Cause.CauseRequestID, OperationID: receipt.OperationID, LifeID: request.Cause.Target.LifeID, Run: request.Cause.Target.Run, Payload: data})
	return nil
}

type launchCase struct {
	service           *Service
	backend           *measuredBackend
	store             *launchCaseStore
	helper            *launchCaseHelper
	control           *launchCaseControl
	clock             *clockFixture
	profile           bstate.Profile
	grant             api.ProfileGrant
	target            api.LifeRef
	key               []byte
	material          []byte
	directory         string
	beforeBind        func(*testing.T, api.LaunchSpec)
	registeredCapture bool
}

func newLaunchCase(t *testing.T, mode string, drivers ...api.Driver) *launchCase {
	t.Helper()
	return newLaunchCaseInventory(t, mode, false, drivers...)
}

func newLaunchCaseWithAlternate(t *testing.T, mode string, drivers ...api.Driver) *launchCase {
	t.Helper()
	return newLaunchCaseInventory(t, mode, true, drivers...)
}

func newLaunchCaseInventory(t *testing.T, mode string, alternate bool, drivers ...api.Driver) *launchCase {
	t.Helper()
	return newLaunchCaseRuntime(t, mode, alternate, nil, drivers...)
}

func newLaunchCaseRuntime(t *testing.T, mode string, alternate bool, configure func(*api.RuntimeManifest, *api.Executable), drivers ...api.Driver) *launchCase {
	t.Helper()
	return newLaunchCaseRuntimeAt(t, mode, alternate, configure, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), drivers...)
}

func newLaunchCaseRuntimeAt(t *testing.T, mode string, alternate bool, configure func(*api.RuntimeManifest, *api.Executable), now time.Time, drivers ...api.Driver) *launchCase {
	t.Helper()
	driver := api.DriverCodex
	if len(drivers) > 1 {
		t.Fatal("fixture accepts one enrolled driver")
	}
	if len(drivers) == 1 {
		driver = drivers[0]
	}
	clock := &clockFixture{now: now}
	root := testdir.New(t)
	for _, name := range []string{"work", "home", "history", "connections", "jobs", "exports"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal("cannot allocate fixture private objects")
		}
	}
	store := &launchCaseStore{root: root, objects: map[api.ID]api.ObjectMetadata{}, operations: map[api.ID]api.Operation{}, fail: map[string]error{}, planID: "reservation-a", effectID: "planning-effect"}
	directory := filepath.Join(testdir.New(t), "records")
	key := syntheticBytes(t, 32)
	backend := openMutationBackend(t, directory, clock, key)
	helper := &launchCaseHelper{store: store, root: root, clock: clock, fail: map[string]error{}}
	control := &launchCaseControl{helper: helper}
	service, err := New(Dependencies{ProjectionIdentity: deniedProjection{}, Backend: backend, Store: store, Human: &humanFixture{}, Clock: clock, Config: "service-case", Grants: &launchCaseResolver{store: store, clock: clock}, Helper: helper, Control: control})
	if err != nil {
		t.Fatal("cannot initialize launch broker fixture")
	}
	target := api.LifeRef{LifeID: "reserved-life", Run: 1}
	expires := api.Timestamp(clock.now.Add(time.Hour).Format(time.RFC3339Nano))
	grant := api.ProfileGrant{ID: "profile-grant", ProfileID: "profile-a", Driver: driver, Provider: "provider-a", ExpiresAt: expires}
	material := syntheticBytes(t, 91)
	if mode == "file_login" {
		material, err = json.Marshal(map[string]string{"account_id": "synthetic-account", "access_token": hex.EncodeToString(syntheticBytes(t, 40)), "refresh_token": hex.EncodeToString(syntheticBytes(t, 40))})
		if err != nil {
			t.Fatal("cannot create synthetic file login")
		}
	}
	if mode == "codex-file" {
		material, err = json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"account_id": "synthetic-account", "access_token": hex.EncodeToString(syntheticBytes(t, 40)), "refresh_token": hex.EncodeToString(syntheticBytes(t, 40))}})
		if err != nil {
			t.Fatal("cannot encode the native synthetic subscription credential")
		}
	}
	if mode == "claudock-headless" {
		material = []byte(hex.EncodeToString(syntheticBytes(t, 40)))
	}
	if mode == "claude-api-key" {
		material = []byte("sk-ant-" + hex.EncodeToString(syntheticBytes(t, 40)))
	}
	info, err := backend.Store(context.Background(), api.SecretInfo{Name: "synthetic-login", Version: "one"}, api.SecretMaterial{Bytes: material})
	if err != nil {
		t.Fatal("cannot enroll synthetic protected login")
	}
	runtimeBytes := syntheticBytes(t, 97)
	if err := os.WriteFile(filepath.Join(root, "runtime.bin"), runtimeBytes, 0600); err != nil {
		t.Fatal("cannot retain enrolled runtime bytes")
	}
	runtime := api.Executable{ID: "runtime-a", SHA256: digestFixture(string(runtimeBytes)), Version: "fixture-wrapper-v1"}
	enrolledRuntime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: runtime, Bootstrap: runtime, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}}
	if configure != nil {
		configure(&enrolledRuntime, &runtime)
	}
	observation := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: "service-case", ProfileID: grant.ProfileID, LoginID: "canonical-login", Generation: 1, Driver: grant.Driver, Provider: grant.Provider, Available: true,
		CheckedAt: api.Timestamp(clock.now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(clock.now.Add(4 * time.Minute).Format(time.RFC3339Nano))}
	evidence := store.putObject(t, "profile-evidence", "credential_evidence", observation, "observation-operation")
	profile := bstate.Profile{Schema: "laneboss.credential-profile.v2", Config: "service-case", ID: grant.ProfileID, LoginID: observation.LoginID, Generation: 1, Driver: grant.Driver, Provider: grant.Provider, Mode: mode,
		Source: api.SecretGrant{ID: "profile-source", Name: info.Name, Version: info.Version, SourceHandle: info.SourceHandle, Delivery: "file", Target: "auth.json", ExpiresAt: expires}, Runtime: runtime,
		Models: []string{"fixture-model"}, VendorVersions: []string{"fixture-vendor-v1"}, RefreshFields: []string{"access_token", "refresh_token", "expires_at"}, Evidence: evidence, ExpiresAt: expires}
	if mode == "codex-file" {
		profile.AccountSHA256 = digestFixture("synthetic-account")
	}
	if err := service.InstallProfile(context.Background(), profile); err != nil {
		t.Fatal("cannot install protected synthetic profile")
	}
	project := store.putObject(t, "project-object", "manifest", map[string]string{"schema": "fixture.project"}, "project-operation")
	runtimeManifest := store.putObject(t, "runtime-object", "manifest", enrolledRuntime, "runtime-operation")
	source := api.ProjectLaunchSource{EnrollmentID: "project-enrollment", Generation: 1, ProjectID: "project-a", GrantID: "main-data", Object: project, Base: strings.Repeat("a", 40), HistoryScope: "tree"}
	inputs := api.LaunchInputs{Sources: api.LaunchSources{ReservationID: store.planID, Project: source, Runtime: api.LaunchRuntime{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: grant.Driver, Executable: runtime, Manifest: runtimeManifest}}}
	enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: "service-case", Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: source.EnrollmentID, Generation: source.Generation, ProjectID: source.ProjectID, Object: source.Object, Base: source.Base, HistoryScope: source.HistoryScope}}, Runtimes: []api.LaunchRuntime{inputs.Sources.Runtime}}
	if err := store.save("enrollment.json", enrollment); err != nil {
		t.Fatal("cannot retain independent installed source enrollment")
	}
	store.grants = api.GrantSet{ID: "reserved-grants", LifeID: target.LifeID, Generation: 1, PolicyGeneration: 1, SHA256: digestFixture("actual reserved grants"), ExpiresAt: expires,
		Resources: []api.ResourceGrant{}, Data: []api.DataGrant{{ID: source.GrantID, SourceObjectID: source.Object.ID, SourceSHA256: source.Object.SHA256, Destination: "/work/main", RelativePath: ".", Access: "rw", Delivery: "copy", HistoryScope: source.HistoryScope, ExpiresAt: expires}},
		Profiles: []api.ProfileGrant{grant}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	if alternate {
		other := grant
		other.ID, other.ProfileID = "profile-grant-b", "profile-b"
		store.grants.Profiles = append(store.grants.Profiles, other)
	}
	grantCopy := store.grants
	grantCopy.SHA256 = ""
	store.grants.SHA256, err = valueDigest(grantCopy)
	if err != nil {
		t.Fatal("cannot hash retained fixture grants")
	}
	inputs.Grants = store.grants
	store.policy = api.EffectivePolicy{Generation: 1, AllowCaptureRefusal: true, CaptureRefusalApprovalID: "fixture-capture-approval"}
	start := api.StartRequest{Lane: "synthetic-lane", ProjectID: source.ProjectID, Level: 3, Role: "executor", RootTicketID: "fixture-root-ticket", Task: store.putObject(t, "task-object", "task", map[string]string{"task": "synthetic"}, "task-operation"),
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{{ParentGrantID: api.ID("template-" + string(grant.ID)), ProfileID: grant.ProfileID, Delegate: grant.Delegate, ExpiresAt: grant.ExpiresAt}}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}},
		Driver: grant.Driver, ProfileGrantID: api.ID("template-" + string(grant.ID)), Model: "fixture-model", Effort: "high", Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 1 << 20, Processes: 10, DiskBytes: 1 << 20}, ExpectedPolicyGeneration: 1}
	start.Grants.Profiles = make([]api.ProfileDelegation, 0, len(store.grants.Profiles))
	for _, member := range store.grants.Profiles {
		start.Grants.Profiles = append(start.Grants.Profiles, api.ProfileDelegation{ParentGrantID: api.ID("template-" + string(member.ID)),
			ProfileID: member.ProfileID, Delegate: member.Delegate, ExpiresAt: member.ExpiresAt})
	}
	params, err := json.Marshal(start)
	if err != nil {
		t.Fatal("cannot encode retained start input")
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "service-case", RequestID: "request-a", IdempotencyKey: "retained-operation-key", Method: "lane.start", Params: params}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal("cannot hash retained start intent")
	}
	original := store.putObject(t, "original-request", "launch_request", request, "launch-operation")
	r := api.LaunchReservation{ID: store.planID, Config: "service-case", Mode: "start", Level: start.Level, Role: start.Role, Driver: start.Driver, Authority: api.LaunchAuthority{Kind: "ticket", ID: start.RootTicketID}, Target: target, LaunchID: "launch-a", SpecID: "spec-a", GrantSetID: store.grants.ID, Generation: 1, PolicyGeneration: 1, CancellationEpoch: 1, RootLifeID: target.LifeID,
		StarterChain: []api.ID{}, OperationID: "launch-operation", RequestID: request.RequestID, RequestSHA256: request.RequestSHA256, RequestedBy: api.Actor{Kind: "human", ID: "human-a"}, OriginalRequest: original}
	record := api.LaunchPlanRecord{Reservation: r, Generation: 2, Phase: "sourced", Inputs: &inputs}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		t.Fatal("fixture sourced record failed contract validation")
	}
	if err := store.save("plan.json", record); err != nil {
		t.Fatal("cannot retain sourced plan")
	}
	cause := api.InternalIntent{ID: "planning-intent", Kind: api.InternalLaunchPlan, Config: r.Config, Actor: api.Actor{Kind: "service", ID: "service-a"}, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: store.effectID, Target: target, CancellationEpoch: r.CancellationEpoch}
	effect := api.EffectRecord{Effect: api.Effect{ID: store.effectID, OperationID: r.OperationID, Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}, Generation: 1, State: api.EffectClaimed, ClaimID: "claim-a", ClaimantID: "planner-a", ClaimExpiresAt: expires}
	if err := store.save("effect.json", effect); err != nil {
		t.Fatal("cannot retain current planning claim")
	}
	lease := api.HelperLease{ID: "helper-lease", UID: 12001, GID: 12001, ContainmentID: "containment-a", EndpointGeneration: 1}
	storage := api.LaunchStorage{ReservationID: r.ID, Target: target, LeaseID: lease.ID, WorkspaceID: "work-a", Home: api.PrivateHomeBinding{LifeID: target.LifeID, RootID: "home-root", Generation: 1, Home: api.PrivateHome{ID: "home-a", WorkspaceID: "work-a", HistoryID: "history-a", VendorDirectory: ".codex"}}}
	if err := store.save("storage.json", storage); err != nil {
		t.Fatal("cannot retain allocation registry")
	}
	payload, err := json.Marshal(lease)
	if err != nil {
		t.Fatal("cannot encode measured allocation")
	}
	store.events = []api.Event{{Schema: api.SchemaVersion, ID: "allocation-event", Seq: 1, Kind: "helper.allocated", Config: r.Config, Actor: cause.Actor, RequestedBy: r.RequestedBy, RequestID: r.RequestID, OperationID: r.OperationID, LifeID: target.LifeID, Run: target.Run, Payload: payload}}
	return &launchCase{service: service, backend: backend, store: store, helper: helper, control: control, clock: clock, profile: profile, grant: grant, target: target, key: key, material: material, directory: directory}
}

func (c *launchCase) plan(t *testing.T) api.LaunchPlanRecord {
	t.Helper()
	var record api.LaunchPlanRecord
	if err := c.store.read("plan.json", &record); err != nil {
		t.Fatal("cannot read fixture retained plan")
	}
	return record
}
func (c *launchCase) setPlan(t *testing.T, record api.LaunchPlanRecord) {
	t.Helper()
	if err := c.store.save("plan.json", record); err != nil {
		t.Fatal("cannot update fixture retained plan")
	}
}

func (c *launchCase) bind(t *testing.T, slot api.CredentialSlot, injection api.Injection) api.ProcessObservation {
	t.Helper()
	record := c.plan(t)
	r := record.Reservation
	var storage api.LaunchStorage
	if err := c.store.read("storage.json", &storage); err != nil {
		t.Fatal("cannot read allocated storage")
	}
	lease := api.HelperLease{ID: storage.LeaseID, UID: 12001, GID: 12001, ContainmentID: "containment-a", EndpointGeneration: 1}
	workspace := api.Workspace{ID: storage.WorkspaceID, ProjectID: record.Inputs.Sources.Project.ProjectID, Base: record.Inputs.Sources.Project.Base, Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main", Snapshot: c.store.putObject(t, "workspace-snapshot", "manifest", map[string]string{"snapshot": "actual synthetic fixture"}, r.OperationID)}
	materialized := api.Materialization{GrantSetID: c.store.grants.ID, Manifest: c.store.putObject(t, "materialized", "manifest", map[string]string{"state": "prepared"}, r.OperationID), Objects: []api.MaterializedObject{{GrantID: record.Inputs.Sources.Project.GrantID, SourceIdentity: "opened-source", DestinationIdentity: "opened-work", WorkspaceID: workspace.ID, SnapshotSHA256: workspace.Snapshot.SHA256}}}
	session := api.Session{ID: "session-a", Driver: c.grant.Driver, VendorVersion: "fixture-vendor-v1", HomeID: storage.Home.Home.ID, HistoryID: storage.Home.Home.HistoryID, LogicalCWD: "/work/main"}
	prompt := c.store.putObject(t, "prompt-object", "prompt", map[string]string{"prompt": "synthetic"}, r.OperationID)
	var original api.Request
	blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: r.OriginalRequest.ID})
	if err != nil || json.Unmarshal(blob.Data, &original) != nil {
		t.Fatal("cannot reload original launch")
	}
	var start api.StartRequest
	if json.Unmarshal(original.Params, &start) != nil {
		t.Fatal("cannot reload original start fields")
	}
	capture := api.CaptureBinding{ID: "capture-refused", Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID, HelperLeaseID: lease.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1, Status: "refused", Streams: []api.CaptureStreamBinding{}, Refusal: api.NotImplemented("lb-v2-admin", "fixture capture")}
	capture.Refusal.OperationID = r.OperationID
	policy, err := c.store.Policy(context.Background(), api.Scope{})
	if err != nil {
		t.Fatal("cannot load explicit fixture capture policy")
	}
	capture.RefusalPolicy = &api.CaptureRefusalPolicy{Allowed: policy.AllowCaptureRefusal, PolicyGeneration: policy.Generation, ApprovalID: policy.CaptureRefusalApprovalID}
	var capturePolicy *api.EffectivePolicy = &policy
	if c.registeredCapture {
		capture.Status, capture.Refusal, capture.RefusalPolicy = "registered", nil, nil
		capture.WorkerLeaseID, capture.EffectID, capture.ProducerID, capture.ProducerGeneration, capture.BootID = "capture-worker", "capture-effect", "capture-producer", "capture-generation", "capture-boot"
		capture.Supervisor = &c.profile.Runtime
		capture.Streams = []api.CaptureStreamBinding{{ID: "stdout-stream", Stream: "stdout", PipeID: "stdout-pipe"}, {ID: "stderr-stream", Stream: "stderr", PipeID: "stderr-pipe"}}
		capturePolicy = nil
	}
	plan := api.LaunchPlan{Reservation: r, Inputs: *record.Inputs, Lease: lease, Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: record.Inputs.Sources.Project, Workspace: workspace, Home: storage.Home, Materialization: materialized},
		Runner: api.RunnerPlan{Driver: c.grant.Driver, Executable: c.profile.Runtime, Argv: []string{"runtime-a", "synthetic"}, CWD: "/work/main", EnvironmentNames: []string{}, Prompt: prompt, Home: storage.Home.Home, Slot: slot, Session: session, AdapterVersion: "fixture-v1"}, Injection: injection, Budget: start.Budget, Capture: capture, CapturePolicy: capturePolicy}
	if err := api.ValidateLaunchPlan(plan); err != nil {
		t.Fatal("fixture plan failed contract validation")
	}
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, Capture: &capture, ID: r.SpecID, Target: r.Target, LaunchID: r.LaunchID, Backend: record.Inputs.Sources.Runtime.Backend, UIDLeaseID: lease.ID, Workspace: workspace, Materialization: materialized, Grants: plan.Inputs.Grants, Runner: &plan.Runner, Injection: injection, Budget: plan.Budget, EndpointGeneration: lease.EndpointGeneration, RuntimeManifest: record.Inputs.Sources.Runtime.Manifest, PolicyGeneration: r.PolicyGeneration}
	digest, err := valueDigest(spec)
	if err != nil {
		t.Fatal("cannot hash complete launch spec")
	}
	specObject := c.store.putObject(t, "spec-object", "launch_spec", spec, r.OperationID)
	handoff := api.PreparedSpecHandoff{Config: r.Config, Spec: spec, Original: specObject, SpecSHA256: digest, OperationID: r.OperationID, RequestID: r.RequestID, Cause: api.InternalIntent{ID: "register-intent", Kind: api.InternalHelperRegister, Config: r.Config, Actor: api.Actor{Kind: "service", ID: "service-a"}, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: "register-effect", Target: r.Target, CancellationEpoch: r.CancellationEpoch}}
	record.Plan, record.Handoff, record.Phase, record.Generation = &plan, &handoff, "spec_retained", 4
	c.setPlan(t, record)
	if err := c.store.save("handoff.json", handoff); err != nil {
		t.Fatal("cannot retain original spec handoff")
	}
	if c.beforeBind != nil {
		c.beforeBind(t, spec)
	}
	generation := c.startOwnedProcess(t)
	launchRecord := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq, Actor: api.Actor{Kind: "lane", ID: "lane-principal", LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role}, UIDLeaseID: lease.ID, HostUID: lease.UID, ProcessGeneration: generation, ContainmentID: lease.ContainmentID, GrantSetID: plan.Inputs.Grants.ID, GrantsSHA256: plan.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: lease.EndpointGeneration}
	recordDigest, err := valueDigest(launchRecord)
	if err != nil {
		t.Fatal("cannot hash retained launch identity")
	}
	binding := api.LaunchBindingRequest{Record: launchRecord, Prepared: api.PreparedLaunch{ID: "prepared-a", SpecSHA256: digest, Target: r.Target, ContainmentID: lease.ContainmentID, ProcessGeneration: generation, EndpointGeneration: lease.EndpointGeneration, GateID: "gate-a"},
		Identity: api.IdentityCommit{LaunchID: r.LaunchID, EventID: "identity-event", CommittedSeq: 2, RecordSHA256: recordDigest}, Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: storage.Home, Capture: capture}}
	if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {
		t.Fatal("fixture binding failed contract validation")
	}
	record.Plan, record.Handoff, record.Phase, record.Generation = &plan, &handoff, "opened", 5
	c.setPlan(t, record)
	if err := c.store.save("binding.json", binding); err != nil {
		t.Fatal("cannot retain committed identity binding")
	}
	c.store.lane = &api.Lane{Level: r.Level, Role: r.Role, LifeID: r.Target.LifeID, Run: r.Target.Run, Generation: 1, GrantSetID: plan.Inputs.Grants.ID, PolicyGeneration: r.PolicyGeneration, LaunchID: r.LaunchID, CancellationEpoch: r.CancellationEpoch, ProfileGrantID: slot.ProfileGrantID, Model: start.Model, Session: session, State: "running"}
	return api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: r.Target, ContainmentID: lease.ContainmentID, Generation: generation}, State: "running", Survivors: new(uint64), PromptStatus: "done"}
}

func (c *launchCase) startOwnedProcess(t *testing.T) string {
	t.Helper()
	process := exec.Command("/bin/sleep", "30")
	process.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	if err := process.Start(); err != nil {
		t.Fatal("cannot start owned quiescence control")
	}
	c.helper.process = process
	t.Cleanup(func() {
		if !c.helper.exited {
			if err := process.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error("cannot stop owned process by PID")
			}
			if err := process.Wait(); err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Error("cannot collect owned process")
				}
			}
			c.helper.exited = true
		}
	})
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", process.Process.Pid))
	if err != nil {
		t.Fatal("cannot measure owned process generation")
	}
	fields := strings.Fields(string(data[strings.LastIndex(string(data), ")")+2:]))
	if len(fields) < 20 {
		t.Fatal("owned process stat has invalid shape")
	}
	generation := fields[19]
	c.helper.processGeneration = generation
	return generation
}

func (c *launchCase) finish(t *testing.T, observation api.ProcessObservation) api.ProcessObservation {
	t.Helper()
	if err := c.helper.process.Process.Kill(); err != nil {
		t.Fatal("cannot stop owned process by PID")
	}
	if err := c.helper.process.Wait(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("cannot collect stopped process")
		}
	}
	c.helper.exited = true
	code := c.helper.process.ProcessState.ExitCode()
	zero := uint64(0)
	observation.State, observation.ExitCode, observation.Survivors = "exited", &code, &zero
	return observation
}
