//go:build linux && laneboss_root_canary && laneboss_gate_integration

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type MaterializationCanaryMetadata struct {
	Binding      api.InstalledBinding
	Agent        api.HelperLease
	Runtime      api.BlobRef
	RuntimeBytes []byte
	Budget       api.Budget
	TaskPeakOnly bool
	WithCopies   bool
}

type MaterializationCanarySource struct {
	Stage      api.LaunchDataStage
	Allocation api.HelperLeaseRequest
	Policy     api.EffectivePolicy
	Objects    []MaterializationCanaryObject
}

type MaterializationCanaryObject struct {
	Ref  api.BlobRef
	Data []byte
}

type materializationCanaryHelper struct {
	*admin.Service
	exchange    func(string, any) error
	interrupted bool
}

func (h *materializationCanaryHelper) PrepareDataWorker(ctx context.Context, request api.StorageProjectionRequest) (api.PreparedLaunch, error) {
	if !h.interrupted {
		h.interrupted = true
		if err := h.exchange("interrupt", request); err != nil {
			return api.PreparedLaunch{}, err
		}
	}
	return h.Service.PrepareDataWorker(ctx, request)
}

// ExerciseMaterializationCanary runs the original stage owner as the actual
// service UID. The exchange only installs retained source bytes or repairs the
// deliberately missing native cgroup; helper IPC, identity and worker are real.
func ExerciseMaterializationCanary(t *testing.T, meta MaterializationCanaryMetadata, exchange func(string, any) error) {
	t.Helper()
	if os.Geteuid() == 0 || uint32(os.Geteuid()) != meta.Binding.ServiceUID {
		t.Fatal("materialization writer must use its installed unprivileged identity")
	}
	options := fx.DataOptions{Config: meta.Binding.Config, Clock: fx.Clock{}, ParentTTL: time.Minute,
		Agent: meta.Agent, Runtime: meta.Runtime, RuntimeBytes: meta.RuntimeBytes, Budget: meta.Budget}
	if meta.WithCopies {
		options.ReadOnlyProject = true
		assembly, objects := materializationCanaryAssembly(t)
		options.ExtraObjects = append(options.ExtraObjects, objects...)
		raw := fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
			{Path: "bundle", Kind: "directory", Mode: 0700},
			{Path: "bundle/nested", Kind: "directory", Mode: 0700},
			{Path: "bundle/nested/input.bin", Kind: "file", Mode: 0600, Assembly: &assembly},
			{Path: "bundle/link", Kind: "symlink", Mode: 0777, LinkTarget: "nested/input.bin"},
			{Path: "fixed", Kind: "directory", Mode: 0700},
			{Path: "fixed/input.bin", Kind: "file", Mode: 0600, Assembly: &assembly},
		}})
		for _, view := range []struct{ relative, access, destination string }{
			{"bundle", "rw", "/data/parent"}, {"fixed/input.bin", "ro", "/data/fixed"},
		} {
			// Independent source enrollments permit independent root ceilings;
			// the helper still validates their identical immutable tree bytes.
			source := api.BlobRef{ID: fx.ID(t), Class: "manifest", SHA256: fx.Digest(raw), Bytes: int64(len(raw))}
			options.ExtraObjects = append(options.ExtraObjects, api.ObjectWrite{ObjectKey: source.ID, Class: source.Class,
				Bytes: raw, SHA256: source.SHA256, Origin: "service"})
			options.ExtraData = append(options.ExtraData, api.DataGrant{SourceObjectID: source.ID, SourceSHA256: source.SHA256,
				RelativePath: view.relative, Access: view.access, Delivery: "copy", Destination: view.destination,
				ExpiresAt: fx.Expiry(), HistoryScope: "snapshot"})
		}
	}
	d := datafx.NewData(t, options)
	f := d.F
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	inventory := f.Retain(t, "manifest", []byte("[]"), f.Execution.Actor, "")
	ownership := f.Retain(t, "manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}), f.Execution.Actor, "")
	cause := f.Intent(t, api.InternalOrgBootstrap)
	snapshot := api.OrgSnapshot{Config: f.Deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: inventory.SHA256},
		Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, OwnershipManifest: ownership, Renderer: d.Stage.Plan.Executable,
		PublishedBy: fx.ID(t), PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{OrgSnapshots: []api.OrgSnapshot{snapshot}}}); err != nil {
		t.Fatal(err)
	}
	policy, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	source := MaterializationCanarySource{Stage: d.Stage, Policy: policy}
	allocated, err := f.State.Effect(ctx, f.Execution, d.AgentRequest.Cause.EffectID)
	if err != nil || allocated.Outcome == nil || allocated.Outcome.HelperLease == nil || *allocated.Outcome.HelperLease != meta.Agent || allocated.Effect.HelperAllocate == nil {
		t.Fatal("native fixture lost its actual retained allocation", err)
	}
	source.Allocation = *allocated.Effect.HelperAllocate
	seen := map[api.ID]bool{}
	readObject := func(ref api.BlobRef) []byte {
		var raw []byte
		for int64(len(raw)) < ref.Bytes {
			chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(raw)), Limit: api.MaxChunkBytes})
			if err != nil || len(chunk.Data) == 0 {
				t.Fatal("cannot read complete retained native source", err)
			}
			raw = append(raw, chunk.Data...)
		}
		if int64(len(raw)) != ref.Bytes || fx.Digest(raw) != ref.SHA256 {
			t.Fatal("native source bytes differ from retained pins")
		}
		if !seen[ref.ID] {
			seen[ref.ID] = true
			source.Objects = append(source.Objects, MaterializationCanaryObject{Ref: ref, Data: raw})
		}
		return raw
	}
	refs := []api.BlobRef{d.Stage.Inputs.Sources.Project.Object}
	for _, grant := range d.Stage.Inputs.Grants.Data {
		metadata, err := f.State.ObjectMetadata(ctx, f.Execution, grant.SourceObjectID)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, metadata.Ref)
	}
	for _, ref := range refs {
		if seen[ref.ID] {
			continue
		}
		raw := readObject(ref)
		var manifest api.ObjectManifest
		if err := api.DecodeObject(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		for _, entry := range manifest.Entries {
			if entry.Content != nil {
				readObject(*entry.Content)
			}
			if entry.Assembly != nil {
				for _, part := range entry.Assembly.Parts {
					if !seen[part.ID] {
						readObject(part)
					}
				}
			}
		}
	}
	if err := exchange("source", source); err != nil {
		t.Fatal(err)
	}
	var launchEnrollment *api.BlobRef
	if meta.WithCopies {
		var runtime api.RuntimeManifest
		if err := api.DecodeObject(meta.RuntimeBytes, &runtime); err != nil {
			t.Fatal(err)
		}
		project := d.Stage.Inputs.Sources.Project
		enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: f.Deps.Config, Generation: 1,
			Projects: []api.ProjectEnrollment{{ID: project.EnrollmentID, Generation: project.Generation, ProjectID: project.ProjectID,
				Object: project.Object, Base: project.Base, HistoryScope: project.HistoryScope}},
			Runtimes: []api.LaunchRuntime{d.Stage.Inputs.Sources.Runtime}, Supervisor: &runtime.Bootstrap}
		raw := fx.JSON(t, enrollment)
		ref := api.BlobRef{ID: "native-launch-enrollment", Class: "manifest", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
		intent := f.Intent(t, api.InternalOrgBootstrap)
		if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &intent, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
			ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
			t.Fatal("native fixture enrollment retention failed", err)
		}
		launchEnrollment = &ref
	}
	helper, err := admin.New(admin.Dependencies{Config: meta.Binding.Config, Store: f.State, ServiceUID: meta.Binding.ServiceUID,
		ArtifactSHA256: meta.Binding.ArtifactSHA256, Version: meta.Binding.ServiceVersion, Protocol: api.Protocol, Schema: api.SchemaVersion,
		RuntimeManifest: meta.Runtime, LaunchEnrollment: launchEnrollment})
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &materializationCanaryHelper{Service: helper, exchange: exchange}
	peers, err := peerlinux.New(helper)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.New(identity.Dependencies{Peers: peers, Registry: helper, Store: f.State, Clock: f.Deps.Clock, Workers: helper})
	if err != nil {
		t.Fatal(err)
	}
	host := &Server{options: Options{Config: f.Deps.Config}, deps: Dependencies{Store: f.State, Clock: f.Deps.Clock, Binding: meta.Binding, Authenticator: auth},
		verified: true, bound: true, controller: fx.ID(t), flights: map[string]chan struct{}{}, connections: map[api.ID]*connectionContext{}}
	host.runtime = api.RuntimeServices{Store: f.State, Helper: wrapped, Identity: auth}
	defer func() {
		if err := host.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx = api.WithEffectLease(ctx, f.Claim)
	attempt := &effectAttempt{kind: "PlanLaunch"}
	ctx = api.WithHelperReasonObserver(ctx, attempt.observeHelperReason)
	_, err = host.MaterializationStage(ctx, d.Request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown {
		t.Fatal("first actual planning preparation did not reach its native interruption", attempt.errorReason(err), err)
	}
	if err := exchange("repair", d.Request); err != nil {
		t.Fatal(err)
	}
	stage, err := host.MaterializationStage(ctx, d.Request)
	if err != nil {
		t.Fatal("original planning stage did not resume through the real helper", attempt.errorReason(err), err)
	}
	if meta.WithCopies {
		module, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: f.State, Helper: wrapped,
			Controls: host, Launcher: &materializationCanaryLauncher{}, Clock: f.Deps.Clock})
		if err != nil {
			t.Fatal(err)
		}
		data, err := module.MaterializeLaunch(ctx, d.Request)
		if err != nil {
			t.Fatal("three-copy real store/dataworker/helper materialization failed", err)
		}
		if len(data.Materialization.Objects) != 3 {
			t.Fatal("materialization omitted additional granted copies")
		}
		if err := exchange("verify-copies", stage.ID); err != nil {
			t.Fatal(err)
		}
	}
	result, err := host.AwaitMaterialization(ctx, stage.ID)
	if err != nil {
		t.Fatal("real helper materialization did not complete after resume", attempt.errorReason(err), err)
	}
	if result.StageID != stage.ID || result.Observation.ExitCode == nil || *result.Observation.ExitCode != 0 || result.Observation.Survivors == nil || *result.Observation.Survivors != 0 {
		t.Fatal("real materialization lost its measured original completion")
	}
	if err := exchange("verify", result); err != nil {
		t.Fatal(err)
	}
	if child, err := f.State.Effect(ctx, f.Execution, stage.Worker.EffectID); err != nil || child.State != api.EffectCompleted || child.Outcome == nil {
		t.Fatal("real measured worker was not completed in the writer", err)
	}
	if meta.WithCopies {
		if err := exchange("collect-copies", stage.ID); err != nil {
			t.Fatal(err)
		}
		return
	}
	if meta.TaskPeakOnly {
		return
	}
	captureCause := f.Intent(t, api.InternalLaunchPlan)
	captureCause.LogicalTurnID = f.Claim.Record.Effect.Context.LogicalTurnID
	captureRequest := api.CaptureRegistrationRequest{Claim: d.Request.Claim, Cause: captureCause,
		ReservationID: f.Reservation.ID, HelperLeaseID: meta.Agent.ID, WorkerLeaseID: fx.ID(t)}
	captureInput := f.Retain(t, "manifest", fx.JSON(t, captureRequest), f.Execution.Actor, f.Reservation.Target.LifeID)
	captureWorker := api.WorkerLease{ID: captureRequest.WorkerLeaseID, Kind: "capture_supervisor", Target: f.Reservation.Target,
		OperationID: f.Reservation.OperationID, EffectID: captureCause.EffectID, Input: captureInput, RuntimeManifest: meta.Runtime,
		GrantSetID: f.Reservation.GrantSetID, Generation: result.Data.Home.Generation, ExpiresAt: f.Claim.ExpiresAt}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &captureCause, Writes: api.StateWrites{WorkerLeases: []api.WorkerLease{captureWorker}}}); err != nil {
		t.Fatal("capture fixture could not retain its actual request", err)
	}
	capture, err := helper.RegisterCapture(ctx, captureRequest)
	if err != nil {
		t.Fatal("capture registration after real materialization failed", attempt.errorReason(err), err)
	}
	if capture.Status != "registered" || capture.HelperLeaseID != meta.Agent.ID || capture.ReservationID != f.Reservation.ID {
		t.Fatal("capture did not register against the original returned allocation")
	}
	if err := exchange("capture", capture); err != nil {
		t.Fatal(err)
	}
	t.Log("real helper data_prepare and data_gate completed the retained materialization stage after native retry")
}

// Generate real bounded artifact bytes and hash their ordered concatenation,
// as the production archive writer does. Reusing an immutable part keeps the
// fixture's source transport small; both helper and worker rehash all 65 MiB.
func materializationCanaryAssembly(t testing.TB) (api.ObjectAssembly, []api.ObjectWrite) {
	t.Helper()
	seed := []byte("deterministic materialization assembly part\n")
	part := bytes.Repeat(seed, (api.MaxChunkBytes+len(seed)-1)/len(seed))[:api.MaxChunkBytes]
	ref := api.BlobRef{ID: "canary-assembly-" + api.ID(manifest.Hash(part)[:32]), Class: "artifact",
		SHA256: manifest.Hash(part), Bytes: int64(len(part))}
	assembly := api.ObjectAssembly{Parts: []api.BlobRef{}}
	whole := sha256.New()
	for assembly.Bytes < api.MaxObjectBytes+(1<<20) {
		written, err := io.Copy(whole, bytes.NewReader(part))
		if err != nil || written != ref.Bytes {
			t.Fatal("cannot hash complete generated assembly part", err)
		}
		assembly.Bytes += written
		assembly.Parts = append(assembly.Parts, ref)
	}
	assembly.SHA256 = api.Digest(hex.EncodeToString(whole.Sum(nil)))
	if err := manifest.Assembly(assembly); err != nil {
		t.Fatal("generated native assembly violates the production format", err)
	}
	t.Logf("generated native assembly: bytes=%d parts=%d part_bytes=%d sha256=%s", assembly.Bytes, len(assembly.Parts), ref.Bytes, assembly.SHA256)
	return assembly, []api.ObjectWrite{{ObjectKey: ref.ID, Class: ref.Class, Bytes: part, SHA256: ref.SHA256, Origin: "service"}}
}

// MaterializeLaunch delegates execution to the real service control above;
// this unused constructor dependency cannot supply a launcher result.
type materializationCanaryLauncher struct{ api.Launcher }
