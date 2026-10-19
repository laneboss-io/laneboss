//go:build linux

package testfx

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/store"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	grantmanifest "laneboss.io/laneboss/internal/v2/grants/manifest"
)

// DataFixture supplies explicit helper/kernel fixtures for component tests.
// Every digest is computed from actual retained bytes, and all reservation,
// stage, claim, identity, acknowledgement and completion writes use the store.
// It does not execute a native worker or prove an installed boundary.
type DataFixture struct {
	F            *Fixture
	Request      api.LaunchDataRequest
	Stage        api.LaunchDataStage
	Projection   api.StorageProjection
	Allocation   api.HelperLease
	Endpoint     api.InstalledBinding
	Handoff      api.PreparedSpecHandoff
	Prepared     api.PreparedLaunch
	Binding      api.LaunchBindingRequest
	Worker       api.Scope
	Content      []byte
	AgentRequest api.HelperLeaseRequest
}

type DataOptions struct {
	Clock           api.Clock
	ParentTTL       time.Duration
	Config          string
	Agent           api.HelperLease
	Runtime         api.BlobRef
	RuntimeBytes    []byte
	Budget          api.Budget
	ExtraData       []api.DataGrant
	ExtraObjects    []api.ObjectWrite
	ReadOnlyProject bool
}

// NewDataWithResolver keeps shared store fixtures independent of the grants
// service. The materialization subpackage supplies the real reserved resolver.
func NewDataWithResolver(t testing.TB, newResolver func(*Fixture) (api.GrantResolver, error), options ...DataOptions) *DataFixture {
	t.Helper()
	if newResolver == nil {
		t.Fatal("data fixture requires its grants resolver factory")
	}
	if len(options) > 1 {
		t.Fatal("data fixture accepts one clock/deadline option")
	}
	config := "launch-fixture"
	if len(options) == 1 && options[0].Config != "" {
		config = options[0].Config
	}
	f := New(t, config)
	if len(options) == 1 {
		if options[0].Clock == nil || options[0].ParentTTL <= 0 {
			t.Fatal("data fixture requires a clock and positive parent TTL")
		}
		if options[0].Budget != (api.Budget{}) {
			f.Start.Budget = options[0].Budget
			f.Admit(t, "lane.start", f.Start)
		}
		if err := f.State.Close(); err != nil {
			t.Fatal(err)
		}
		f.Deps.Clock = options[0].Clock
		var err error
		f.State, err = store.New(f.Deps)
		if err != nil {
			t.Fatal(err)
		}
	}
	content := []byte("materialization source bytes " + string(ID(t)))
	contentRef := api.BlobRef{ID: ID(t), Class: "artifact", SHA256: Digest(content), Bytes: int64(len(content))}
	manifest := JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: ".", Kind: "directory", Mode: 0700}, {Path: "input.txt", Kind: "file", Mode: 0600, Content: &contentRef}}})
	source := api.BlobRef{ID: ID(t), Class: "manifest", SHA256: Digest(manifest), Bytes: int64(len(manifest))}
	f.Ceiling.Generation++
	f.Ceiling.Data[0].SourceObjectID, f.Ceiling.Data[0].SourceSHA256 = source.ID, source.SHA256
	if len(options) == 1 {
		if options[0].ReadOnlyProject {
			f.Start.Grants.Data[0].Access = "ro"
		}
		for _, extra := range options[0].ExtraData {
			extra.ID = ID(t)
			parent := extra
			// The fixture enrolls each immutable source root. The requested
			// view is selected once, relative to that root, by real issuance.
			parent.RelativePath = "."
			f.Ceiling.Data = append(f.Ceiling.Data, parent)
			f.Start.Grants.Data = append(f.Start.Grants.Data, api.DataGrantRequest{ParentGrantID: extra.ID,
				RelativePath: extra.RelativePath, Access: extra.Access, Delivery: extra.Delivery, Destination: extra.Destination,
				Delegate: extra.Delegate, ExpiresAt: extra.ExpiresAt, PublicationID: extra.PublicationID})
		}
	}
	for _, expiry := range grantmanifest.Expiries(f.Ceiling) {
		value, err := grantmanifest.Time(expiry)
		if err != nil {
			t.Fatal(err)
		}
		limit, err := grantmanifest.Time(f.Ceiling.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if value.After(limit) {
			f.Ceiling.ExpiresAt = expiry
		}
	}
	f.Ceiling.SHA256 = ""
	sealed, err := api.CanonicalJSON(JSON(t, f.Ceiling))
	if err != nil {
		t.Fatal(err)
	}
	f.Ceiling.SHA256 = Digest(sealed)
	cause := f.Intent(t, api.InternalOrgBootstrap)
	objects := []api.ObjectWrite{}
	for _, item := range []struct {
		ref api.BlobRef
		raw []byte
	}{{contentRef, content}, {source, manifest}} {
		objects = append(objects, api.ObjectWrite{ObjectKey: item.ref.ID, Class: item.ref.Class, Bytes: item.raw, SHA256: item.ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}})
	}
	if len(options) == 1 {
		for _, object := range options[0].ExtraObjects {
			object.ACL = api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}
			objects = append(objects, object)
		}
	}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Grants: []api.GrantSet{f.Ceiling}, Objects: objects}}); err != nil {
		t.Fatal("materialization source setup failed", err)
	}
	f.Admit(t, "lane.start", f.Start)
	if len(options) == 1 {
		f.Reserve(t, api.Timestamp(f.Deps.Clock.Now().Add(options[0].ParentTTL).UTC().Format(time.RFC3339Nano)))
	} else {
		f.Reserve(t)
	}
	input := f.SourceTransaction(t)
	resolver, err := newResolver(f)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := resolver.Resolve(context.Background(), f.Execution, api.GrantResolveRequest{ReservationID: f.Reservation.ID})
	if err != nil {
		t.Fatal("materialization fixture reserved grant resolution failed", err)
	}
	input.Writes.Grants = []api.GrantSet{issued}
	input.Writes.LaunchPlans[0].Inputs.Grants = issued
	input.Writes.LaunchPlans[0].Inputs.Sources.Project.GrantID = issued.Data[0].ID
	input.Writes.LaunchPlans[0].Inputs.Sources.Project.Base = string(source.SHA256)
	input.Writes.Grants[0].Generation = 1
	input.Writes.LaunchPlans[0].Inputs.Grants.Generation = 1
	input.Events[0] = f.Event(t, "grants.issued", api.GrantEvent{GrantSet: input.Writes.Grants[0]})
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: api.Executable{ID: ID(t), SHA256: digest, Version: release.Version}, Bootstrap: api.Executable{ID: ID(t), SHA256: Digest([]byte(ID(t))), Version: "component-v1"}, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}}
	runtimeRef := f.Retain(t, "manifest", JSON(t, runtime), f.Execution.Actor, "")
	if len(options) == 1 && options[0].Runtime.ID != "" {
		provided := options[0]
		if Digest(provided.RuntimeBytes) != provided.Runtime.SHA256 || int64(len(provided.RuntimeBytes)) != provided.Runtime.Bytes {
			t.Fatal("native fixture runtime lost its measured bytes")
		}
		var enrolled api.RuntimeManifest
		if api.DecodeObject(provided.RuntimeBytes, &enrolled) != nil || enrolled.Artifact.SHA256 != digest {
			t.Fatal("native fixture runtime is not the executing artifact")
		}
		input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Executable = enrolled.Artifact
		cause := f.Intent(t, api.InternalOrgBootstrap)
		if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause,
			Writes: api.StateWrites{Objects: []api.ObjectWrite{{ObjectKey: provided.Runtime.ID, Class: provided.Runtime.Class, Bytes: provided.RuntimeBytes, SHA256: provided.Runtime.SHA256, Origin: "service", ACL: api.ObjectACL{Config: config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
			t.Fatal(err)
		}
		runtimeRef = provided.Runtime
	}
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Manifest = runtimeRef
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal("materialization sourcing failed", err)
	}
	f.Record = input.Writes.LaunchPlans[0]
	allocateCause := f.Intent(t, api.InternalHelperAllocate)
	allocateCause.Actor = f.Claim.Record.Effect.Context.Actor
	allocateCause.EffectID = ID(t)
	effect := api.Effect{ID: allocateCause.EffectID, OperationID: f.Reservation.OperationID, Context: &allocateCause, HelperAllocate: &api.HelperLeaseRequest{ReservationID: f.Reservation.ID, Cause: allocateCause, Config: f.Deps.Config, LifeID: f.Reservation.Target.LifeID, Backend: f.Record.Inputs.Sources.Runtime.Backend, Budget: f.Start.Budget, RuntimeManifestID: runtimeRef.ID}}
	parent := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	agent := api.HelperLease{ID: ID(t), UID: uint32(os.Geteuid()) + 1000, GID: uint32(os.Getegid()) + 1000, ContainmentID: ID(t), EndpointGeneration: 1}
	if len(options) == 1 && options[0].Agent.ID != "" {
		agent = options[0].Agent
	}
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", HelperLease: &agent}); err != nil {
		t.Fatal(err)
	}
	d := &DataFixture{F: f, Content: content, AgentRequest: *effect.HelperAllocate, Request: api.LaunchDataRequest{ReservationID: f.Reservation.ID, GrantSetID: f.Reservation.GrantSetID, LeaseID: agent.ID, Claim: api.PlanningClaim(f.Reservation.ID, f.Claim)}}
	d.Stage, err = f.State.LaunchDataStage(context.Background(), f.Execution, d.Request)
	if err != nil {
		t.Fatal("materialization reservation failed", err)
	}
	workspace := ID(t)
	home := api.PrivateHomeBinding{LifeID: f.Reservation.Target.LifeID, RootID: ID(t), Generation: 1, Home: api.PrivateHome{ID: ID(t), WorkspaceID: workspace, VendorDirectory: "vendor", HistoryID: ID(t)}}
	evidence := f.Retain(t, "manifest", JSON(t, []api.ID{d.Stage.ID, workspace, home.RootID}), f.Execution.Actor, f.Reservation.Target.LifeID)
	d.Projection = api.StorageProjection{StageID: d.Stage.ID, WorkerLeaseID: d.Stage.Worker.ID, Storage: api.LaunchStorage{ReservationID: f.Reservation.ID, Target: f.Reservation.Target, LeaseID: agent.ID, WorkspaceID: workspace, Home: home}, OpenToken: ID(t), Generation: 1, SourceIdentity: "component-source:" + string(source.ID), WorkspaceIdentity: "component-workspace:" + string(workspace), HomeIdentity: "component-home:" + string(home.RootID), Evidence: evidence}
	d.componentCopies(t)
	d.Allocation = api.HelperLease{ID: ID(t), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), ContainmentID: ID(t), EndpointGeneration: 1}
	d.Endpoint = api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/runtime/laneboss-worker.sock", ArtifactSHA256: digest, ServiceVersion: release.Version, Backend: f.Record.Inputs.Sources.Runtime.Backend, LaunchID: d.Stage.WorkerLaunchID, Target: &f.Reservation.Target, WorkerLeaseID: d.Stage.Worker.ID}
	return d
}

// DataForLaunch attaches explicit helper/kernel component fixtures to an
// already sourced real planner reservation. It never replaces store reads.
func DataForLaunch(t testing.TB, f *Fixture, request api.LaunchDataRequest) *DataFixture {
	t.Helper()
	if request.Claim == (api.LaunchClaim{}) {
		request.Claim = api.PlanningClaim(request.ReservationID, f.Claim)
	}
	var err error
	f.Record, err = f.State.LaunchPlan(context.Background(), f.Execution, request.ReservationID)
	if err != nil || f.Record.Inputs == nil {
		t.Fatal("component data fixture has no real sourced reservation", err)
	}
	f.Reservation = f.Record.Reservation
	source := f.Record.Inputs.Sources.Project.Object
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	agent := api.HelperLease{ID: request.LeaseID}
	d := &DataFixture{F: f, Request: request}
	d.Stage, err = f.State.LaunchDataStage(context.Background(), f.Execution, d.Request)
	if err != nil {
		t.Fatal("materialization reservation failed", err)
	}
	workspace := ID(t)
	vendor := ".codex"
	if f.Record.Inputs.Sources.Runtime.Driver == api.DriverClaudock {
		vendor = ".claude"
	}
	home := api.PrivateHomeBinding{LifeID: f.Reservation.Target.LifeID, RootID: ID(t), Generation: 1, Home: api.PrivateHome{ID: ID(t), WorkspaceID: workspace, VendorDirectory: vendor, HistoryID: ID(t)}}
	evidence := f.Retain(t, "manifest", JSON(t, []api.ID{d.Stage.ID, workspace, home.RootID}), f.Execution.Actor, f.Reservation.Target.LifeID)
	d.Projection = api.StorageProjection{StageID: d.Stage.ID, WorkerLeaseID: d.Stage.Worker.ID, Storage: api.LaunchStorage{ReservationID: f.Reservation.ID, Target: f.Reservation.Target, LeaseID: agent.ID, WorkspaceID: workspace, Home: home}, OpenToken: ID(t), Generation: 1, SourceIdentity: "component-source:" + string(source.ID), WorkspaceIdentity: "component-workspace:" + string(workspace), HomeIdentity: "component-home:" + string(home.RootID), Evidence: evidence}
	d.componentCopies(t)
	d.Allocation = api.HelperLease{ID: ID(t), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), ContainmentID: ID(t), EndpointGeneration: 1}
	d.Endpoint = api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/runtime/laneboss-worker.sock", ArtifactSHA256: digest, ServiceVersion: release.Version, Backend: f.Record.Inputs.Sources.Runtime.Backend, LaunchID: d.Stage.WorkerLaunchID, Target: &f.Reservation.Target, WorkerLeaseID: d.Stage.Worker.ID}
	return d
}

func (d *DataFixture) Seal(t testing.TB) {
	t.Helper()
	f, ctx := d.F, context.Background()
	var err error
	d.Stage, err = f.State.SealDataStage(ctx, f.Execution, d.Stage.ID, d.Projection, d.Allocation)
	if err != nil {
		t.Fatal("materialization input sealing failed", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: d.Stage.Worker.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: d.Stage.Worker.ExpiresAt})
	if err != nil {
		t.Fatal("materialization child claim failed", err)
	}
	d.Stage, err = f.State.RecordDataClaim(ctx, f.Execution, d.Stage.ID, claim)
	if err != nil {
		t.Fatal("materialization child claim retention failed", err)
	}
	d.Handoff, err = f.State.DataHandoff(ctx, f.Execution, d.Stage.ID, d.Endpoint)
	if err != nil {
		t.Fatal("materialization spec handoff failed", err)
	}
}

// These identities are declared component inputs, as are the original three
// roots above. Native canaries replace this projection with real helper pins.
func (d *DataFixture) componentCopies(t testing.TB) {
	t.Helper()
	var entries []api.DataCopyProjection
	for _, grant := range d.Stage.Inputs.Grants.Data {
		if grant.ID == d.Stage.Inputs.Sources.Project.GrantID {
			continue
		}
		meta, err := d.F.State.ObjectMetadata(context.Background(), d.F.Execution, grant.SourceObjectID)
		if err != nil {
			t.Fatal(err)
		}
		chunk, err := d.F.State.Blob(context.Background(), d.F.Execution, api.BlobReadRequest{ObjectID: grant.SourceObjectID, Limit: api.MaxChunkBytes})
		if err != nil || Digest(chunk.Data) != grant.SourceSHA256 || int64(len(chunk.Data)) != meta.Ref.Bytes {
			t.Fatal("component copy lost its actual source bytes", err)
		}
		var source api.ObjectManifest
		if err := api.DecodeObject(chunk.Data, &source); err != nil {
			t.Fatal(err)
		}
		selected, file, err := grantmanifest.CopySelection(source, grant.RelativePath)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, api.DataCopyProjection{Grant: grant, Source: meta.Ref, Manifest: selected, File: file,
			WorkspaceID: ID(t), SourceIdentity: "component-source:" + string(grant.ID), DestinationIdentity: "component-copy:" + string(grant.ID)})
	}
	var err error
	d.Projection.Copies, err = api.EncodeDataCopyProjections(entries)
	if err != nil {
		t.Fatal(err)
	}
}

func (d *DataFixture) Open(t testing.TB) {
	t.Helper()
	d.Seal(t)
	d.Prepared = api.PreparedLaunch{ID: ID(t), SpecSHA256: d.Handoff.SpecSHA256, Target: d.Stage.Reservation.Target, ContainmentID: d.Allocation.ContainmentID, ProcessGeneration: "component-boot:" + string(ID(t)), EndpointGeneration: 1, GateID: ID(t)}
	var err error
	d.Binding, err = d.F.State.BindDataWorker(context.Background(), d.F.Execution, d.Stage.ID, d.Prepared)
	if err != nil {
		t.Fatal("materialization prepared binding failed", err)
	}
	process := api.ProcessHandle{ID: d.Stage.WorkerLaunchID, Target: d.Stage.Reservation.Target, ContainmentID: d.Allocation.ContainmentID, Generation: d.Prepared.ProcessGeneration}
	d.Stage, err = d.F.State.RecordDataProcess(context.Background(), d.F.Execution, d.Stage.ID, process)
	if err != nil {
		t.Fatal("materialization process retention failed", err)
	}
	d.BindWorker(t)
}

func (d *DataFixture) BindWorker(t testing.TB) {
	t.Helper()
	r := d.Binding.Record
	connection := &Connection{Identity: ID(t), Endpoint: d.Endpoint, Verified: &Peer{FactsValue: api.PeerFacts{HostUID: d.Allocation.UID, HostGID: d.Allocation.GID, HostPID: os.Getpid(), ContainmentID: d.Allocation.ContainmentID, ProcessGeneration: r.ProcessGeneration}}}
	d.Worker = api.Scope{Config: r.Config, Actor: r.Actor, LaunchID: r.ID, EndpointGeneration: r.EndpointGeneration, PolicyGeneration: r.PolicyGeneration, Connection: connection, Source: "worker", Frame: &Frame{Raw: []byte("component frame")}}
}

func (d *DataFixture) Result(t testing.TB) (api.LaunchData, []byte) {
	t.Helper()
	input, err := d.F.State.WorkerInput(context.Background(), d.Worker, api.WorkerInputRequest{LeaseID: d.Stage.Worker.ID})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Output api.BlobRef `json:"output"`
	}
	if err := json.Unmarshal(input.Bytes, &body); err != nil {
		t.Fatal(err)
	}
	s, storage := d.Stage, d.Stage.Storage.Storage
	data := api.LaunchData{ReservationID: s.Reservation.ID, Target: s.Reservation.Target, LeaseID: s.AgentLeaseID, Source: s.Inputs.Sources.Project, Home: storage.Home, Workspace: api.Workspace{ID: storage.WorkspaceID, ProjectID: s.Inputs.Sources.Project.ProjectID, Base: s.Inputs.Sources.Project.Base, Branch: "lane/" + string(s.Reservation.Target.LifeID), LogicalCWD: "/work/main", Snapshot: body.Output}, Materialization: api.Materialization{GrantSetID: s.Reservation.GrantSetID, Manifest: body.Output, Objects: []api.MaterializedObject{{GrantID: s.Inputs.Sources.Project.GrantID, SourceIdentity: s.Storage.SourceIdentity, DestinationIdentity: s.Storage.WorkspaceIdentity, SnapshotSHA256: body.Output.SHA256, WorkspaceID: storage.WorkspaceID}}}}
	raw, err := api.CanonicalJSON(JSON(t, data))
	if err != nil {
		t.Fatal(err)
	}
	return data, raw
}

func (d *DataFixture) Submission(raw []byte) api.WorkerResultSubmission {
	return api.WorkerResultSubmission{LeaseID: d.Stage.Worker.ID, ExpectedGeneration: d.Stage.Worker.Generation, InputSHA256: d.Stage.Worker.Input.SHA256, Result: raw}
}

func (d *DataFixture) HostBinding() api.InstalledBinding {
	binding := d.Endpoint
	binding.Class, binding.LaunchID, binding.Target, binding.WorkerLeaseID = api.EndpointHuman, "", nil, ""
	binding.Socket = filepath.Join(d.F.Deps.Directory, "control.sock")
	return binding
}
