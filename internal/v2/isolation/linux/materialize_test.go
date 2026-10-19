package linux

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Metadata stages only. Held descriptors, real child claims, process identities
// and copy/Git results must come from the installed service/helper/worker.
func materializeMeta(t *testing.T) (api.LaunchDataStage, api.LaunchSpec) {
	t.Helper()
	r, _ := planMeta(t)
	p := r.Plan
	grants := p.Inputs.Grants
	grants.ID, grants.ParentLifeID = "job-grants", r.Reservation.Target.LifeID
	grants.SHA256 = fixtureBlob("job-grants").SHA256
	grants.Resources, grants.Secrets, grants.Profiles = []api.ResourceGrant{}, []api.SecretGrant{}, []api.ProfileGrant{}
	grants.Network, grants.Channels = []api.NetworkGrant{}, []api.ChannelGrant{}
	source := grants.Data[0]
	source.ID, source.ParentGrantID = "job-source", p.Inputs.Sources.Project.GrantID
	source.Destination, source.Access, source.Delivery = "/job/source", "ro", "bind_ro"
	grants.Data = []api.DataGrant{source}
	lease := api.WorkerLease{ID: "child-worker", Kind: "materialize", Target: r.Reservation.Target,
		OperationID: r.Reservation.OperationID, EffectID: "child-effect", Generation: 1,
		Input: metaBlob("materialize-input", "materialize_input"), RuntimeManifest: p.Inputs.Sources.Runtime.Manifest,
		GrantSetID: grants.ID, ExpiresAt: "2100-01-01T00:00:00Z", ConsumedBy: "materialize-launch"}
	worker := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: lease.Kind,
		Executable: api.Executable{ID: "laneboss-worker", Version: "fixture-v1", SHA256: fixtureBlob("worker-binary").SHA256},
		Argv:       []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(lease.ID)},
		Input:      lease.Input, GrantSetID: grants.ID, Budget: p.Budget}
	cause := api.InternalIntent{ID: "child-intent", Kind: api.InternalObjectRetain, Config: r.Reservation.Config,
		Actor: api.Actor{Kind: "service", ID: "outbox"}, RequestedBy: r.Reservation.RequestedBy, Target: lease.Target,
		CauseOperationID: lease.OperationID, CauseRequestID: r.Reservation.RequestID, EffectID: lease.EffectID,
		CancellationEpoch: r.Reservation.CancellationEpoch}
	claim := api.EffectLease{ClaimID: "child-claim", ExpiresAt: lease.ExpiresAt,
		Record: api.EffectRecord{State: "claimed", Generation: 1, ClaimID: "child-claim", ClaimExpiresAt: lease.ExpiresAt,
			Effect: api.Effect{ID: lease.EffectID, OperationID: lease.OperationID, Context: &cause, Worker: &worker}}}
	storage := api.StorageProjection{StageID: r.DataStageID, WorkerLeaseID: lease.ID, OpenToken: "held-storage", Generation: 1,
		Storage: api.LaunchStorage{ReservationID: r.Reservation.ID, Target: lease.Target, LeaseID: p.Lease.ID,
			WorkspaceID: p.Data.Workspace.ID, Home: p.Data.Home},
		SourceIdentity: "source-inode", WorkspaceIdentity: "private-inode", HomeIdentity: "home-inode", Evidence: metaBlob("storage", "manifest")}
	stage := api.LaunchDataStage{ID: r.DataStageID, Reservation: r.Reservation, Inputs: p.Inputs, Grants: grants,
		AgentLeaseID: p.Lease.ID, ParentEffectID: "parent-plan-effect", Claim: claim, Worker: lease, Plan: worker, Storage: storage,
		WorkerLaunchID: lease.ConsumedBy, Process: api.ProcessHandle{ID: "job-process", Target: lease.Target,
			ContainmentID: "job-containment", Generation: "job-generation"}}
	request := api.LaunchDataRequest{ReservationID: r.Reservation.ID, GrantSetID: r.Reservation.GrantSetID, LeaseID: p.Lease.ID}
	if err := api.ValidateLaunchDataStage(stage, request); err != nil {
		t.Fatal("child stage metadata must satisfy the shared validator:", err)
	}
	workspace := api.Workspace{ID: "job-scratch", LogicalCWD: "/work/main"}
	materialization := api.Materialization{GrantSetID: grants.ID, Manifest: metaBlob("job-projection", "manifest"),
		Objects: []api.MaterializedObject{{GrantID: source.ID, WorkspaceID: workspace.ID, SourceIdentity: storage.SourceIdentity,
			DestinationIdentity: "job-source-inode", SnapshotSHA256: p.Data.Workspace.Snapshot.SHA256}}}
	spec := api.LaunchSpec{Kind: "worker", Worker: &worker, ID: "job-spec", Target: lease.Target, LaunchID: lease.ConsumedBy,
		Backend: backendName, UIDLeaseID: "job-uid", Workspace: workspace, Materialization: materialization, Grants: grants,
		Injection: api.Injection{Target: lease.Target, Outcome: "ready", SlotIDs: []api.ID{}, TaskSecretNames: []string{},
			TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}, Budget: p.Budget,
		EndpointGeneration: 1, RuntimeManifest: lease.RuntimeManifest, PolicyGeneration: r.Reservation.PolicyGeneration}
	return stage, spec
}

func TestMaterializeSpec(t *testing.T) {
	_, spec := materializeMeta(t)
	if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("materialization spec metadata control:", err)
	}
	for _, fault := range []string{"argv", "binding", "lease", "extra", "input", "input_id", "executable", "empty", "large", "agent"} {
		_, spec := materializeMeta(t)
		switch fault {
		case "argv":
			spec.Worker.Argv[2] = "caller-command"
		case "binding":
			spec.Worker.Argv[4] = "/caller/binding"
		case "lease":
			spec.Worker.Argv[6] = "../caller"
		case "extra":
			spec.Worker.Argv = append(spec.Worker.Argv, "extra")
		case "input":
			spec.Worker.Input.Class = "upload"
		case "input_id":
			spec.Worker.Input.ID = "/caller/input"
		case "executable":
			spec.Worker.Executable.ID = "/caller/executable"
		case "empty":
			spec.Worker.Input.Bytes = 0
		case "large":
			spec.Worker.Input.Bytes = api.MaxFrameBytes + 1
		case "agent":
			spec.PlanID = "agent-reservation"
		}
		if _, err := validateMaterializePlan(spec); err == nil {
			t.Fatal("materialization escaped its fixed worker grammar or input")
		}
	}
}

func TestMaterializeGrants(t *testing.T) {
	for _, fault := range []string{"resource", "secret", "profile", "network", "channel", "count", "parent", "destination", "write", "relative", "delivery", "history", "missing"} {
		_, spec := materializeMeta(t)
		if err := validateMaterializeGrants(spec.Grants); err != nil {
			t.Fatal("narrow job metadata control:", err)
		}
		switch fault {
		case "resource":
			spec.Grants.Resources = []api.ResourceGrant{{}}
		case "secret":
			spec.Grants.Secrets = []api.SecretGrant{{}}
		case "profile":
			spec.Grants.Profiles = []api.ProfileGrant{{}}
		case "network":
			spec.Grants.Network = []api.NetworkGrant{{}}
		case "channel":
			spec.Grants.Channels = []api.ChannelGrant{{}}
		case "count":
			spec.Grants.Data = append(spec.Grants.Data, spec.Grants.Data[0])
		case "parent":
			spec.Grants.Data[0].ParentGrantID = ""
		case "destination":
			spec.Grants.Data[0].Destination = "/data/caller"
		case "write":
			spec.Grants.Data[0].Access = "rw"
		case "relative":
			spec.Grants.Data[0].RelativePath = "subtree"
		case "delivery":
			spec.Grants.Data[0].Delivery = "copy"
		case "history":
			spec.Grants.Data[0].HistoryScope = "all"
		case "missing":
			spec.Grants.Data = nil
		}
		if validateMaterializeGrants(spec.Grants) == nil {
			t.Fatal("materialization admitted a widened job capability or source")
		}
	}
}

func TestMaterializeRuntime(t *testing.T) {
	for _, fault := range []string{"lease", "class", "executable", "bytes"} {
		stage, spec := materializeMeta(t)
		_, runtime := channelRuntimeMeta(t, spec)
		binding := &runtime.Manifest.Bindings[0]
		binding.WorkerLeaseID = stage.Worker.ID
		object := &runtime.Manifest.Objects[0]
		object.Content = fixtureBlob("worker-binary")
		if err := validateMaterializeRuntime(spec, runtime); err != nil {
			t.Fatal("materialization runtime metadata control:", err)
		}
		switch fault {
		case "lease":
			binding.WorkerLeaseID = "foreign-worker"
		case "class":
			binding.Class = api.EndpointLane
		case "executable":
			object.ID = "foreign-executable"
		case "bytes":
			object.Content.SHA256 = fixtureBlob("foreign").SHA256
		}
		if validateMaterializeRuntime(spec, runtime) == nil {
			t.Fatal("materialization admitted another worker endpoint or executable")
		}
	}
}

func TestMaterializePrepare(t *testing.T) {
	stage, spec := materializeMeta(t)
	cause := *stage.Claim.Record.Effect.Context
	cause.Kind, cause.ID, cause.EffectID = api.InternalHelperRegister, "job-register", "job-register-effect"
	handoff, raw := metaHandoff(t, spec, cause)
	source := &fixtureControls{handoff: handoff, original: raw}
	helper := &helperTripwire{}
	launcher, err := New(Dependencies{Helper: helper, RuntimeManifest: spec.RuntimeManifest, Controls: source})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := launcher.Prepare(context.Background(), spec)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || helper.calls != 1 || prepared.ID != "" {
		t.Fatal("materialization did not reach the failing helper registration port")
	}
}

func TestWorkerActorBoundary(t *testing.T) {
	source, _, _ := committedFixture(t)
	if err := validateRecordKind(source.binding); err != nil {
		t.Fatal("worker actor metadata control:", err)
	}
	for _, fault := range []string{"agent", "human", "level", "role"} {
		binding := source.binding
		switch fault {
		case "agent":
			binding.Record.Actor.Kind = "lane"
		case "human":
			binding.Record.Actor.Kind = "human"
		case "level":
			binding.Record.Actor.Level = 5
		case "role":
			binding.Record.Actor.Role = "supervisor"
		}
		if validateRecordKind(binding) == nil {
			t.Fatal("worker actor inherited agent or requester authority")
		}
	}
}

func TestFixedWorkerKinds(t *testing.T) {
	for _, kind := range []string{"capture", "usage", "materialize"} {
		if !workerKind(kind) {
			t.Fatal("fixed worker kind is missing from the closed protocol")
		}
	}
	if workerKind("arbitrary-worker") {
		t.Fatal("unknown worker kind widened the closed protocol")
	}
}
