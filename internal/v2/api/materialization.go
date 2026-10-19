package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"time"
)

// OpenToken names helper-held open descriptors, never a host path or permission
// to reopen a name. Prepare projects those exact descriptors into one job.
type StorageProjection struct {
	StageID           ID
	Storage           LaunchStorage
	WorkerLeaseID     ID
	OpenToken         ID
	Generation        Generation
	SourceIdentity    string
	WorkspaceIdentity string
	HomeIdentity      string
	Evidence          BlobRef
	// Copies is canonical metadata for additional helper-held copy projections.
	// Keeping the closed map encoded preserves comparability of the token tuple.
	Copies string `json:",omitempty"`
}

type StorageProjectionRequest struct {
	Claim         LaunchClaim `json:"-"`
	StageID       ID
	ReservationID ID
	AgentLeaseID  ID
	WorkerLeaseID ID
}

type LaunchDataStorage interface {
	OpenLaunchDataStorage(context.Context, StorageProjectionRequest) (StorageProjection, error)
}

// One child Worker effect of the current PlanLaunch claim, retained forever
// under that reservation's materialization selector. No caller invents IDs.
type LaunchDataStage struct {
	// ParentClaim is a compatibility container for the stable reservation/effect
	// pin. Its attempt fields are not authority and are never compared or issued.
	ParentClaim    LaunchClaim
	Grants         GrantSet
	WorkerLaunchID ID
	Process        ProcessHandle
	ID             ID
	Reservation    LaunchReservation
	Inputs         LaunchInputs
	AgentLeaseID   ID
	ParentEffectID ID
	Claim          EffectLease
	Worker         WorkerLease
	Plan           WorkerPlan
	Storage        StorageProjection
}

type LaunchDataResult struct {
	ResultReceipt  WorkerResultReceipt
	ReadBackSHA256 Digest
	StageID        ID
	WorkerLeaseID  ID
	EffectID       ID
	OperationID    ID
	InputSHA256    Digest
	Data           LaunchData
	Manifest       BlobRef
	Observation    ProcessObservation
}

type LaunchDataStageStore interface {
	LaunchDataStage(context.Context, Scope, LaunchDataRequest) (LaunchDataStage, error)
}

type MaterializationControl interface {
	// Service outbox creates/claims/launches the fixed worker under the current
	// parent claim; the dataworker library neither steals it nor runs as service.
	MaterializationStage(context.Context, LaunchDataRequest) (LaunchDataStage, error)
	AwaitMaterialization(context.Context, ID) (LaunchDataResult, error)
}

type WorkerInputRequest struct {
	LeaseID ID `json:"lease_id"`
}

type WorkerJobInput struct {
	Bytes       []byte  `json:"bytes"`
	Schema      string  `json:"schema"`
	StageID     ID      `json:"stage_id"`
	LeaseID     ID      `json:"lease_id"`
	Kind        string  `json:"kind"`
	OperationID ID      `json:"operation_id"`
	EffectID    ID      `json:"effect_id"`
	Input       BlobRef `json:"input"`
}

type WorkerResultSubmission struct {
	LeaseID            ID         `json:"lease_id"`
	ExpectedGeneration Generation `json:"expected_generation"`
	InputSHA256        Digest     `json:"input_sha256"`
	Result             []byte     `json:"result"`
}

type WorkerResultReceipt struct {
	LeaseID      ID         `json:"lease_id"`
	StageID      ID         `json:"stage_id"`
	Generation   Generation `json:"generation"`
	Result       BlobRef    `json:"result"`
	CommittedSeq Sequence   `json:"committed_seq"`
}

// These are on the worker-only installed endpoint, not public Methods entries.
type WorkerBootstrap interface {
	WorkerInput(context.Context, Scope, WorkerInputRequest) (WorkerJobInput, error)
	WorkerResult(context.Context, Scope, WorkerResultSubmission) (WorkerResultReceipt, error)
}

// WorkerPolicySource is a private identity read, never a worker RPC or generic
// policy capability. The writer revalidates the actual native job connection.
type WorkerPolicySource interface {
	WorkerPolicyGeneration(context.Context, ConnectionContext, ID) (Generation, error)
}

func ValidateWorkerInput(p WorkerPrincipal, input WorkerJobInput, now time.Time) error {
	if err := ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, WorkerInputRead, now); err != nil {
		return err
	}
	sum := sha256.Sum256(input.Bytes)
	if input.Schema != "laneboss.worker-input.v2" || input.StageID != p.StageID || input.LeaseID != p.Lease.ID || input.Kind != p.Lease.Kind ||
		input.OperationID != p.Lease.OperationID || input.EffectID != p.Lease.EffectID || input.Input != p.Lease.Input ||
		len(input.Bytes) == 0 || len(input.Bytes) > MaxFrameBytes || int64(len(input.Bytes)) != input.Input.Bytes || input.Input.SHA256 != Digest(hex.EncodeToString(sum[:])) {
		return launchInvalid("worker input differs from its protected leased stage and exact bytes")
	}
	return nil
}

func ValidateWorkerResult(p WorkerPrincipal, submission WorkerResultSubmission, receipt WorkerResultReceipt, now time.Time) error {
	if err := ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, WorkerResultAppend, now); err != nil {
		return err
	}
	sum := sha256.Sum256(submission.Result)
	if submission.LeaseID != p.Lease.ID || submission.ExpectedGeneration != p.Lease.Generation || p.Lease.Generation >= launchMaxInteger ||
		submission.InputSHA256 != p.Lease.Input.SHA256 || len(submission.Result) == 0 || len(submission.Result) > MaxFrameBytes ||
		receipt.LeaseID != p.Lease.ID || receipt.StageID != p.StageID || receipt.Generation != p.Lease.Generation+1 || receipt.CommittedSeq == 0 ||
		!launchBlob(receipt.Result, "worker_result") || receipt.Result.Bytes != int64(len(submission.Result)) || receipt.Result.SHA256 != Digest(hex.EncodeToString(sum[:])) {
		return launchInvalid("worker result acknowledgement differs from its authenticated input and bytes")
	}
	return nil
}

func ValidateLaunchDataStage(stage LaunchDataStage, request LaunchDataRequest) error {
	s, r := stage, stage.Reservation
	if err := ValidateLaunchReservation(r); err != nil {
		return err
	}
	if err := validateLaunchInputs(r, s.Inputs); err != nil {
		return err
	}
	if request.Claim != (LaunchClaim{}) && (request.Claim.ReservationID != r.ID || request.Claim.EffectID != s.ParentEffectID) {
		return launchInvalid("materialization stage changed its original planning selector")
	}
	argv := []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(s.Worker.ID)}
	cause := s.Claim.Record.Effect.Context
	if request.ReservationID != r.ID || request.GrantSetID != r.GrantSetID || request.LeaseID != s.AgentLeaseID || !launchID(s.ID) || !launchID(s.AgentLeaseID) ||
		!launchID(s.ParentEffectID) || s.Claim.Record.Effect.ID == s.ParentEffectID || !EffectLeaseClaimed(s.Claim) ||
		s.Claim.ClaimID == "" || s.Claim.Record.ClaimID != s.Claim.ClaimID || s.Claim.Record.Effect.Worker == nil || !reflect.DeepEqual(s.Plan, *s.Claim.Record.Effect.Worker) ||
		s.Worker.EffectID != s.Claim.Record.Effect.ID || s.Worker.OperationID != r.OperationID ||
		s.Worker.Kind != "materialize" || s.Worker.Target != r.Target || s.Worker.GrantSetID != s.Grants.ID || s.Worker.RuntimeManifest != s.Inputs.Sources.Runtime.Manifest ||
		!launchID(s.WorkerLaunchID) || s.Worker.ConsumedBy != s.WorkerLaunchID || !launchID(s.Process.ID) || s.Process.Target != r.Target || !launchID(s.Process.ContainmentID) || s.Process.Generation == "" ||
		s.Plan.Schema != "laneboss.worker-plan.v2" || s.Plan.Kind != "materialize" || !launchExecutable(s.Plan.Executable) ||
		s.Plan.Input != s.Worker.Input || !launchBlob(s.Plan.Input, "materialize_input") || s.Plan.GrantSetID != s.Grants.ID || !slices.Equal(s.Plan.Argv, argv) ||
		cause == nil || cause.Config != r.Config || cause.Target != r.Target || cause.RequestedBy != r.RequestedBy || cause.CauseOperationID != r.OperationID ||
		cause.CauseRequestID != r.RequestID || cause.CancellationEpoch != r.CancellationEpoch ||
		s.Storage.StageID != s.ID || s.Storage.WorkerLeaseID != s.Worker.ID || s.Storage.Storage.ReservationID != r.ID || s.Storage.Storage.LeaseID != s.AgentLeaseID ||
		s.Storage.Storage.Target != r.Target || !launchID(s.Storage.OpenToken) || !launchGeneration(s.Storage.Generation) ||
		s.Storage.SourceIdentity == "" || s.Storage.WorkspaceIdentity == "" || s.Storage.HomeIdentity == "" || !launchBlob(s.Storage.Evidence, "manifest") {
		return launchInvalid("materialization stage lacks its claimed fixed worker and opened storage")
	}
	g := s.Grants
	if !launchID(g.ID) || g.ID == r.GrantSetID || g.LifeID != r.Target.LifeID || g.PolicyGeneration != r.PolicyGeneration || g.Revoked ||
		!launchGeneration(g.Generation) || !bindingDigest.MatchString(string(g.SHA256)) ||
		len(g.Resources)+len(g.Secrets)+len(g.Profiles)+len(g.Network)+len(g.Channels) != 0 || len(g.Data) != 1 {
		return launchInvalid("materialization worker grants exceed the narrow data job")
	}
	source := g.Data[0]
	if source.ParentGrantID != s.Inputs.Sources.Project.GrantID || source.SourceObjectID != s.Inputs.Sources.Project.Object.ID || source.SourceSHA256 != s.Inputs.Sources.Project.Object.SHA256 ||
		source.Destination != "/job/source" || source.Access != "ro" || source.RelativePath != "." || source.HistoryScope != s.Inputs.Sources.Project.HistoryScope {
		return launchInvalid("materialization worker source differs from its read-only grant")
	}
	_, err := ValidateDataCopyProjections(s.Inputs, s.Storage)
	return err
}

func ValidateLaunchDataResult(stage LaunchDataStage, result LaunchDataResult) error {
	r, s := result, stage
	if err := ValidateLaunchDataStage(s, LaunchDataRequest{ReservationID: s.Reservation.ID, GrantSetID: s.Reservation.GrantSetID, LeaseID: s.AgentLeaseID}); err != nil {
		return err
	}
	d := r.Data
	canonical, digest, canonicalErr := launchCanonical(d)
	if r.StageID != s.ID || r.WorkerLeaseID != s.Worker.ID || r.EffectID != s.Worker.EffectID || r.OperationID != s.Reservation.OperationID ||
		canonicalErr != nil || r.ResultReceipt.LeaseID != s.Worker.ID || r.ResultReceipt.StageID != s.ID || r.ResultReceipt.Generation != s.Worker.Generation+1 || r.ResultReceipt.CommittedSeq == 0 ||
		!launchBlob(r.ResultReceipt.Result, "worker_result") || r.ResultReceipt.Result.SHA256 != digest || r.ResultReceipt.Result.Bytes != int64(len(canonical)) ||
		r.InputSHA256 != s.Worker.Input.SHA256 || d.ReservationID != s.Reservation.ID || d.Target != s.Reservation.Target || d.LeaseID != s.AgentLeaseID ||
		d.Source != s.Inputs.Sources.Project || d.Workspace.ID != s.Storage.Storage.WorkspaceID || d.Home != s.Storage.Storage.Home ||
		d.Workspace.ProjectID != d.Source.ProjectID || d.Workspace.Base != d.Source.Base || d.Workspace.Branch != "lane/"+string(d.Target.LifeID) || d.Workspace.LogicalCWD != "/work/main" ||
		d.Home.LifeID != d.Target.LifeID || d.Home.Home.WorkspaceID != d.Workspace.ID || r.ReadBackSHA256 != r.Manifest.SHA256 ||
		d.Materialization.GrantSetID != s.Reservation.GrantSetID || d.Materialization.Manifest != r.Manifest || !launchBlob(r.Manifest, "manifest") ||
		r.Observation.Handle != s.Process || r.Observation.State != "exited" || r.Observation.ExitCode == nil || *r.Observation.ExitCode != 0 ||
		r.Observation.Survivors == nil || *r.Observation.Survivors != 0 {
		return launchInvalid("materialization result lacks correlated measured zero-exit read-back")
	}
	main := 0
	for _, object := range d.Materialization.Objects {
		if object.GrantID == d.Source.GrantID && object.WorkspaceID == d.Workspace.ID && object.SourceIdentity == s.Storage.SourceIdentity &&
			object.DestinationIdentity == s.Storage.WorkspaceIdentity && object.SnapshotSHA256 == d.Workspace.Snapshot.SHA256 {
			main++
		}
	}
	if main != 1 {
		return launchInvalid("materialization result changed opened source or destination identity")
	}
	copies, err := ValidateDataCopyProjections(s.Inputs, s.Storage)
	if err != nil {
		return err
	}
	if len(d.Materialization.Objects) != 1+len(copies) {
		return launchInvalid("materialization result omitted a copy projection")
	}
	for _, copy := range copies {
		expected, err := copy.Receipt(s.Storage.Storage.WorkspaceID)
		if err != nil {
			return err
		}
		matched := 0
		for _, object := range d.Materialization.Objects {
			if object == expected {
				matched++
			}
		}
		if matched != 1 {
			return launchInvalid("materialization result replaced a copy source or destination")
		}
	}
	return nil
}
