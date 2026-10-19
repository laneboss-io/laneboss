package grants_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Real fixture file IO is measured on Linux; identity/process/claim facts are
// explicitly synthetic DTOs and cannot certify an installed worker boundary.
type materializationFixture struct {
	*launchGraph
	stage                                        api.LaunchDataStage
	principal                                    api.WorkerPrincipal
	result                                       api.LaunchDataResult
	request                                      api.LaunchDataRequest
	planning                                     api.EffectRecord
	sourcePath, workspacePath, homePath          string
	roots                                        []*os.Root
	openCalls, awaitCalls, resultCalls, ackReads int
	objectReads                                  int
	stageErr, awaitErr, openErr                  error
	onResult                                     func(*api.LaunchDataResult)
	onReceipt                                    func(*api.WorkerResultReceipt)
	onInput                                      func(*api.WorkerJobInput)
	onObject                                     func(api.ID)
}

type materializationHelper struct {
	*launchJournal
	f *materializationFixture
}

func (h *materializationHelper) OpenLaunchDataStorage(_ context.Context, r api.StorageProjectionRequest) (api.StorageProjection, error) {
	f := h.f
	if err := api.CheckPlanningClaim(f.planning, r.Claim, f.scope.Config, launchClock{}.Now()); err != nil {
		return api.StorageProjection{}, err
	}
	f.openCalls++
	if f.openErr != nil {
		return api.StorageProjection{}, f.openErr
	}
	if r.StageID != f.stage.ID || r.ReservationID != f.stage.Reservation.ID || r.AgentLeaseID != f.stage.AgentLeaseID || r.WorkerLeaseID != f.stage.Worker.ID {
		return api.StorageProjection{}, &api.Error{Code: api.CodeForbidden}
	}
	for _, path := range []string{f.sourcePath, f.workspacePath, f.homePath} {
		info, err := os.Lstat(path)
		if err != nil {
			return api.StorageProjection{}, err
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return api.StorageProjection{}, &api.Error{Code: api.CodeIntegrity}
		}
	}
	if launchIdentity(f.t, f.sourcePath) != f.stage.Storage.SourceIdentity || launchIdentity(f.t, f.workspacePath) != f.stage.Storage.WorkspaceIdentity || launchIdentity(f.t, f.homePath) != f.stage.Storage.HomeIdentity {
		return api.StorageProjection{}, &api.Error{Code: api.CodeIntegrity}
	}
	return f.stage.Storage, nil
}

func (f *materializationFixture) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	f.check(scope)
	if err := ctx.Err(); err != nil {
		return api.EffectRecord{}, err
	}
	if id != f.planning.Effect.ID {
		return api.EffectRecord{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(f.t, f.planning), nil
}

func (f *materializationFixture) ClaimEffect(ctx context.Context, scope api.Scope, request api.EffectClaimRequest) (api.EffectLease, error) {
	current, err := f.Effect(ctx, scope, request.EffectID)
	if err != nil {
		return api.EffectLease{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(request.Deadline))
	if err != nil || !(launchClock{}).Now().Before(deadline) || request.ExpectedGeneration != current.Generation ||
		request.ClaimantID != scope.Actor.ID || current.State != api.EffectPending || current.Outcome != nil {
		return api.EffectLease{}, &api.Error{Code: api.CodeConflict}
	}
	claimID, err := wire.NewID()
	if err != nil {
		return api.EffectLease{}, err
	}
	current.Generation++
	current.State, current.ClaimID, current.ClaimantID, current.ClaimExpiresAt = api.EffectClaimed, claimID, request.ClaimantID, request.Deadline
	f.planning = current
	return api.EffectLease{Record: launchCopy(f.t, current), ClaimID: claimID, ExpiresAt: request.Deadline}, nil
}

func (f *materializationFixture) LaunchDataStage(_ context.Context, scope api.Scope, r api.LaunchDataRequest) (api.LaunchDataStage, error) {
	f.check(scope)
	if r != f.request {
		return api.LaunchDataStage{}, &api.Error{Code: api.CodeForbidden}
	}
	return launchCopy(f.t, f.stage), nil
}
func (f *materializationFixture) MaterializationStage(_ context.Context, r api.LaunchDataRequest) (api.LaunchDataStage, error) {
	if f.stageErr != nil {
		return api.LaunchDataStage{}, f.stageErr
	}
	if r != f.request {
		return api.LaunchDataStage{}, &api.Error{Code: api.CodeForbidden}
	}
	return launchCopy(f.t, f.stage), nil
}
func (f *materializationFixture) AwaitMaterialization(ctx context.Context, id api.ID) (api.LaunchDataResult, error) {
	f.awaitCalls++
	if f.awaitErr != nil {
		return api.LaunchDataResult{}, f.awaitErr
	}
	if id != f.stage.ID {
		return api.LaunchDataResult{}, &api.Error{Code: api.CodeForbidden}
	}
	if f.result.ResultReceipt.StageID == "" {
		job := f.job()
		_, err := dataworker.RunInternalJob(ctx, f.scope.Config, []string{"--binding", "/runtime/laneboss-worker.json", "--lease", string(f.stage.Worker.ID)}, job)
		if err != nil {
			return api.LaunchDataResult{}, err
		}
	}
	// Independent fixture read-back observes actual destination bytes and mode.
	actual, err := os.ReadFile(filepath.Join(f.workspacePath, "main.txt"))
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	if manifest.Hash(actual) != f.metadata["workspace-file"].Ref.SHA256 {
		return api.LaunchDataResult{}, &api.Error{Code: api.CodeIntegrity}
	}
	zero, survivors := 0, uint64(0)
	f.result.Observation = api.ProcessObservation{Handle: f.stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors, ObservedAt: "2030-01-01T00:00:00Z"}
	ref := f.result.Data.Materialization.Manifest
	f.result.ReadBackSHA256 = manifest.Hash(f.blobs[ref.ID])
	if f.onResult != nil {
		f.onResult(&f.result)
		f.retainResult()
	}
	return launchCopy(f.t, f.result), nil
}

func (f *materializationFixture) WorkerInput(_ context.Context, scope api.Scope, r api.WorkerInputRequest) (api.WorkerJobInput, error) {
	if scope.Actor != f.principal.Record.Actor || r.LeaseID != f.stage.Worker.ID {
		return api.WorkerJobInput{}, &api.Error{Code: api.CodeForbidden}
	}
	w := f.stage.Worker
	input := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: f.stage.ID, LeaseID: w.ID, Kind: w.Kind, OperationID: w.OperationID, EffectID: w.EffectID, Input: w.Input, Bytes: append([]byte{}, f.blobs[w.Input.ID]...)}
	if f.onInput != nil {
		f.onInput(&input)
	}
	return input, nil
}
func (f *materializationFixture) WorkerResult(_ context.Context, scope api.Scope, submission api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	f.resultCalls++
	if scope.Actor != f.principal.Record.Actor || submission.LeaseID != f.stage.Worker.ID || submission.InputSHA256 != f.stage.Worker.Input.SHA256 {
		return api.WorkerResultReceipt{}, &api.Error{Code: api.CodeForbidden}
	}
	var data api.LaunchData
	if err := api.DecodeObject(submission.Result, &data); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	f.result.Data = data
	f.result.Manifest = data.Materialization.Manifest
	ref := f.resultObject(submission.Result)
	f.result.ResultReceipt = api.WorkerResultReceipt{LeaseID: f.stage.Worker.ID, StageID: f.stage.ID, Generation: submission.ExpectedGeneration + 1, Result: ref, CommittedSeq: 20}
	receipt := f.result.ResultReceipt
	if f.onReceipt != nil {
		f.onReceipt(&receipt)
	}
	return receipt, nil
}
func (f *materializationFixture) retainResult() {
	f.t.Helper()
	raw, err := json.Marshal(f.result.Data)
	if err != nil {
		f.t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	f.result.ResultReceipt.Result = f.resultObject(canonical)
}

// Model the private WorkerResult writer, not the generic owner-visible object
// helper used for task/source fixtures. Bytes and operation come from this
// worker's actual submission. The real-store companion verifies this contract.
func (f *materializationFixture) resultObject(raw []byte) api.BlobRef {
	ref := f.object("data-result", "worker_result", raw, f.stage.Reservation.OperationID)
	metadata := f.metadata[ref.ID]
	metadata.ACL.Audience = "private"
	metadata.ACL.LifeID = f.stage.Reservation.Target.LifeID
	f.metadata[ref.ID] = metadata
	return ref
}

func (f *materializationFixture) job() dataworker.MaterializationJob {
	f.t.Helper()
	if len(f.roots) == 0 {
		for _, path := range []string{f.sourcePath, f.workspacePath, f.homePath} {
			root, err := os.OpenRoot(path)
			if err != nil {
				f.t.Fatal(err)
			}
			f.roots = append(f.roots, root)
			f.t.Cleanup(func() {
				if err := root.Close(); err != nil {
					f.t.Error(err)
				}
			})
		}
	}
	p := launchCopy(f.t, f.principal)
	return dataworker.MaterializationJob{Principal: p, Scope: api.Scope{Config: p.Record.Config, Actor: p.Record.Actor, LaunchID: p.Record.ID, EndpointGeneration: p.Endpoint.EndpointGeneration},
		Bootstrap: f, Source: f.roots[0], Workspace: f.roots[1], Home: f.roots[2], Clock: launchClock{}, Read: func(_ context.Context, r api.BlobReadRequest) (api.BlobChunk, error) {
			f.objectReads++
			if r.ObjectID != f.stage.Inputs.Sources.Project.Object.ID && r.ObjectID != "workspace-snapshot" {
				return api.BlobChunk{}, &api.Error{Code: api.CodeForbidden}
			}
			if f.onObject != nil {
				f.onObject(r.ObjectID)
			}
			raw := f.blobs[r.ObjectID]
			if r.Offset < 0 || r.Offset > int64(len(raw)) || r.Limit <= 0 {
				return api.BlobChunk{}, &api.Error{Code: api.CodeInvalid}
			}
			end := min(int64(len(raw)), r.Offset+int64(r.Limit))
			data := append([]byte{}, raw[r.Offset:end]...)
			return api.BlobChunk{ObjectID: r.ObjectID, Offset: r.Offset, Data: data, SHA256: manifest.Hash(data)}, nil
		}}
}

func newMaterializationFixture(t *testing.T) *materializationFixture {
	t.Helper()
	g := newLaunchGraph(t)
	completed := g.completed()
	p := *completed.Plan
	r := completed.Reservation
	f := &materializationFixture{launchGraph: g, request: launchRequestFor(completed)}
	parentCause := api.InternalIntent{ID: "plan-cause", Kind: api.InternalLaunchPlan, Config: r.Config, Actor: g.scope.Actor,
		RequestedBy: r.RequestedBy, Target: r.Target, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID,
		EffectID: "plan-effect", CancellationEpoch: r.CancellationEpoch}
	f.planning = api.EffectRecord{Effect: api.Effect{ID: parentCause.EffectID, OperationID: r.OperationID, Context: &parentCause,
		PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}, State: api.EffectPending, Generation: 1}
	parent, err := f.ClaimEffect(context.Background(), g.scope, api.EffectClaimRequest{EffectID: parentCause.EffectID, ExpectedGeneration: 1,
		ClaimantID: g.scope.Actor.ID, Deadline: api.Timestamp(launchClock{}.Now().Add(time.Hour).Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal("materialization fixture could not claim its actual planning effect", err)
	}
	f.request.Claim = api.PlanningClaim(r.ID, parent)
	base := filepath.Dir(g.helper.directories[p.Data.Workspace.ID])
	f.sourcePath = filepath.Join(base, "source")
	f.workspacePath = filepath.Join(base, "job-workspace")
	f.homePath = filepath.Join(base, "job-home")
	for _, path := range []string{f.workspacePath, f.homePath} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	g.helper.directories[p.Data.Workspace.ID], g.helper.directories[p.Data.Home.RootID] = f.workspacePath, f.homePath
	grants, err := dataworker.MaterializationGrants(r, *completed.Inputs, "materialize-grants", "job-source", "2030-01-01T00:05:00Z", launchClock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	worker := api.WorkerLease{ID: "materialize-worker", Kind: "materialize", Target: r.Target, OperationID: r.OperationID, EffectID: "materialize-effect", GrantSetID: grants.ID,
		RuntimeManifest: p.Inputs.Sources.Runtime.Manifest, Generation: 1, ExpiresAt: grants.ExpiresAt, ConsumedBy: "materialize-launch"}
	workerExecutable := api.Executable{ID: "laneboss-artifact", SHA256: g.metadata["artifact-bytes"].Ref.SHA256, Version: "fixture-version"}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize", Executable: workerExecutable,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(worker.ID)}, GrantSetID: grants.ID, Budget: p.Budget}
	cause := api.InternalIntent{ID: "materialize-cause", Kind: api.InternalObjectRetain, Config: r.Config, Actor: g.scope.Actor, RequestedBy: r.RequestedBy, Target: r.Target,
		CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: worker.EffectID, CancellationEpoch: r.CancellationEpoch}
	claim := api.EffectLease{ClaimID: "materialize-claim", ExpiresAt: grants.ExpiresAt, Record: api.EffectRecord{State: "claimed", Generation: 1, ClaimID: "materialize-claim", ClaimantID: "outbox",
		ClaimExpiresAt: grants.ExpiresAt, Effect: api.Effect{ID: worker.EffectID, OperationID: r.OperationID, Context: &cause}}}
	storage := api.StorageProjection{StageID: "materialize-stage", Storage: g.helper.storage[p.Lease.ID], WorkerLeaseID: worker.ID, OpenToken: "held-materialize-roots", Generation: 1,
		SourceIdentity: launchIdentity(t, f.sourcePath), WorkspaceIdentity: launchIdentity(t, f.workspacePath), HomeIdentity: launchIdentity(t, f.homePath), Evidence: g.encoded("storage-proof", "manifest", map[string]string{"stage": "materialize-stage"}, r.OperationID)}
	f.stage = api.LaunchDataStage{ID: storage.StageID, Reservation: r, Inputs: *completed.Inputs, Grants: grants, AgentLeaseID: p.Lease.ID, ParentEffectID: parent.Record.Effect.ID, ParentClaim: api.StablePlanningPin(r.ID, parent.Record.Effect.ID), Claim: claim, Worker: worker, Plan: plan, Storage: storage,
		WorkerLaunchID: worker.ConsumedBy, Process: api.ProcessHandle{ID: "materialize-process", Target: r.Target, ContainmentID: "materialize-containment", Generation: "worker-generation"}}
	bytes, err := dataworker.EncodeMaterializationInput(f.stage, p.Data.Workspace.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	f.stage.Worker.Input = g.object("materialize-input", "materialize_input", bytes, r.OperationID)
	f.stage.Plan.Input = f.stage.Worker.Input
	retainedPlan := f.stage.Plan
	f.stage.Claim.Record.Effect.Worker = &retainedPlan
	if err := api.ValidateLaunchDataStage(f.stage, f.request); err != nil {
		t.Fatal("materialization seed rejected by production validator", err)
	}
	record := api.LaunchRecord{Kind: "worker", ID: worker.ConsumedBy, Config: r.Config, Target: r.Target, Actor: api.Actor{Kind: "worker", ID: "materialize-principal", LifeID: r.Target.LifeID},
		UIDLeaseID: "materialize-helper", HostUID: 41002, ContainmentID: f.stage.Process.ContainmentID, ProcessGeneration: f.stage.Process.Generation, GrantSetID: grants.ID, GrantsSHA256: grants.SHA256,
		EndpointGeneration: 1, PolicyGeneration: r.PolicyGeneration}
	g.launches[record.ID] = record
	target := r.Target
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: r.Config, Class: api.EndpointWorker,
		LaunchID: record.ID, WorkerLeaseID: worker.ID, Target: &target, EndpointGeneration: 1, InstallationGeneration: 1, ServiceUID: 41000, ServiceGID: 41000, Socket: "/runtime/worker.sock",
		ArtifactSHA256: workerExecutable.SHA256, ServiceVersion: "fixture-version", Backend: "linux-bwrap-landlock"}
	f.principal = api.WorkerPrincipal{StageID: f.stage.ID, Lease: f.stage.Worker, Record: record, Endpoint: endpoint, Peer: api.PeerFacts{HostUID: record.HostUID, HostGID: 41002, HostPID: 100,
		ProcessGeneration: "worker-connector", ContainmentID: record.ContainmentID}, BootID: "fixture-boot", AllocationGeneration: 1, Claim: f.stage.Claim, CancellationEpoch: r.CancellationEpoch}
	if err := api.ValidateWorkerPrincipal(f.principal, endpoint, f.principal.Peer, api.WorkerInputRead, launchClock{}.Now()); err != nil {
		t.Fatal(err)
	}
	completed.Plan, completed.Phase, completed.DataStageID = nil, "sourced", f.stage.ID
	g.plans[r.ID] = completed
	f.result = api.LaunchDataResult{StageID: f.stage.ID, WorkerLeaseID: worker.ID, EffectID: worker.EffectID, OperationID: r.OperationID, InputSHA256: f.stage.Worker.Input.SHA256}
	g.onBlob = func(id api.ID) {
		if id == "data-result" {
			f.ackReads++
		}
	}
	g.worker, err = dataworker.New(dataworker.Dependencies{Config: r.Config, Controls: f, Store: f, Helper: &materializationHelper{launchJournal: g.helper, f: f}, Launcher: &launchProbe{}, Clock: launchClock{}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMaterializationStageFlow(t *testing.T) {
	f := newMaterializationFixture(t)
	data, err := f.worker.MaterializeLaunch(context.Background(), f.request)
	if err != nil {
		t.Fatal("materialization child stage positive failed", err)
	}
	if !reflect.DeepEqual(data, f.result.Data) || f.awaitCalls != 1 || f.resultCalls != 1 || f.ackReads == 0 || f.openCalls < 2 {
		t.Fatal("materialization did not await and read back its one acknowledged child stage")
	}
	if err := api.ValidateLaunchDataResult(f.stage, f.result); err != nil {
		t.Fatal(err)
	}
}

func TestMatPrivProvenance(t *testing.T) {
	for _, fault := range []string{"audience", "operation", "owner"} {
		t.Run(fault, func(t *testing.T) {
			f := newMaterializationFixture(t)
			f.onReceipt = func(receipt *api.WorkerResultReceipt) {
				metadata := f.metadata[receipt.Result.ID]
				switch fault {
				case "audience":
					metadata.ACL.Audience = "owner"
				case "operation":
					metadata.SourceOperationID = "foreign-operation"
				case "owner":
					metadata.ACL.Owner = api.Actor{Kind: "human", ID: "foreign-owner"}
				}
				f.metadata[receipt.Result.ID] = metadata
			}
			result, err := f.worker.MaterializeLaunch(context.Background(), f.request)
			launchError(t, err, api.CodeIntegrity)
			if !reflect.DeepEqual(result, api.LaunchData{}) {
				t.Fatal("materialization accepted substituted private result provenance")
			}
		})
	}
}

func TestMaterializationStageGuards(t *testing.T) {
	for _, fault := range []string{"parent", "input", "storage", "open", "argv", "epoch", "grants"} {
		t.Run(fault, func(t *testing.T) {
			f := newMaterializationFixture(t)
			switch fault {
			case "parent":
				f.stage.ParentEffectID = f.stage.Worker.EffectID
			case "input":
				f.stage.Plan.Input.ID = "foreign-input"
			case "storage":
				f.stage.Storage.WorkerLeaseID = "foreign-worker"
			case "open":
				f.stage.Storage.OpenToken = ""
			case "argv":
				f.stage.Plan.Argv = []string{"caller-command"}
			case "epoch":
				f.stage.Claim.Record.Effect.Context.CancellationEpoch++
			case "grants":
				f.stage.Grants.Network = []api.NetworkGrant{{ID: "network", EndpointID: "foreign-endpoint"}}
			}
			plan := f.stage.Plan
			f.stage.Claim.Record.Effect.Worker = &plan
			_, err := f.worker.MaterializeLaunch(context.Background(), f.request)
			if f.openCalls != 0 || f.awaitCalls != 0 {
				t.Fatal("invalid materialization stage reached storage or await")
			}
			launchError(t, err, api.CodeInvalid)
		})
	}
}

func TestMaterializationResultGuards(t *testing.T) {
	for _, fault := range []string{"run", "operation", "exit", "process", "readback", "source"} {
		t.Run(fault, func(t *testing.T) {
			f := newMaterializationFixture(t)
			f.onResult = func(r *api.LaunchDataResult) {
				switch fault {
				case "run":
					r.Data.Target.Run++
				case "operation":
					r.OperationID = "foreign-operation"
				case "exit":
					one := 1
					r.Observation.ExitCode = &one
				case "process":
					r.Observation.Handle.Generation = "foreign-generation"
				case "readback":
					r.ReadBackSHA256 = manifest.Hash([]byte("foreign read-back"))
				case "source":
					r.Data.Materialization.Objects[0].SourceIdentity = "foreign-source"
				}
			}
			_, err := f.worker.MaterializeLaunch(context.Background(), f.request)
			if f.ackReads != 0 {
				t.Fatal("invalid materialization result reached object read-back")
			}
			launchError(t, err, api.CodeInvalid)
		})
	}
}

func TestMaterializationCopyAndAck(t *testing.T) {
	f := newMaterializationFixture(t)
	receipt, err := dataworker.RunMaterialization(context.Background(), f.job())
	if err != nil {
		t.Fatal("confined fixture copy failed", err)
	}
	actual, err := os.ReadFile(filepath.Join(f.workspacePath, "main.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, f.blobs["file-bytes"]) || launchIdentity(t, filepath.Join(f.sourcePath, "main.txt")) == launchIdentity(t, filepath.Join(f.workspacePath, "main.txt")) || receipt != f.result.ResultReceipt {
		t.Fatal("materialization copied bytes, independence or acknowledgement changed")
	}
	info, err := os.Lstat(filepath.Join(f.homePath, ".codex"))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("materialization did not prepare the private vendor home", err)
	}
}

func TestMaterializationWorkerGuards(t *testing.T) {
	for _, fault := range []string{"input", "source-bytes", "hardlink", "root", "output-extra", "destination-race", "ack"} {
		t.Run(fault, func(t *testing.T) {
			f := newMaterializationFixture(t)
			job := f.job()
			code := api.CodeIntegrity
			switch fault {
			case "input":
				f.onInput = func(i *api.WorkerJobInput) { i.Bytes = append(i.Bytes, '\n') }
				code = api.CodeInvalid
			case "source-bytes":
				if err := os.WriteFile(filepath.Join(f.sourcePath, "main.txt"), []byte("changed data\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(f.sourcePath, "main.txt"), filepath.Join(filepath.Dir(f.sourcePath), "linked-source")); err != nil {
					t.Fatal(err)
				}
			case "root":
				foreign := filepath.Join(filepath.Dir(f.homePath), "foreign-home")
				if err := os.Mkdir(foreign, 0700); err != nil {
					t.Fatal(err)
				}
				root, err := os.OpenRoot(foreign)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := root.Close(); err != nil {
						t.Error(err)
					}
				})
				job.Home = root
			case "output-extra":
				f.onObject = func(id api.ID) {
					if id == "workspace-snapshot" {
						f.onObject = nil
						if err := os.WriteFile(filepath.Join(f.workspacePath, "extra"), []byte("ungranted"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			case "destination-race":
				f.onObject = func(id api.ID) {
					if id == "workspace-snapshot" {
						f.onObject = nil
						if err := os.WriteFile(filepath.Join(f.workspacePath, "main.txt"), []byte("kept"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			case "ack":
				f.onReceipt = func(r *api.WorkerResultReceipt) { r.Result.SHA256 = manifest.Hash([]byte("foreign acknowledgement")) }
				code = api.CodeInvalid
			}
			receipt, err := dataworker.RunMaterialization(context.Background(), job)
			if fault == "destination-race" {
				if !errors.Is(err, os.ErrExist) {
					t.Fatal("materialization overwrote a raced destination", err)
				}
				actual, readErr := os.ReadFile(filepath.Join(f.workspacePath, "main.txt"))
				if readErr != nil || string(actual) != "kept" || receipt.LeaseID != "" || f.resultCalls != 0 {
					t.Fatal("materialization changed a refused raced destination", readErr)
				}
				return
			}
			if fault == "root" && f.objectReads != 0 {
				t.Fatal("foreign materialization roots reached object read")
			}
			launchError(t, err, code)
			if receipt.LeaseID != "" || fault != "ack" && f.resultCalls != 0 {
				t.Fatal("refused materialization produced a usable acknowledgement")
			}
		})
	}
}

func TestMaterializationOwnerErrors(t *testing.T) {
	for _, port := range []string{"stage", "open", "await"} {
		t.Run(port, func(t *testing.T) {
			f := newMaterializationFixture(t)
			owner := "lb-v2-service"
			if port == "open" {
				owner = "lb-v2-admin"
			}
			refusal := api.NotImplemented(owner, "fixture materialization "+port)
			switch port {
			case "stage":
				f.stageErr = refusal
			case "open":
				f.openErr = refusal
			case "await":
				f.awaitErr = refusal
			}
			_, err := f.worker.MaterializeLaunch(context.Background(), f.request)
			if !errors.Is(err, refusal) {
				t.Fatal("materialization replaced its owner port failure", err)
			}
		})
	}
}

type materializationLateClock struct{}

func (materializationLateClock) Now() time.Time { return launchClock{}.Now().Add(6 * time.Minute) }

func TestMaterializationRetainedStage(t *testing.T) {
	f := newMaterializationFixture(t)
	first, err := f.worker.MaterializeLaunch(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := dataworker.New(dataworker.Dependencies{Config: f.scope.Config, Controls: f, Store: f, Helper: &materializationHelper{launchJournal: f.helper, f: f}, Launcher: &launchProbe{}, Clock: materializationLateClock{}})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := worker.MaterializeLaunch(context.Background(), f.request)
	if err != nil || !reflect.DeepEqual(first, replayed) || f.resultCalls != 1 || f.awaitCalls != 2 {
		t.Fatal("retained stage was re-executed or mistaken for fresh expired authority", err)
	}
}

func TestMaterializationRuntimePin(t *testing.T) {
	f := newMaterializationFixture(t)
	f.stage.Plan.Executable.ID = "foreign-artifact"
	plan := f.stage.Plan
	f.stage.Claim.Record.Effect.Worker = &plan
	_, err := f.worker.MaterializeLaunch(context.Background(), f.request)
	if f.openCalls != 0 {
		t.Fatal("foreign materialization executable reached opened storage")
	}
	launchError(t, err, api.CodeForbidden)
}
