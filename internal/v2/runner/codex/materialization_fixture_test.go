package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Go-only ports contain nullable effect unions and have no frozen JSON field
// map. Verify their exact retained bytes, reject unknown JSON fields, then run
// the actual API stage/worker validators. Wire objects keep retainedObject.
func (m *memoryStore) retainedInternal(ref api.BlobRef, destination any) error {
	data, ok := m.blobs[ref.ID]
	if !ok || m.refs[ref.ID] != ref || hashBytes(data) != ref.SHA256 || int64(len(data)) != ref.Bytes {
		return problem(api.CodeIntegrity, "test internal object bytes differ")
	}
	if _, err := api.CanonicalJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func (m *memoryStore) LaunchDataStage(ctx context.Context, scope api.Scope, request api.LaunchDataRequest) (api.LaunchDataStage, error) {
	var stage api.LaunchDataStage
	if m.readError != nil {
		return stage, m.readError
	}
	ref, ok := m.dataStages[request.ReservationID]
	if scope.Config != "case-codex" || !ok {
		return stage, problem(api.CodeNotFound, "test data stage absent")
	}
	if err := m.retainedInternal(ref, &stage); err != nil {
		return stage, err
	}
	if stage.Reservation.ID != request.ReservationID || stage.Reservation.GrantSetID != request.GrantSetID || stage.AgentLeaseID != request.LeaseID {
		return api.LaunchDataStage{}, problem(api.CodeForbidden, "test data stage selector differs")
	}
	return stage, nil
}

func (m *memoryStore) MaterializationStage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchDataStage, error) {
	return m.LaunchDataStage(ctx, api.Scope{Config: m.cause.Config}, request)
}

func (m *memoryStore) AwaitMaterialization(ctx context.Context, id api.ID) (api.LaunchDataResult, error) {
	var result api.LaunchDataResult
	if m.readError != nil {
		return result, m.readError
	}
	ref, ok := m.dataResults[id]
	if !ok {
		return result, problem(api.CodeNotFound, "test data result absent")
	}
	if err := m.retainedInternal(ref, &result); err != nil {
		return result, err
	}
	if result.StageID != id {
		return api.LaunchDataResult{}, problem(api.CodeIntegrity, "test data result selector differs")
	}
	return result, nil
}

// Private synthetic stages use actual retained bytes and physical workspace
// identity. They prove DTO correlation, not a real confined copy/Git worker.
func (f *runnerFixture) prepareDataStage(r api.LaunchReservation, inputs api.LaunchInputs, helper api.HelperLease, storage api.LaunchStorage) {
	f.t.Helper()
	m := f.store
	suffix := strconv.FormatUint(uint64(r.Target.Run), 10)
	root, err := os.OpenRoot(f.physicalWork)
	if err != nil {
		f.t.Fatal(err)
	}
	workKey, err := homeKey(root)
	closeErr := root.Close()
	if err != nil || closeErr != nil {
		f.t.Fatal(err, closeErr)
	}
	snapshot := m.keepClass([]byte("synthetic private workspace snapshot bytes"), "manifest")
	workspace := api.Workspace{ID: storage.WorkspaceID, ProjectID: inputs.Sources.Project.ProjectID, Base: inputs.Sources.Project.Base,
		Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main", Snapshot: snapshot}
	materialization := api.Materialization{GrantSetID: r.GrantSetID, Manifest: m.keepClass([]byte("synthetic measured materialization receipt"), "manifest"),
		Objects: []api.MaterializedObject{{GrantID: inputs.Sources.Project.GrantID, WorkspaceID: workspace.ID,
			SourceIdentity: string(inputs.Sources.Project.Object.SHA256), DestinationIdentity: workKey, SnapshotSHA256: snapshot.SHA256}}}
	data := api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: helper.ID, Source: inputs.Sources.Project,
		Workspace: workspace, Home: storage.Home, Materialization: materialization}
	jobGrants := fixtureCopy(inputs.Grants)
	jobGrants.ID, jobGrants.ParentLifeID = api.ID("data_grants_"+suffix), r.Target.LifeID
	jobGrants.Resources, jobGrants.Secrets = []api.ResourceGrant{}, []api.SecretGrant{}
	jobGrants.Profiles, jobGrants.Network, jobGrants.Channels = []api.ProfileGrant{}, []api.NetworkGrant{}, []api.ChannelGrant{}
	grant := inputs.Grants.Data[0]
	grant.ID, grant.ParentGrantID, grant.Access, grant.Destination, grant.Delivery = api.ID("job_source_"+suffix), inputs.Sources.Project.GrantID, "ro", "/job/source", "bind_ro"
	jobGrants.Data = []api.DataGrant{grant}
	jobGrants.SHA256 = f.keepJSON(jobGrants, "manifest").SHA256
	input := f.keepJSON(struct {
		Reservation api.LaunchReservation
		Inputs      api.LaunchInputs
		Storage     api.LaunchStorage
	}{r, inputs, storage}, "materialize_input")
	worker := api.WorkerLease{ID: api.ID("data_worker_" + suffix), Kind: "materialize", Target: r.Target, OperationID: r.OperationID,
		EffectID: api.ID("data_effect_" + suffix), Input: input, RuntimeManifest: inputs.Sources.Runtime.Manifest,
		GrantSetID: jobGrants.ID, Generation: 1, ExpiresAt: f.request.Slot.ExpiresAt, ConsumedBy: api.ID("data_launch_" + suffix)}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize", Executable: f.request.Executable,
		Argv:  []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(worker.ID)},
		Input: input, GrantSetID: jobGrants.ID, Budget: f.request.Budget}
	plan.Executable.ID = "synthetic_installed_worker"
	cause := m.cause
	cause.ID, cause.Kind, cause.EffectID = api.ID("data_intent_"+suffix), api.InternalObjectRetain, worker.EffectID
	claim := api.EffectRecord{Effect: api.Effect{ID: worker.EffectID, OperationID: r.OperationID, Context: &cause, Worker: &plan},
		State: api.EffectClaimed, Generation: 1, ClaimID: api.ID("data_claim_" + suffix), ClaimantID: cause.Actor.ID, ClaimExpiresAt: worker.ExpiresAt}
	stage := api.LaunchDataStage{ID: api.ID("data_stage_" + suffix), Reservation: r, Inputs: fixtureCopy(inputs), Grants: jobGrants,
		AgentLeaseID: helper.ID, ParentEffectID: m.cause.EffectID, Claim: api.EffectLease{Record: fixtureCopy(claim), ClaimID: claim.ClaimID, ExpiresAt: worker.ExpiresAt},
		Worker: worker, WorkerLaunchID: worker.ConsumedBy, Plan: plan,
		Process: api.ProcessHandle{ID: api.ID("data_process_" + suffix), Target: r.Target, ContainmentID: api.ID("data_containment_" + suffix), Generation: "synthetic_data_generation"}}
	stage.Storage = api.StorageProjection{StageID: stage.ID, Storage: storage, WorkerLeaseID: worker.ID, OpenToken: api.ID("open_data_" + suffix),
		Generation: 1, SourceIdentity: materialization.Objects[0].SourceIdentity, WorkspaceIdentity: workKey, HomeIdentity: f.home.key,
		Evidence: m.keepClass([]byte("synthetic held descriptor projection"), "manifest")}
	zero, survivors := 0, uint64(0)
	result := api.LaunchDataResult{StageID: stage.ID, WorkerLeaseID: worker.ID, EffectID: worker.EffectID, OperationID: r.OperationID,
		InputSHA256: input.SHA256, Data: data, Manifest: materialization.Manifest, ReadBackSHA256: materialization.Manifest.SHA256,
		Observation: api.ProcessObservation{Handle: stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: api.Timestamp(f.clock.Now().Format(time.RFC3339Nano))}}
	result.ResultReceipt = api.WorkerResultReceipt{LeaseID: worker.ID, StageID: stage.ID, Generation: 2, CommittedSeq: 1, Result: f.keepJSON(data, "worker_result")}
	if err := api.ValidateLaunchDataResult(stage, result); err != nil {
		f.t.Fatal("invalid materialization fixture", err)
	}
	m.dataStages[r.ID], m.dataResults[stage.ID] = f.keepJSON(stage, "record"), f.keepJSON(result, "record")
	complete := fixtureCopy(claim)
	complete.State, complete.Generation = api.EffectCompleted, 2
	complete.Outcome = &api.EffectOutcome{EffectID: worker.EffectID, Status: "succeeded", Output: &result.ResultReceipt.Result, Observation: &result.Observation}
	m.effects[worker.EffectID] = complete
	record := m.plans[r.ID]
	record.DataStageID = stage.ID
	m.plans[r.ID] = record
	f.service.deps.Materialization = m
}
