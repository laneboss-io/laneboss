package lifecycle

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func (store *launchFixtureStore) LaunchDataStage(_ context.Context, scope api.Scope, request api.LaunchDataRequest) (api.LaunchDataStage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	stage, ok := store.dataStages[request.ReservationID]
	if !ok {
		return api.LaunchDataStage{}, launchMissing()
	}
	if stage.Reservation.Config != scope.Config || stage.Reservation.GrantSetID != request.GrantSetID || stage.AgentLeaseID != request.LeaseID {
		return api.LaunchDataStage{}, launchConflict()
	}
	return stage, nil
}

// Model the service-owned child journal and fixed job output. No stage/claim
// supplied by the planner is accepted, and no actual OS/Git worker is claimed.
func (worker *launchFixtureWorker) materializeStage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchData, error) {
	p := worker.ports
	p.calls["materialize-entry"]++
	record, ok := p.store.plans[request.ReservationID]
	if !ok || record.Inputs == nil || record.Reservation.GrantSetID != request.GrantSetID {
		return api.LaunchData{}, launchMissing()
	}
	r := record.Reservation
	stage, exists := p.store.dataStages[r.ID]
	if !exists {
		if record.DataStageID != "" {
			return api.LaunchData{}, launchMissing()
		}
		var parent api.EffectRecord
		for _, effect := range p.store.effects {
			if effect.Effect.PlanLaunch != nil && effect.Effect.PlanLaunch.ReservationID == r.ID {
				parent = effect
			}
		}
		if parent.State != api.EffectClaimed || parent.Effect.Context == nil {
			return api.LaunchData{}, launchConflict()
		}
		runtimeBytes := p.store.blobs[record.Inputs.Sources.Runtime.Manifest.ID]
		var runtime api.RuntimeManifest
		if err := api.DecodeObject(runtimeBytes, &runtime); err != nil {
			return api.LaunchData{}, err
		}
		raw, err := json.Marshal(request)
		if err != nil {
			return api.LaunchData{}, err
		}
		input := p.f.blob(launchIDForTest(), "materialize_input", raw)
		jobGrants := launchClone(p.f.t, record.Inputs.Grants)
		jobGrants.ID, jobGrants.ParentLifeID, jobGrants.SHA256 = launchIDForTest(), r.Target.LifeID, ""
		jobGrants.Resources, jobGrants.Secrets, jobGrants.Profiles, jobGrants.Network, jobGrants.Channels = []api.ResourceGrant{}, []api.SecretGrant{}, []api.ProfileGrant{}, []api.NetworkGrant{}, []api.ChannelGrant{}
		source := record.Inputs.Grants.Data[0]
		source.ID, source.ParentGrantID, source.Destination, source.Access, source.Delivery = launchIDForTest(), record.Inputs.Sources.Project.GrantID, "/job/source", "ro", "bind_ro"
		jobGrants.Data = []api.DataGrant{source}
		raw, err = json.Marshal(jobGrants)
		if err != nil {
			return api.LaunchData{}, err
		}
		jobGrants.SHA256 = digestOf(raw)
		lease := api.WorkerLease{ID: launchIDForTest(), Kind: "materialize", Target: r.Target, OperationID: r.OperationID, EffectID: launchIDForTest(),
			Input: input, RuntimeManifest: record.Inputs.Sources.Runtime.Manifest, GrantSetID: jobGrants.ID, Generation: 1, ExpiresAt: parent.ClaimExpiresAt, ConsumedBy: launchIDForTest()}
		var budget api.Budget
		for _, effect := range p.store.effects {
			if effect.Effect.HelperAllocate != nil && effect.Effect.HelperAllocate.ReservationID == r.ID {
				budget = effect.Effect.HelperAllocate.Budget
			}
		}
		plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize", Executable: runtime.Artifact, Input: input, GrantSetID: jobGrants.ID, Budget: budget,
			Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(lease.ID)}}
		cause := *parent.Effect.Context
		cause.Kind, cause.ID, cause.EffectID = api.InternalLifecycleEffect, launchIDForTest(), lease.EffectID
		child := api.EffectRecord{Effect: api.Effect{ID: lease.EffectID, OperationID: r.OperationID, Context: &cause, Worker: &plan}, Generation: 1, State: api.EffectPending}
		p.store.mu.Lock()
		p.store.effects[lease.EffectID] = child
		p.store.mu.Unlock()
		executor := api.Scope{Config: r.Config, Actor: api.Actor{Kind: "service", ID: "materialize-outbox"}, PolicyGeneration: r.PolicyGeneration}
		claim, err := p.store.ClaimEffect(ctx, executor, api.EffectClaimRequest{EffectID: lease.EffectID,
			ExpectedGeneration: child.Generation, ClaimantID: executor.Actor.ID, Deadline: parent.ClaimExpiresAt})
		if err != nil {
			return api.LaunchData{}, err
		}
		child = claim.Record
		storage, ok := p.storage[request.LeaseID]
		if !ok {
			return api.LaunchData{}, launchMissing()
		}
		stage = api.LaunchDataStage{ID: launchIDForTest(), Reservation: r, Inputs: *record.Inputs, Grants: jobGrants, AgentLeaseID: request.LeaseID, ParentEffectID: parent.Effect.ID,
			Claim: api.EffectLease{Record: child, ClaimID: child.ClaimID, ExpiresAt: child.ClaimExpiresAt}, Worker: lease, Plan: plan, WorkerLaunchID: lease.ConsumedBy,
			Process: api.ProcessHandle{ID: launchIDForTest(), Target: r.Target, ContainmentID: launchIDForTest(), Generation: string(launchIDForTest())}}
		stage.Storage = api.StorageProjection{StageID: stage.ID, Storage: storage, WorkerLeaseID: lease.ID, OpenToken: launchIDForTest(), Generation: 1,
			SourceIdentity: string(record.Inputs.Sources.Project.Object.ID), WorkspaceIdentity: string(storage.WorkspaceID), HomeIdentity: string(storage.Home.RootID),
			Evidence: p.f.blob(launchIDForTest(), "manifest", []byte("fixture opened data roots "+string(stage.ID)))}
		if err := api.ValidateLaunchDataStage(stage, request); err != nil {
			return api.LaunchData{}, err
		}
		p.store.mu.Lock()
		if epoch, present := p.store.fences[r.Target.LifeID]; !present || epoch != r.CancellationEpoch {
			p.store.mu.Unlock()
			return api.LaunchData{}, launchConflict()
		}
		p.store.dataStages[r.ID] = stage
		p.store.effects[lease.EffectID] = child
		p.store.workers[lease.ID] = lease
		p.store.grants[jobGrants.ID] = jobGrants
		p.store.launches[stage.WorkerLaunchID] = api.LaunchRecord{Kind: "worker", ID: stage.WorkerLaunchID, Config: r.Config, Target: r.Target,
			Actor: api.Actor{Kind: "worker", ID: launchIDForTest()}, HostUID: p.allocations[r.ID].UID + 1000,
			ContainmentID: stage.Process.ContainmentID, ProcessGeneration: stage.Process.Generation, GrantSetID: jobGrants.ID, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: 1}
		record.DataStageID, record.Generation = stage.ID, record.Generation+1
		p.store.plans[r.ID] = record
		p.store.mu.Unlock()
	}
	data, err := p.MaterializeLaunch(ctx, request)
	if err != nil {
		outcome := api.EffectOutcome{EffectID: stage.Worker.EffectID, ClaimID: stage.Claim.ClaimID, ExpectedGeneration: stage.Claim.Record.Generation, Status: "failed", Error: failure(err).(*api.Error)}
		if _, completeErr := p.store.CompleteEffect(ctx, api.Scope{Config: r.Config, Actor: api.Actor{Kind: "service", ID: stage.Claim.Record.ClaimantID}}, outcome); completeErr != nil {
			return api.LaunchData{}, completeErr
		}
		return api.LaunchData{}, err
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return api.LaunchData{}, err
	}
	raw, err = api.CanonicalJSON(raw)
	if err != nil {
		return api.LaunchData{}, err
	}
	output := p.f.measuredBlob(launchIDForTest(), "worker_result", raw, r.OperationID, r.Target)
	meta := p.store.metadata[output.ID]
	meta.ACL.Owner = p.store.launches[stage.WorkerLaunchID].Actor
	p.store.metadata[output.ID] = meta
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: stage.Process, State: "exited", Survivors: &zero, ExitCode: &exit, PromptStatus: "completed", ObservedAt: "2030-01-02T03:04:05Z"}
	result := api.LaunchDataResult{StageID: stage.ID, WorkerLeaseID: stage.Worker.ID, EffectID: stage.Worker.EffectID, OperationID: r.OperationID, InputSHA256: stage.Worker.Input.SHA256,
		Data: data, Manifest: data.Materialization.Manifest, ReadBackSHA256: data.Materialization.Manifest.SHA256, Observation: observation,
		ResultReceipt: api.WorkerResultReceipt{LeaseID: stage.Worker.ID, StageID: stage.ID, Generation: stage.Worker.Generation + 1, Result: output, CommittedSeq: p.store.seq + 1}}
	if err := api.ValidateLaunchDataResult(stage, result); err != nil {
		return api.LaunchData{}, err
	}
	if _, err := p.store.CompleteEffect(ctx, api.Scope{Config: r.Config, Actor: api.Actor{Kind: "service", ID: stage.Claim.Record.ClaimantID}},
		api.EffectOutcome{EffectID: stage.Worker.EffectID, ClaimID: stage.Claim.ClaimID, ExpectedGeneration: stage.Claim.Record.Generation,
			Status: "succeeded", Output: &output, Observation: &observation}); err != nil {
		return api.LaunchData{}, err
	}
	if p.dataHook != nil {
		data = launchClone(p.f.t, data)
		p.dataHook(&data)
	}
	return data, nil
}

func TestMaterializeStagePins(t *testing.T) {
	for _, mode := range []string{"missing", "parent", "claim", "grants", "executable", "result", "exit", "bytes", "worker", "lease", "budget"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			stage := launchClone(t, f.store.dataStages[record.Reservation.ID])
			switch mode {
			case "missing":
				delete(f.store.dataStages, record.Reservation.ID)
			case "parent":
				stage.ParentEffectID = "foreign-parent"
			case "claim":
				stage.Claim.Record.State = api.EffectPending
			case "grants":
				stage.Grants.Network = []api.NetworkGrant{{ID: "extra-network"}}
			case "executable":
				stage.Plan.Executable.ID = "foreign-worker"
				stage.Claim.Record.Effect.Worker = &stage.Plan
			case "budget":
				stage.Plan.Budget.WallMS++
				stage.Claim.Record.Effect.Worker = &stage.Plan
			case "result":
				// Replay the actual claimed stage before its completion. A
				// malformed terminal record would stop at effectRecord first.
				f.store.effects[stage.Worker.EffectID] = launchClone(t, stage.Claim.Record)
			case "exit":
				child := f.store.effects[stage.Worker.EffectID]
				exit := 3
				child.Outcome.Observation.ExitCode = &exit
				f.store.effects[stage.Worker.EffectID] = child
			case "bytes":
				child := f.store.effects[stage.Worker.EffectID]
				f.store.blobs[child.Outcome.Output.ID][0] ^= 1
			case "worker":
				principal := f.store.launches[stage.WorkerLaunchID]
				principal.Actor.Kind = "lane"
				f.store.launches[principal.ID] = principal
				child := f.store.effects[stage.Worker.EffectID]
				meta := f.store.metadata[child.Outcome.Output.ID]
				meta.ACL.Owner = principal.Actor
				f.store.metadata[meta.Ref.ID] = meta
			case "lease":
				lease := f.store.workers[stage.Worker.ID]
				lease.RuntimeManifest.ID = "foreign-runtime"
				f.store.workers[lease.ID] = lease
			}
			// Keep duplicate retained facts coherent so the named pin, rather
			// than a later effect-equality check, decides these two refusals.
			if mode == "executable" || mode == "budget" {
				child := f.store.effects[stage.Worker.EffectID]
				child.Effect = stage.Claim.Record.Effect
				f.store.effects[child.Effect.ID] = child
			}
			if mode != "missing" {
				f.store.dataStages[record.Reservation.ID] = stage
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || f.ports.calls["materialize"] != 1 || f.ports.calls["materialize-entry"] != 1 {
				t.Fatalf("materialization replay ignored its real child stage: %s: %v", mode, err)
			}
			// The invalid stage must stop at its shared validator. A later
			// completion-claim refusal must not hide a skipped stage check.
			if mode == "claim" || mode == "grants" {
				want := "materialization stage lacks its claimed fixed worker and opened storage"
				if mode == "grants" {
					want = "materialization worker grants exceed the narrow data job"
				}
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeInvalid || typed.Message != want {
					t.Fatalf("materialization replay ignored its real child stage: %s: want stage validation %q, got %v", mode, want, err)
				}
			}
			if mode == "result" {
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeContainmentUnknown || typed.Message != "materialization child has no measured completion" {
					t.Fatalf("materialization replay ignored its real child stage: %s: want measured completion refusal, got %v", mode, err)
				}
			}
		})
	}
}
