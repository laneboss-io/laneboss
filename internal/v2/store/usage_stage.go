package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type usageStage struct {
	Job         api.UsageJob
	Claim       api.EffectLease
	Native      *channelLaunch
	Observation *api.ProcessObservation
}

func (s *Service) usageOwner(ctx context.Context, db queryer, scope api.Scope) error {
	if err := s.scope(ctx, db, scope); err != nil {
		return err
	}
	if scope.Actor.Kind != "service" || scope.Connection != nil || scope.Frame != nil || scope.Request.Method != "" {
		return fault(api.CodeForbidden, "usage preparation requires its installed service owner")
	}
	return nil
}

func (s *Service) usageFence(ctx context.Context, db queryer, job api.UsageJob) error {
	if err := api.ValidateUsageJob(job, s.deps.Clock.Now()); err != nil {
		return err
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", job.Lease.Target.LifeID, &lane); err != nil {
		return err
	}
	if lane.Cleaned || lane.Run != job.Lease.Target.Run || lane.CancellationEpoch != job.CancellationEpoch || lane.LaunchID != job.Input.Request.LaunchID {
		return fault(api.CodeCancelled, "usage causing run changed or was collected")
	}
	var parent api.GrantSet
	if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &parent); err != nil {
		return err
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return err
	}
	if parent.Revoked || !future(parent.ExpiresAt, s.deps.Clock.Now()) || parent.PolicyGeneration != job.Grants.PolicyGeneration || policy.Generation != job.Grants.PolicyGeneration {
		return fault(api.CodeConflict, "usage policy or causing grants changed")
	}
	selected := false
	for _, p := range parent.Profiles {
		selected = selected || p.ID == job.Input.Request.ProfileGrantID && p.ProfileID == job.Input.Request.ProfileID && p.Provider == job.Input.Request.Provider && p.Driver == api.DriverClaudock && future(p.ExpiresAt, s.deps.Clock.Now())
	}
	if !selected {
		return fault(api.CodeForbidden, "usage profile is outside its causing delegation")
	}
	return nil
}

func (s *Service) PrepareUsageJob(ctx context.Context, scope api.Scope, input api.UsageCredentialInput) (job api.UsageJob, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return job, err
	}
	if err := s.usageOwner(ctx, s.db, scope); err != nil {
		return job, err
	}
	r := input.Request
	keyBytes, err := canonicalValue(input)
	if err != nil {
		return job, err
	}
	key := api.ID(hash(keyBytes))
	var previous api.ID
	if err := storedProjection(ctx, s.db, "usage_request", key, &previous); err == nil {
		stage, err := usageStageFor(ctx, s.db, previous)
		if err != nil {
			return job, err
		}
		if stage.Observation == nil {
			if !sameValue(stage.Job.Input, input) {
				return job, fault(api.CodeIntegrity, "usage request digest changed its retained input")
			}
			return stage.Job, s.usageFence(ctx, s.db, stage.Job)
		}
	} else if !absent(err) {
		return job, err
	}
	parent, err := s.launchBinding(ctx, s.db, r.LaunchID)
	if err != nil {
		return job, err
	}
	if parent.Recovery == nil || parent.Record.Target != r.Target || parent.Record.Config != scope.Config || parent.Record.Revoked {
		return job, fault(api.CodeForbidden, "usage request has no exact retained causing launch")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", parent.Recovery.PlanID, &plan); err != nil {
		return job, err
	}
	if api.ValidateLaunchPlanRecord(plan) != nil || plan.Plan == nil || api.ValidateLaunchBindingPlan(parent, *plan.Plan) != nil || plan.Plan.Runner.Executable != r.Executable || plan.Inputs.Sources.Runtime.Manifest != r.RuntimeManifest {
		return job, fault(api.CodeIntegrity, "usage runtime differs from the opened causing plan")
	}
	meta, raw, err := objectRow(ctx, s.db, r.RuntimeManifest.ID)
	if err != nil {
		return job, err
	}
	var runtime api.RuntimeManifest
	if meta.Ref != r.RuntimeManifest || meta.Origin != "service" || api.DecodeObject(raw, &runtime) != nil {
		return job, fault(api.CodeIntegrity, "usage runtime has no protected exact manifest")
	}
	ids := make([]api.ID, 6)
	for n := range ids {
		ids[n], err = wire.NewID()
		if err != nil {
			return job, err
		}
	}
	now := s.deps.Clock.Now()
	expires := api.Timestamp(now.Add(60 * time.Second).UTC().Format(time.RFC3339Nano))
	for _, bound := range []api.Timestamp{input.Source.ExpiresAt, plan.Inputs.Grants.ExpiresAt} {
		end, err := time.Parse(time.RFC3339Nano, string(bound))
		if err != nil || !end.After(now) {
			return job, fault(api.CodeForbidden, "usage source or causing grant is expired")
		}
		if before, _ := time.Parse(time.RFC3339Nano, string(expires)); end.Before(before) {
			expires = bound
		}
	}
	job = api.UsageJob{ID: ids[0], Input: input, LaunchID: ids[1], Actor: api.Actor{Kind: "worker", ID: ids[2]}, ParentLeaseID: parent.Record.UIDLeaseID, CancellationEpoch: plan.Reservation.CancellationEpoch}
	job.Grants = api.GrantSet{ID: ids[3], LifeID: r.Target.LifeID, ParentLifeID: plan.Reservation.ParentLifeID, Generation: 1, PolicyGeneration: plan.Reservation.PolicyGeneration,
		ExpiresAt: expires, Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Profiles: []api.ProfileGrant{}, Channels: []api.ChannelGrant{}, Network: []api.NetworkGrant{}, Secrets: []api.SecretGrant{input.Source}}
	for _, network := range plan.Inputs.Grants.Network {
		if !future(network.ExpiresAt, now) {
			return job, fault(api.CodeForbidden, "usage network grant has expired")
		}
		network.Delegate = false
		job.Grants.Network = append(job.Grants.Network, network)
	}
	sealed, err := canonicalValue(job.Grants)
	if err != nil {
		return job, err
	}
	job.Grants.SHA256 = api.Digest(hash(sealed))
	job.Lease = api.WorkerLease{ID: ids[4], Kind: "usage", Target: r.Target, OperationID: r.OperationID, EffectID: ids[5], RuntimeManifest: r.RuntimeManifest, GrantSetID: job.Grants.ID, Generation: 1, ExpiresAt: expires}
	job.Runtime = plan.Inputs.Sources.Runtime
	job.Runtime.Executable = runtime.Bootstrap
	job.Cause = api.InternalIntent{ID: job.ID, Kind: api.InternalObjectRetain, Config: scope.Config, Actor: scope.Actor, RequestedBy: plan.Reservation.RequestedBy,
		Target: r.Target, CauseOperationID: r.OperationID, CauseRequestID: plan.Reservation.RequestID, EffectID: job.Lease.EffectID, CancellationEpoch: job.CancellationEpoch}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer finish(tx, &resultErr)
	encoded, err := canonicalValue(input)
	if err != nil {
		return job, err
	}
	inputID, err := wire.NewID()
	if err != nil {
		return job, err
	}
	job.Lease.Input, err = s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, scope, api.ObjectWrite{ObjectKey: inputID, Class: "usage_input", Bytes: encoded, SHA256: api.Digest(hash(encoded)), Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: r.Target.LifeID, Audience: "service", Generation: 1}}, r.OperationID, api.Timestamp(now.UTC().Format(timeFormat)))
	if err != nil {
		return job, err
	}
	budget := plan.Plan.Budget
	budget.WallMS, budget.CPUSeconds, budget.MemoryBytes = min(budget.WallMS, 60000), min(budget.CPUSeconds, 10), min(budget.MemoryBytes, 256<<20)
	budget.Processes, budget.DiskBytes, budget.SpendMicros = min(budget.Processes, 16), min(budget.DiskBytes, 4<<20), 0
	job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "usage", Executable: runtime.Bootstrap, Input: job.Lease.Input, GrantSetID: job.Grants.ID, Budget: budget,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)}}
	if err := s.usageFence(ctx, tx, job); err != nil {
		return job, err
	}
	effect := api.Effect{ID: job.Lease.EffectID, OperationID: r.OperationID, Context: &job.Cause, Worker: &job.Plan}
	effectBytes, err := json.Marshal(effect)
	if err != nil {
		return job, err
	}
	if err := validateEffect(effect); err != nil {
		return job, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO effects(id,operation_id,data) VALUES(?,?,?)", string(effect.ID), string(effect.OperationID), effectBytes); err != nil {
		return job, err
	}
	state, err := encodeEffectState(api.EffectRecord{Effect: effect, State: api.EffectPending, Generation: 1})
	if err != nil {
		return job, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO effect_states(id,data) VALUES(?,?)", string(effect.ID), state); err != nil {
		return job, err
	}
	for _, value := range []struct {
		kind string
		id   api.ID
		data any
	}{{"usage_stage", job.ID, usageStage{Job: job, Native: &channelLaunch{ID: job.LaunchID, Actor: job.Actor, Plan: job.Plan}}}, {"grants", job.Grants.ID, job.Grants}, {"worker_lease", job.Lease.ID, job.Lease}} {
		if err := put(ctx, tx, value.kind, value.id, 1, value.data); err != nil {
			return job, err
		}
	}
	if err := put(ctx, tx, "usage_request", key, 1, job.ID); err != nil {
		return job, err
	}
	return job, tx.Commit()
}

func usageStageFor(ctx context.Context, db queryer, id api.ID) (result usageStage, err error) {
	err = storedProjection(ctx, db, "usage_stage", id, &result)
	return result, err
}

func (s *Service) usageClaim(ctx context.Context, db queryer, scope api.Scope, claim api.EffectLease, writer bool) (usageStage, error) {
	var stage usageStage
	if err := s.usageOwner(ctx, db, scope); err != nil {
		return stage, err
	}
	current, err := effectRow(ctx, db, claim.Record.Effect.ID)
	if err != nil {
		return stage, err
	}
	if !api.EffectLeaseClaimed(claim) || !sameValue(current, claim.Record) || current.Outcome != nil || current.Effect.Worker == nil || current.Effect.Worker.Kind != "usage" || current.Effect.Context == nil ||
		!future(claim.ExpiresAt, s.deps.Clock.Now()) || writer && current.ClaimantID != scope.Actor.ID {
		return stage, fault(api.CodeConflict, "usage job lost its current actual claim")
	}
	stage, err = usageStageFor(ctx, db, current.Effect.Context.ID)
	if err != nil {
		return stage, err
	}
	if !sameValue(*current.Effect.Worker, stage.Job.Plan) || current.Effect.ID != stage.Job.Lease.EffectID {
		return stage, fault(api.CodeIntegrity, "usage job changed its fixed worker")
	}
	stage.Claim = claim
	return stage, s.usageFence(ctx, db, stage.Job)
}

func saveUsage(ctx context.Context, tx *sql.Tx, stage usageStage) error {
	return put(ctx, tx, "usage_stage", stage.Job.ID, stage.Claim.Record.Generation+1, stage)
}

func (s *Service) UsageStage(ctx context.Context, scope api.Scope, id api.ID) (api.UsageStage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.usageOwner(ctx, s.db, scope); err != nil {
		return api.UsageStage{}, err
	}
	stage, err := usageStageFor(ctx, s.db, id)
	if err != nil {
		return api.UsageStage{}, err
	}
	result := api.UsageStage{Job: stage.Job, Claim: stage.Claim}
	if stage.Native != nil {
		result.Allocation, result.Endpoint, result.Handoff = stage.Native.Allocation, stage.Native.Endpoint, stage.Native.Handoff
	}
	return result, nil
}
