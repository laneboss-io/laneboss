package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	grantmanifest "laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Preparation is deliberately durable before the helper opens roots. The
// parent claim here authorizes preparation only; after sealing, Claim is the
// actual child claim. Only a bound/opened stage passes ValidateLaunchDataStage.
type dataStageRecord struct {
	Stage      api.LaunchDataStage
	Generation api.Generation
	Phase      string
	Parent     api.EffectLease
	Allocation api.HelperLease
	Output     api.BlobRef
	Handoff    *api.PreparedSpecHandoff
	Endpoint   *api.InstalledBinding
	Actor      api.Actor
	BindIntent api.ID
	BindEvent  api.ID
}

// This closed private body is shared with the fixed grants/dataworker and
// administrator consumers. It contains no host paths or execution authority.
type dataJobInput struct {
	Schema      string                  `json:"schema"`
	StageID     api.ID                  `json:"stage_id"`
	Reservation api.LaunchReservation   `json:"reservation"`
	Source      api.ProjectLaunchSource `json:"source"`
	Storage     api.StorageProjection   `json:"storage"`
	Grants      api.GrantSet            `json:"grants"`
	Output      api.BlobRef             `json:"output"`
	Budget      api.Budget              `json:"budget"`
}

func (s *Service) dataScope(ctx context.Context, db queryer, scope api.Scope) error {
	if err := s.available(); err != nil {
		return err
	}
	if err := s.scope(ctx, db, scope); err != nil {
		return err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" || scope.Request.Method != "" || scope.Frame != nil {
		return fault(api.CodeForbidden, "materialization control requires its private service scope")
	}
	return nil
}

func (s *Service) dataParent(ctx context.Context, db queryer, scope api.Scope, plan api.LaunchPlanRecord, claims ...api.LaunchClaim) (api.EffectLease, error) {
	if len(claims) != 1 || claims[0].ReservationID != plan.Reservation.ID || claims[0].ClaimantID != scope.Actor.ID {
		return api.EffectLease{}, fault(api.CodeConflict, "materialization requires its explicit current planning selector")
	}
	parent, err := effectRow(ctx, db, claims[0].EffectID)
	if err != nil {
		return api.EffectLease{}, err
	}
	if err := api.CheckPlanningClaim(parent, claims[0], s.deps.Config, s.deps.Clock.Now()); err != nil {
		return api.EffectLease{}, err
	}
	if err := s.checkDataParent(ctx, db, plan, parent); err != nil {
		return api.EffectLease{}, err
	}
	return api.EffectLease{Record: parent, ClaimID: parent.ClaimID, ExpiresAt: parent.ClaimExpiresAt}, nil
}

// checkDataParent checks a fresh durable record against the immutable stage.
// It does not change the caller's identity or authorize writes as the parent.
func (s *Service) checkDataParent(ctx context.Context, db queryer, plan api.LaunchPlanRecord, parent api.EffectRecord) error {
	claim := api.PlanningClaim(plan.Reservation.ID, api.EffectLease{Record: parent, ClaimID: parent.ClaimID, ExpiresAt: parent.ClaimExpiresAt})
	if err := api.CheckPlanningClaim(parent, claim, s.deps.Config, s.deps.Clock.Now()); err != nil {
		return err
	}
	r, cause := plan.Reservation, parent.Effect.Context
	if cause.Target != r.Target || cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID ||
		cause.RequestedBy != r.RequestedBy || cause.CancellationEpoch != r.CancellationEpoch {
		return fault(api.CodeConflict, "materialization parent differs from its reserved cause")
	}
	return s.currentLaunch(ctx, db, plan)
}

// LaunchDataStage issues a preparation record once, under the sourced plan's
// current claim and CAS. A nonempty selector is always reloaded, never repaired
// by allocating another stage. No helper work happens under this writer lock.
func (s *Service) LaunchDataStage(ctx context.Context, scope api.Scope, request api.LaunchDataRequest) (result api.LaunchDataStage, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if !wire.ValidID(string(request.ReservationID)) || !wire.ValidID(string(request.GrantSetID)) || !wire.ValidID(string(request.LeaseID)) {
		return result, wire.Invalid("invalid materialization reservation selector")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", request.ReservationID, &plan); err != nil {
		return result, err
	}
	if err := s.checkLaunchBytes(ctx, s.db, plan); err != nil {
		return result, err
	}
	if plan.Reservation.GrantSetID != request.GrantSetID || plan.Inputs == nil || plan.Phase == "failed" {
		return result, fault(api.CodeConflict, "materialization selector differs from the sourced reservation")
	}
	source, err := s.materializationProjectSource(*plan.Inputs)
	if err != nil {
		return result, err
	}
	if plan.DataStageID != "" {
		if err := s.currentLaunch(ctx, s.db, plan); err != nil {
			return result, err
		}
		var saved dataStageRecord
		if err := storedProjection(ctx, s.db, "data_stage", plan.DataStageID, &saved); err != nil {
			return result, err
		}
		if err := s.checkDataRecord(ctx, s.db, plan, saved); err != nil {
			return result, err
		}
		if saved.Stage.AgentLeaseID != request.LeaseID {
			return result, fault(api.CodeConflict, "materialization agent allocation changed")
		}
		if request.Claim != (api.LaunchClaim{}) {
			if request.Claim.ReservationID != saved.Stage.Reservation.ID || request.Claim.EffectID != saved.Stage.ParentEffectID {
				return result, fault(api.CodeConflict, "materialization selector differs from its retained planning effect")
			}
			if _, err := s.dataParent(ctx, s.db, scope, plan, request.Claim); err != nil {
				return result, err
			}
		}
		return saved.Stage, nil
	}
	if plan.Phase != "sourced" {
		return result, fault(api.CodeConflict, "materialization requires the sourced plan phase")
	}
	parent, err := s.dataParent(ctx, s.db, scope, plan, request.Claim)
	if err != nil {
		return result, err
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return result, err
	}
	allocation, err := s.dataAllocation(ctx, s.db, plan, request.LeaseID)
	if err != nil {
		return result, err
	}
	inputs, r := *plan.Inputs, plan.Reservation
	runtimeMeta, runtimeBytes, err := objectRow(ctx, s.db, inputs.Sources.Runtime.Manifest.ID)
	if err != nil {
		return result, err
	}
	if runtimeMeta.Ref != inputs.Sources.Runtime.Manifest || runtimeMeta.Origin != "service" {
		return result, fault(api.CodeIntegrity, "materialization runtime differs from its enrolled immutable bytes")
	}
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(runtimeBytes, &runtime); err != nil {
		return result, err
	}
	if runtime.Schema != "laneboss.runtime.v2" || runtime.Generation == 0 || !wire.ValidID(string(runtime.Artifact.ID)) || !wire.ValidDigest(string(runtime.Artifact.SHA256)) || runtime.Artifact.Version == "" {
		return result, fault(api.CodeIntegrity, "materialization lacks the enrolled fixed worker artifact")
	}
	// Retain the immutable parent effect, not its expiring attempt lease.
	parentPin := api.EffectLease{Record: api.EffectRecord{Effect: parent.Record.Effect}}
	saved := dataStageRecord{Phase: "reserved", Generation: 1, Parent: parentPin, Actor: api.Actor{Kind: "worker"}}
	stage := &saved.Stage
	stage.Reservation, stage.Inputs, stage.AgentLeaseID, stage.ParentEffectID, stage.Claim = r, inputs, allocation.ID, parent.Record.Effect.ID, parentPin
	stage.ParentClaim = api.StablePlanningPin(r.ID, parent.Record.Effect.ID)
	for _, id := range []*api.ID{&stage.ID, &stage.WorkerLaunchID, &stage.Worker.ID, &stage.Worker.EffectID, &stage.Grants.ID, &saved.Actor.ID, &saved.BindIntent, &saved.BindEvent} {
		*id, err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	expires := parent.ExpiresAt
	for _, limit := range []api.Timestamp{inputs.Grants.ExpiresAt} {
		if !future(limit, s.deps.Clock.Now()) {
			return result, fault(api.CodeConflict, "materialization source grants expired")
		}
		a, _ := time.Parse(time.RFC3339Nano, string(expires))
		b, _ := time.Parse(time.RFC3339Nano, string(limit))
		if b.Before(a) {
			expires = limit
		}
	}
	a, _ := time.Parse(time.RFC3339Nano, string(expires))
	b, _ := time.Parse(time.RFC3339Nano, string(source.ExpiresAt))
	if b.Before(a) {
		expires = source.ExpiresAt
	}
	dataID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	stage.Grants = api.GrantSet{ID: stage.Grants.ID, LifeID: r.Target.LifeID, ParentLifeID: r.Target.LifeID, Generation: 1, PolicyGeneration: r.PolicyGeneration, ExpiresAt: expires,
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: dataID, ParentGrantID: source.ID, SourceObjectID: source.SourceObjectID, SourceSHA256: source.SourceSHA256, RelativePath: ".", Access: "ro", Delivery: "bind_ro", Destination: "/job/source", ExpiresAt: expires, HistoryScope: source.HistoryScope}}}
	grantBytes, err := canonicalValue(stage.Grants)
	if err != nil {
		return result, err
	}
	stage.Grants.SHA256 = api.Digest(hash(grantBytes))
	stage.Worker = api.WorkerLease{ID: stage.Worker.ID, EffectID: stage.Worker.EffectID, Kind: "materialize", Target: r.Target, OperationID: r.OperationID, RuntimeManifest: inputs.Sources.Runtime.Manifest, GrantSetID: stage.Grants.ID, Generation: 1, ExpiresAt: expires, ConsumedBy: stage.WorkerLaunchID}
	budget, err := allocationBudget(ctx, s.db, plan, allocation.ID)
	if err != nil {
		return result, err
	}
	stage.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize", Executable: runtime.Artifact, GrantSetID: stage.Grants.ID, Budget: budget,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(stage.Worker.ID)}}
	if !positiveBudget(stage.Plan.Budget) {
		return result, fault(api.CodeBudget, "materialization lacks a positive allocation budget")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "data_stage", stage.ID, 1, saved); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "worker_lease", stage.Worker.ID, stage.Worker.Generation, stage.Worker); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "grants", stage.Grants.ID, stage.Grants.Generation, stage.Grants); err != nil {
		return result, err
	}
	plan.DataStageID, plan.Generation = stage.ID, plan.Generation+1
	if err := put(ctx, tx, "launch_plan", r.ID, plan.Generation, plan); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return *stage, nil
}

// The worker copies one project into the private workspace. Other agent data
// deliveries stay intact in Inputs.Grants for their export owner. dataParent
// and checkDataRecord compare that complete set to the actual issued record,
// including every member's ID, source, path, access, delivery and destination.
func (s *Service) materializationProjectSource(inputs api.LaunchInputs) (api.DataGrant, error) {
	var source api.DataGrant
	count := 0
	seen := map[api.ID]bool{}
	for _, grant := range inputs.Grants.Data {
		if seen[grant.ID] {
			return api.DataGrant{}, fault(api.CodeForbidden, "materialization data grant identity is duplicated")
		}
		seen[grant.ID] = true
		if grant.ID == inputs.Sources.Project.GrantID {
			source = grant
			count++
		} else if !future(grant.ExpiresAt, s.deps.Clock.Now()) {
			return api.DataGrant{}, fault(api.CodeForbidden, "materialization data grant expired")
		}
	}
	if count != 1 || source.RelativePath != "." || source.Delivery != "copy" || !future(source.ExpiresAt, s.deps.Clock.Now()) {
		return api.DataGrant{}, fault(api.CodeUnsupported, "materialization requires its single granted copy source")
	}
	return source, nil
}

func (s *Service) dataAllocation(ctx context.Context, db queryer, plan api.LaunchPlanRecord, id api.ID) (api.HelperLease, error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT effect_states.data FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND json_extract(effect_states.data,'$.Outcome.HelperLease.id')=?", string(plan.Reservation.OperationID), string(id)).Scan(&raw); err != nil {
		if cause := ctx.Err(); cause != nil {
			return api.HelperLease{}, cause
		}
		if errors.Is(err, sql.ErrNoRows) {
			return api.HelperLease{}, fault(api.CodeForbidden, "materialization has no completed agent allocation")
		}
		return api.HelperLease{}, err
	}
	var record api.EffectRecord
	if err := decodeStored(raw, &record); err != nil {
		return api.HelperLease{}, err
	}
	if record.Effect.HelperAllocate == nil || record.Effect.HelperAllocate.ReservationID != plan.Reservation.ID || record.Effect.HelperAllocate.RuntimeManifestID != plan.Inputs.Sources.Runtime.Manifest.ID || record.Outcome == nil || record.Outcome.Status != "succeeded" || record.Outcome.HelperLease == nil || record.Outcome.HelperLease.ID != id || record.Effect.Context.Target != plan.Reservation.Target {
		return api.HelperLease{}, fault(api.CodeConflict, "materialization agent allocation drifted")
	}
	return *record.Outcome.HelperLease, measuredOutcome(record.Effect, *record.Outcome)
}

func allocationBudget(ctx context.Context, db queryer, plan api.LaunchPlanRecord, id api.ID) (api.Budget, error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT effects.data FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND json_extract(effect_states.data,'$.Outcome.HelperLease.id')=?", string(plan.Reservation.OperationID), string(id)).Scan(&raw); err != nil {
		if cause := ctx.Err(); cause != nil {
			return api.Budget{}, cause
		}
		return api.Budget{}, err
	}
	var effect api.Effect
	if err := decodeStored(raw, &effect); err != nil {
		return api.Budget{}, err
	}
	if effect.HelperAllocate == nil {
		return api.Budget{}, fault(api.CodeIntegrity, "materialization budget lost its allocation request")
	}
	return effect.HelperAllocate.Budget, nil
}

func (s *Service) checkDataRecord(ctx context.Context, db queryer, plan api.LaunchPlanRecord, saved dataStageRecord) error {
	stage := saved.Stage
	if stage.ParentClaim != (api.LaunchClaim{}) && (stage.ParentClaim.ReservationID != plan.Reservation.ID || stage.ParentClaim.EffectID != stage.ParentEffectID) {
		return fault(api.CodeIntegrity, "materialization stage changed its retained parent claim selector")
	}
	if saved.Generation == 0 || plan.DataStageID != stage.ID || !sameValue(stage.Reservation, plan.Reservation) || plan.Inputs == nil || !sameValue(stage.Inputs, *plan.Inputs) || stage.ParentEffectID != saved.Parent.Record.Effect.ID {
		return fault(api.CodeIntegrity, "materialization retained stage pins changed")
	}
	switch saved.Phase {
	case "reserved", "sealed", "claimed", "bound", "opened":
	default:
		return fault(api.CodeIntegrity, "materialization retained stage has an unknown phase")
	}
	for _, expected := range []api.GrantSet{stage.Inputs.Grants, stage.Grants} {
		var actual api.GrantSet
		if err := storedProjection(ctx, db, "grants", expected.ID, &actual); err != nil {
			return err
		}
		if !sameValue(actual, expected) || actual.Revoked {
			return fault(api.CodeConflict, "materialization retained grants changed")
		}
	}
	var lease api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", stage.Worker.ID, &lease); err != nil {
		return err
	}
	want := stage.Worker
	want.Generation = lease.Generation
	if lease.Generation < stage.Worker.Generation || lease.Generation > stage.Worker.Generation+1 || lease != want {
		return fault(api.CodeConflict, "materialization worker lease drifted")
	}
	if saved.Phase == "bound" || saved.Phase == "opened" {
		return api.ValidateLaunchDataStage(stage, api.LaunchDataRequest{ReservationID: plan.Reservation.ID, GrantSetID: plan.Reservation.GrantSetID, LeaseID: stage.AgentLeaseID})
	}
	return nil
}

func (s *Service) loadDataStage(ctx context.Context, db queryer, scope api.Scope, id api.ID, current bool) (dataStageRecord, error) {
	var saved dataStageRecord
	if err := s.dataScope(ctx, db, scope); err != nil {
		return saved, err
	}
	if err := storedProjection(ctx, db, "data_stage", id, &saved); err != nil {
		return saved, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", saved.Stage.Reservation.ID, &plan); err != nil {
		return saved, err
	}
	if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
		return saved, err
	}
	if err := s.checkDataRecord(ctx, db, plan, saved); err != nil {
		return saved, err
	}
	if current {
		if _, err := s.materializationProjectSource(saved.Stage.Inputs); err != nil {
			return saved, err
		}
		if err := s.dispatchAllowed(ctx, db); err != nil {
			return saved, err
		}
		current, err := effectRow(ctx, db, saved.Stage.ParentEffectID)
		if err != nil {
			return saved, err
		}
		claim := api.PlanningClaim(plan.Reservation.ID, api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt})
		if _, err := s.dataParent(ctx, db, scope, plan, claim); err != nil {
			return saved, err
		}
		if !sameValue(current.Effect, saved.Parent.Record.Effect) {
			return saved, fault(api.CodeConflict, "materialization parent effect changed")
		}
	}
	return saved, nil
}

func (s *Service) DataStage(ctx context.Context, scope api.Scope, id api.ID) (api.LaunchDataStage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, false)
	return saved.Stage, err
}

func (s *Service) saveDataStage(ctx context.Context, tx *sql.Tx, saved dataStageRecord) error {
	saved.Generation++
	return put(ctx, tx, "data_stage", saved.Stage.ID, saved.Generation, saved)
}

// SealDataStage freezes exact input bytes, the inert candidate tree and the
// immutable child effect together. An opened projection can never be replaced.
func (s *Service) SealDataStage(ctx context.Context, scope api.Scope, id api.ID, projection api.StorageProjection, allocation api.HelperLease) (result api.LaunchDataStage, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, true)
	if err != nil {
		return result, err
	}
	stage := &saved.Stage
	if saved.Phase != "reserved" {
		if stage.Storage != projection || saved.Allocation != allocation {
			return result, fault(api.CodeConflict, "materialization opened storage or worker allocation changed")
		}
		return *stage, nil
	}
	p := projection
	if p.StageID != id || p.WorkerLeaseID != stage.Worker.ID || p.Storage.ReservationID != stage.Reservation.ID || p.Storage.LeaseID != stage.AgentLeaseID || p.Storage.Target != stage.Reservation.Target || p.Storage.WorkspaceID == "" || p.Storage.Home.Home.WorkspaceID != p.Storage.WorkspaceID || p.Storage.Home.LifeID != stage.Reservation.Target.LifeID || !wire.ValidID(string(p.OpenToken)) || p.Generation == 0 || p.SourceIdentity == "" || p.WorkspaceIdentity == "" || p.HomeIdentity == "" || p.Evidence.Class != "manifest" || !wire.ValidDigest(string(p.Evidence.SHA256)) || p.Evidence.Bytes <= 0 || allocation.ID == stage.AgentLeaseID || allocation.ID == "" || allocation.UID == 0 || allocation.GID == 0 || allocation.ContainmentID == "" || allocation.EndpointGeneration == 0 {
		return result, fault(api.CodeIntegrity, "materialization helper did not return its exact held storage and distinct worker allocation")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", stage.Reservation.ID, &plan); err != nil {
		return result, err
	}
	agent, err := s.dataAllocation(ctx, s.db, plan, stage.AgentLeaseID)
	if err != nil {
		return result, err
	}
	if allocation.UID == agent.UID || allocation.GID == agent.GID || allocation.ContainmentID == agent.ContainmentID {
		return result, fault(api.CodeForbidden, "materialization worker shares the agent allocation")
	}
	meta, raw, err := objectRow(ctx, s.db, stage.Inputs.Sources.Project.Object.ID)
	if err != nil {
		return result, err
	}
	if meta.Ref != stage.Inputs.Sources.Project.Object {
		return result, fault(api.CodeIntegrity, "materialization source bytes changed")
	}
	var manifest api.ObjectManifest
	if err := api.DecodeObject(raw, &manifest); err != nil {
		return result, err
	}
	if manifest.Schema != "laneboss.objects.v2" {
		return result, fault(api.CodeInvalid, "materialization source is not an object tree")
	}
	copies, err := api.ValidateDataCopyProjections(stage.Inputs, projection)
	if err != nil {
		return result, err
	}
	for _, copy := range copies {
		metadata, raw, err := objectRow(ctx, s.db, copy.Source.ID)
		if err != nil {
			return result, err
		}
		var source api.ObjectManifest
		if metadata.Ref != copy.Source || api.DecodeObject(raw, &source) != nil {
			return result, fault(api.CodeIntegrity, "copy projection lost its pinned source bytes")
		}
		selected, file, err := grantmanifest.CopySelection(source, copy.Grant.RelativePath)
		if err != nil {
			return result, err
		}
		if file != copy.File || !sameValue(selected, copy.Manifest) {
			return result, fault(api.CodeForbidden, "copy projection changed its granted relative selection")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	stage.Storage, saved.Allocation = projection, allocation
	saved.Output, err = s.retainDataBytes(ctx, tx, *stage, "manifest", "service", raw)
	if err != nil {
		return result, err
	}
	body, err := canonicalValue(dataJobInput{Schema: "laneboss.materialize-input.v2", StageID: id, Reservation: stage.Reservation, Source: stage.Inputs.Sources.Project, Storage: projection, Grants: stage.Grants, Output: saved.Output, Budget: stage.Plan.Budget})
	if err != nil {
		return result, err
	}
	if len(body) > api.MaxFrameBytes {
		return result, wire.Invalid("materialization input exceeds the worker frame bound")
	}
	stage.Worker.Input, err = s.retainDataBytes(ctx, tx, *stage, "materialize_input", "service", body)
	if err != nil {
		return result, err
	}
	stage.Plan.Input = stage.Worker.Input
	cause := *saved.Parent.Record.Effect.Context
	cause.ID, err = wire.NewID()
	if err != nil {
		return result, err
	}
	cause.Kind, cause.EffectID = api.InternalLifecycleEffect, stage.Worker.EffectID
	effect := api.Effect{ID: stage.Worker.EffectID, OperationID: stage.Reservation.OperationID, Context: &cause, Worker: &stage.Plan}
	if err := insertLaunchEffect(ctx, tx, effect); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "worker_lease", stage.Worker.ID, stage.Worker.Generation, stage.Worker); err != nil {
		return result, err
	}
	saved.Phase = "sealed"
	if err := s.saveDataStage(ctx, tx, saved); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return *stage, nil
}

type dataObjectKey struct{}

func (s *Service) retainDataBytes(ctx context.Context, tx *sql.Tx, stage api.LaunchDataStage, class, audience string, data []byte) (api.BlobRef, error) {
	id, err := wire.NewID()
	if err != nil {
		return api.BlobRef{}, err
	}
	actor := api.Actor{Kind: "service", ID: s.storeID}
	return s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, api.Scope{Config: s.deps.Config, Actor: actor}, api.ObjectWrite{ObjectKey: id, Class: class, Bytes: data, SHA256: api.Digest(hash(data)), Origin: "service", ACL: api.ObjectACL{Config: s.deps.Config, Owner: actor, LifeID: stage.Reservation.Target.LifeID, Audience: audience, Generation: 1}}, stage.Reservation.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
}

func (s *Service) RecordDataClaim(ctx context.Context, scope api.Scope, id api.ID, lease api.EffectLease) (result api.LaunchDataStage, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, true)
	if err != nil {
		return result, err
	}
	if saved.Phase != "sealed" {
		if !sameValue(saved.Stage.Claim, lease) {
			return result, fault(api.CodeConflict, "materialization child claim cannot be replaced")
		}
		return saved.Stage, nil
	}
	actual, err := effectRow(ctx, s.db, saved.Stage.Worker.EffectID)
	if err != nil {
		return result, err
	}
	if !sameValue(actual, lease.Record) || actual.ClaimID != lease.ClaimID || actual.ClaimExpiresAt != lease.ExpiresAt || actual.ClaimantID != scope.Actor.ID || actual.Outcome != nil || actual.State != "claimed" || !future(lease.ExpiresAt, s.deps.Clock.Now()) || actual.Effect.Worker == nil || !sameValue(*actual.Effect.Worker, saved.Stage.Plan) {
		return result, fault(api.CodeConflict, "materialization child claim differs from its current outbox record")
	}
	saved.Stage.Claim, saved.Phase = lease, "claimed"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	if err := s.saveDataStage(ctx, tx, saved); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return saved.Stage, nil
}

func (s *Service) DataHandoff(ctx context.Context, scope api.Scope, id api.ID, endpoint api.InstalledBinding) (result api.PreparedSpecHandoff, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, true)
	if err != nil {
		return result, err
	}
	if saved.Handoff != nil {
		if saved.Endpoint == nil || !sameValue(*saved.Endpoint, endpoint) {
			return result, fault(api.CodeConflict, "materialization endpoint changed")
		}
		return *saved.Handoff, nil
	}
	stage, allocation := saved.Stage, saved.Allocation
	if saved.Phase != "claimed" {
		return result, fault(api.CodeConflict, "materialization handoff requires its child claim")
	}
	if err := api.ValidateBinding(endpoint, scope.Config, stage.Plan.Executable.Version); err != nil {
		return result, err
	}
	if endpoint.Class != api.EndpointWorker || endpoint.WorkerLeaseID != stage.Worker.ID || endpoint.LaunchID != stage.WorkerLaunchID || endpoint.Target == nil || *endpoint.Target != stage.Reservation.Target || endpoint.Socket != "/runtime/laneboss-worker.sock" || endpoint.ArtifactSHA256 != stage.Plan.Executable.SHA256 || endpoint.EndpointGeneration != allocation.EndpointGeneration || endpoint.InstallationGeneration != stage.Storage.Generation {
		return result, fault(api.CodeConflict, "materialization endpoint differs from its installed worker")
	}
	specID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	spec := api.LaunchSpec{Kind: "worker", PlanID: stage.Reservation.ID, ID: specID, Target: stage.Reservation.Target, LaunchID: stage.WorkerLaunchID, Backend: stage.Inputs.Sources.Runtime.Backend, UIDLeaseID: allocation.ID, Worker: &stage.Plan, Grants: stage.Grants, Budget: stage.Plan.Budget, EndpointGeneration: allocation.EndpointGeneration, RuntimeManifest: stage.Worker.RuntimeManifest, PolicyGeneration: stage.Reservation.PolicyGeneration,
		Materialization: api.Materialization{GrantSetID: stage.Grants.ID, Manifest: stage.Storage.Evidence, Objects: []api.MaterializedObject{}}, Injection: api.Injection{Target: stage.Reservation.Target, SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}}
	raw, err := canonicalValue(spec)
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	ref, err := s.retainDataBytes(ctx, tx, stage, "launch_spec", "service", raw)
	if err != nil {
		return result, err
	}
	cause := *stage.Claim.Record.Effect.Context
	cause.Kind = api.InternalHelperRegister
	result = api.PreparedSpecHandoff{Cause: cause, Config: scope.Config, Spec: spec, Original: ref, SpecSHA256: ref.SHA256, OperationID: stage.Reservation.OperationID, RequestID: stage.Reservation.RequestID}
	saved.Handoff, saved.Endpoint = &result, &endpoint
	if err := s.saveDataStage(ctx, tx, saved); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Service) BindDataWorker(ctx context.Context, scope api.Scope, id api.ID, prepared api.PreparedLaunch) (api.LaunchBindingRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, true)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	stage, allocation := saved.Stage, saved.Allocation
	if saved.Handoff == nil || saved.Endpoint == nil || prepared.Target != stage.Reservation.Target || prepared.SpecSHA256 != saved.Handoff.SpecSHA256 || prepared.ContainmentID != allocation.ContainmentID || prepared.EndpointGeneration != allocation.EndpointGeneration || prepared.ProcessGeneration == "" || prepared.ID == "" || prepared.GateID == "" {
		return api.LaunchBindingRequest{}, fault(api.CodeIntegrity, "materialization prepared gate changed its sealed worker")
	}
	prior, err := s.launchBinding(ctx, s.db, stage.WorkerLaunchID)
	if err == nil {
		if prior.Prepared != prepared || prior.Record.Actor != saved.Actor {
			return api.LaunchBindingRequest{}, fault(api.CodeConflict, "materialization prepared binding changed")
		}
		return prior, nil
	}
	if !absent(err) {
		return api.LaunchBindingRequest{}, err
	}
	r := stage.Reservation
	record := api.LaunchRecord{Kind: "worker", ID: stage.WorkerLaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID, ParentLifeID: r.ParentLifeID, StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq, Actor: saved.Actor, UIDLeaseID: allocation.ID, HostUID: allocation.UID, ProcessGeneration: prepared.ProcessGeneration, ContainmentID: allocation.ContainmentID, GrantSetID: stage.Grants.ID, GrantsSHA256: stage.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: allocation.EndpointGeneration}
	binding := api.LaunchBindingRequest{Record: record, Prepared: prepared}
	cause := *stage.Claim.Record.Effect.Context
	cause.ID, cause.Kind, cause.Actor = saved.BindIntent, api.InternalLifecycleEffect, scope.Actor
	event := api.Event{Schema: api.SchemaVersion, ID: saved.BindEvent, Config: r.Config, Kind: "identity.bound", Actor: scope.Actor, RequestedBy: r.RequestedBy, LifeID: r.Target.LifeID, Run: r.Target.Run, Origin: "service", StarterChain: append([]api.ID{}, r.StarterChain...),
		RootLifeID: r.RootLifeID, ParentLifeID: r.ParentLifeID, StarterEventSeq: r.StarterEventSeq}
	event.Payload, err = json.Marshal(record)
	if err != nil {
		return binding, err
	}
	if _, err := s.transactInternal(ctx, api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{IdentityBindings: []api.LaunchBindingRequest{binding}, Endpoints: []api.EndpointProjection{{Binding: *saved.Endpoint, Generation: 1}}}, Events: []api.Event{event}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}); err != nil {
		return binding, err
	}
	return s.launchBinding(ctx, s.db, stage.WorkerLaunchID)
}

func (s *Service) RecordDataProcess(ctx context.Context, scope api.Scope, id api.ID, process api.ProcessHandle) (result api.LaunchDataStage, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, true)
	if err != nil {
		return result, err
	}
	binding, err := s.launchBinding(ctx, s.db, saved.Stage.WorkerLaunchID)
	if err != nil {
		return result, err
	}
	if process.ID != binding.Record.ID || process.Target != binding.Record.Target || process.ContainmentID != binding.Record.ContainmentID || process.Generation != binding.Record.ProcessGeneration {
		return result, fault(api.CodeIntegrity, "materialization process differs from its committed prepared identity")
	}
	if saved.Stage.Process.ID != "" && saved.Stage.Process != process {
		return result, fault(api.CodeConflict, "materialization process cannot be replaced")
	}
	saved.Stage.Process, saved.Phase = process, "opened"
	if err := api.ValidateLaunchDataStage(saved.Stage, api.LaunchDataRequest{ReservationID: saved.Stage.Reservation.ID, GrantSetID: saved.Stage.Reservation.GrantSetID, LeaseID: saved.Stage.AgentLeaseID}); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	if err := s.saveDataStage(ctx, tx, saved); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return saved.Stage, nil
}

func sameDataBytes(raw []byte, value any) bool {
	canonical, err := canonicalValue(value)
	return err == nil && bytes.Equal(raw, canonical)
}
