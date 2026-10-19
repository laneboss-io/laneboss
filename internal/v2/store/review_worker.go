package store

import (
	"context"
	"database/sql"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/testjob"
)

type reviewRecord struct {
	Preparation    *reviewjob.CheckInput `json:",omitempty"`
	Job            archivejob.Job
	Scope          api.Scope
	Request        api.Request
	Lane           api.Lane
	Input          reviewjob.Input
	Test           *testjob.Input `json:",omitempty"`
	Grants         api.GrantSet
	Claim          api.EffectLease
	WorkerLaunchID api.ID
	WorkerActor    api.Actor
	Allocation     api.HelperLease
	Handoff        *api.PreparedSpecHandoff
	Endpoint       *api.InstalledBinding
	Process        api.ProcessHandle
	Ack            *dataAcknowledgement
	Allocating     bool
	Retirement     *archivejob.Retirement
}

func (s *Service) ReserveReviewWorker(ctx context.Context, scope api.Scope, request api.ReviewRequest, subject api.ReviewSubject, required []string) (result api.WorkerLease, resultErr error) {
	s.mu.RLock()
	native := s.reviewNative
	s.mu.RUnlock()
	if native == nil {
		return result, fault(api.CodePrerequisite, "review native runtime is not bound")
	}
	currentRequired, err := native.RequiredReviewChecks(ctx, s.reviewScope(), request.Target)
	if err != nil {
		return result, err
	}
	if !slices.Equal(currentRequired, required) || len(required) == 0 {
		return result, fault(api.CodeConflict, "review requirements changed before reservation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	pending, err := s.reviewPending(ctx, scope, request.Target)
	if err != nil {
		return result, err
	}
	var original api.ReviewRequest
	if api.DecodeObject(scope.Request.Params, &original) != nil || !reflect.DeepEqual(original, request) {
		return result, fault(api.CodeIdempotencyConflict, "review changed its original request")
	}
	var frozen reviewFrozen
	if err := storedProjection(ctx, s.db, "review_snapshot", reviewSnapshotID(request.Target), &frozen); err != nil {
		return result, err
	}
	if frozen.Phase != "sealed" || !sameValue(frozen.Subject, subject) {
		return result, fault(api.CodeConflict, "review selected another frozen subject")
	}
	if err := s.reviewFreezeFence(ctx, s.db, frozen); err != nil {
		return result, err
	}
	var r reviewRecord
	err = storedProjection(ctx, s.db, "review_job", pending.Operation.ID, &r)
	if err == nil {
		if requestKey(r.Request) != requestKey(scope.Request) || r.Request.Config != scope.Request.Config || !sameValue(r.Input.Request, request) || r.Scope.Actor != scope.Actor || !sameValue(r.Input.Subject, subject) || !slices.Equal(r.Input.Required, required) {
			return result, fault(api.CodeIdempotencyConflict, "review retry changed its retained native job")
		}
		return s.retainedReviewLease(ctx, s.db, r)
	}
	if !absent(err) {
		return result, err
	}
	binding, err := s.launchBinding(ctx, s.db, frozen.Lane.LaunchID)
	if err != nil {
		return result, err
	}
	if binding.Recovery == nil {
		return result, fault(api.CodeIntegrity, "review lacks the actual enrolled runtime")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", binding.Recovery.PlanID, &plan); err != nil {
		return result, err
	}
	if plan.Inputs == nil {
		return result, fault(api.CodeIntegrity, "review base has no retained project source")
	}
	meta, raw, err := objectRow(ctx, s.db, binding.Recovery.Handoff.Spec.RuntimeManifest.ID)
	if err != nil {
		return result, err
	}
	var runtime api.RuntimeManifest
	budget := binding.Recovery.Handoff.Spec.Budget
	if meta.Ref != binding.Recovery.Handoff.Spec.RuntimeManifest || meta.Origin != "service" || api.DecodeObject(raw, &runtime) != nil || runtime.Schema != "laneboss.runtime.v2" || runtime.Generation == 0 || !positiveBudget(budget) {
		return result, fault(api.CodeIntegrity, "review runtime or worker budget is not enrolled")
	}
	r = reviewRecord{Lane: frozen.Lane, Request: scope.Request, Scope: api.Scope{Config: scope.Config, Actor: scope.Actor, PolicyGeneration: scope.PolicyGeneration}}
	r.Job.Intent = archivejob.Intent{Request: api.ArchiveRequest{Target: request.Target, ExpectedGeneration: subject.Generation}, OperationID: pending.Operation.ID, EndEventID: subject.EndEventID, EndSeq: subject.EndSeq, CancellationEpoch: frozen.Intent.CancellationEpoch}
	for _, id := range []*api.ID{&r.Job.ID, &r.Job.Lease.ID, &r.Job.Lease.EffectID, &r.Grants.ID, &r.WorkerLaunchID, &r.WorkerActor.ID} {
		*id, err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	r.WorkerActor.Kind = "worker"
	var source api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", r.Lane.GrantSetID, &source); err != nil {
		return result, err
	}
	if source.Revoked || !future(source.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeForbidden, "review source grants are revoked or expired")
	}
	budget.WallMS = min(budget.WallMS, int64((15*time.Minute)/time.Millisecond))
	expires := s.deps.Clock.Now().Add(time.Duration(budget.WallMS) * time.Millisecond)
	grantExpiry, err := time.Parse(time.RFC3339Nano, string(source.ExpiresAt))
	if err != nil {
		return result, err
	}
	if grantExpiry.Before(expires) {
		expires = grantExpiry
	}
	r.Grants = api.GrantSet{ID: r.Grants.ID, LifeID: r.Lane.LifeID, ParentLifeID: r.Lane.LifeID, Generation: 1, PolicyGeneration: scope.PolicyGeneration,
		ExpiresAt: api.Timestamp(expires.UTC().Format(timeFormat)), Data: []api.DataGrant{}, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	grantBytes, err := canonicalValue(r.Grants)
	if err != nil {
		return result, err
	}
	r.Grants.SHA256 = api.Digest(hash(grantBytes))
	r.Job.Lease = api.WorkerLease{ID: r.Job.Lease.ID, Kind: "export", Target: request.Target, OperationID: pending.Operation.ID, EffectID: r.Job.Lease.EffectID,
		RuntimeManifest: binding.Recovery.Handoff.Spec.RuntimeManifest, GrantSetID: r.Grants.ID, Generation: 1, ExpiresAt: r.Grants.ExpiresAt}
	r.Input = reviewjob.Input{Schema: "laneboss.review-input.v2", Subject: subject, Request: request, Required: slices.Clone(required), Base: plan.Inputs.Sources.Project.Object, Checks: []api.ReviewCheckFact{}, Resolutions: []api.ReviewResolution{}}
	if err := s.reviewCandidates(ctx, s.db, &r, frozen); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	raw, err = canonicalValue(frozen.Freeze)
	if err != nil {
		return result, err
	}
	r.Job.Freeze, err = s.reviewBytes(ctx, tx, r, "manifest", raw)
	if err != nil {
		return result, err
	}
	raw, err = canonicalValue(r.Input)
	if err != nil {
		return result, err
	}
	r.Job.Lease.Input, err = s.reviewBytes(ctx, tx, r, "manifest", raw)
	if err != nil {
		return result, err
	}
	r.Job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "export", Executable: runtime.Bootstrap, GrantSetID: r.Grants.ID, Input: r.Job.Lease.Input, Budget: budget,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(r.Job.Lease.ID)}}
	causeID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	cause := api.InternalIntent{ID: causeID, Kind: api.InternalLifecycleEffect, Config: scope.Config, Actor: s.reviewScope().Actor, RequestedBy: scope.Actor, CauseOperationID: pending.Operation.ID, CauseRequestID: scope.Request.RequestID, EffectID: r.Job.Lease.EffectID, Target: request.Target, CancellationEpoch: r.Job.Intent.CancellationEpoch}
	if err := insertLaunchEffect(ctx, tx, api.Effect{ID: cause.EffectID, OperationID: pending.Operation.ID, Context: &cause, Worker: &r.Job.Plan}); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "grants", r.Grants.ID, 1, r.Grants); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "worker_lease", r.Job.Lease.ID, 1, r.Job.Lease); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "review_job", pending.Operation.ID, 1, r); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return r.Job.Lease, nil
}

func (s *Service) retainedReviewLease(ctx context.Context, db queryer, r reviewRecord) (api.WorkerLease, error) {
	var actual api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", r.Job.Lease.ID, &actual); err != nil {
		return actual, err
	}
	want := r.Job.Lease
	want.ConsumedBy, want.Generation = actual.ConsumedBy, actual.Generation
	if actual != want || actual.Generation < r.Job.Lease.Generation || actual.Generation > r.Job.Lease.Generation+2 {
		return api.WorkerLease{}, fault(api.CodeIntegrity, "retained review lease changed its immutable job")
	}
	// Preparation always returns the original generation; its later +1 consume
	// and +1 result advances are verified against the measured effect reader.
	return r.Job.Lease, nil
}

func (s *Service) reviewBytes(ctx context.Context, tx *sql.Tx, r reviewRecord, class string, raw []byte) (api.BlobRef, error) {
	id, err := wire.NewID()
	if err != nil {
		return api.BlobRef{}, err
	}
	acl := s.reviewACL(r.Lane.LifeID)
	acl.Audience = "private"
	if r.Test != nil && (class == "worker_result" || class == "check" || class == "capture") {
		acl.Audience = "owner"
	}
	if r.Test != nil && class == "capture" {
		acl.Owner = r.WorkerActor
	}
	return s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, s.reviewScope(), api.ObjectWrite{ObjectKey: id, Class: class, Bytes: raw, SHA256: api.Digest(hash(raw)), Origin: "service", ACL: acl}, r.Job.Intent.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
}

func (s *Service) reviewCandidates(ctx context.Context, db queryer, r *reviewRecord, frozen reviewFrozen) error {
	request, subject := r.Input.Request, r.Input.Subject
	if request.Diff.Class != "diff" || len(request.Checks) == 0 || len(request.Checks) > 200 || request.RefusalResolution == nil || len(request.RefusalResolution) > 200 {
		return fault(api.CodeInvalid, "review candidate set is missing or exceeds its bound")
	}
	for _, ref := range append([]api.BlobRef{request.Diff, request.RecordInventory, r.Input.Base}, request.Checks...) {
		meta, _, err := objectRow(ctx, db, ref.ID)
		if err != nil {
			return err
		}
		if meta.Ref != ref || meta.ACL.Config != s.deps.Config {
			return fault(api.CodeIntegrity, "review candidate differs from its retained exact bytes")
		}
	}
	names := map[string]bool{}
	for _, ref := range request.Checks {
		meta, raw, err := objectRow(ctx, db, ref.ID)
		if err != nil {
			return err
		}
		var check reviewjob.CheckRecord
		if ref.Class != "check" || api.DecodeObject(raw, &check) != nil || check.Schema != "laneboss.check.v2" || names[check.Name] || check.Target != subject.Target || check.EndSeq != subject.EndSeq || check.SnapshotSHA256 != subject.Snapshot.SHA256 || meta.SourceOperationID != check.OperationID || meta.Origin != "service" && meta.Origin != "worker" || meta.ACL.LifeID != subject.Target.LifeID {
			return fault(api.CodeIntegrity, "check receipt has no authenticated frozen test provenance")
		}
		var lease api.WorkerLease
		if err := storedProjection(ctx, db, "worker_lease", check.WorkerLeaseID, &lease); err != nil {
			return err
		}
		effect, err := effectRow(ctx, db, lease.EffectID)
		if err != nil {
			return err
		}
		if lease.Kind != "test" || lease.Target != subject.Target || lease.OperationID != check.OperationID || lease.ConsumedBy == "" || effect.Effect.Worker == nil || effect.Effect.Worker.Kind != "test" || effect.State != api.EffectCompleted || effect.Outcome == nil || effect.Outcome.Observation == nil || effect.Outcome.Status != "succeeded" || effect.Outcome.Error != nil {
			return fault(api.CodePrerequisite, "check receipt has no real completed test worker")
		}
		observation := effect.Outcome.Observation
		var record api.LaunchRecord
		if err := storedProjection(ctx, db, "launch", lease.ConsumedBy, &record); err != nil {
			return err
		}
		if observation.Handle.ID != record.ID || observation.Handle.ContainmentID != record.ContainmentID || observation.Handle.Generation != record.ProcessGeneration || observation.Handle.Target != lease.Target || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != check.ExitCode || observation.Signal != nil || observation.Survivors == nil || *observation.Survivors != 0 {
			return fault(api.CodeContainmentUnknown, "check receipt differs from its measured native test exit")
		}
		names[check.Name] = true
		r.Input.Checks = append(r.Input.Checks, api.ReviewCheckFact{Name: check.Name, Receipt: ref, Target: check.Target, EndSeq: check.EndSeq, SnapshotSHA256: check.SnapshotSHA256, ExitCode: check.ExitCode, WorkerLeaseID: check.WorkerLeaseID, OperationID: check.OperationID})
	}
	meta, raw, err := objectRow(ctx, db, request.RecordInventory.ID)
	if err != nil {
		return err
	}
	var inventory reviewjob.InventoryRecord
	if request.RecordInventory.Class != "manifest" || api.DecodeObject(raw, &inventory) != nil || inventory.Schema != "laneboss.review-inventory.v2" || inventory.ThroughSeq != subject.InventorySeq || meta.ACL.LifeID != subject.Target.LifeID || meta.Origin != "service" && meta.Origin != "worker" {
		return fault(api.CodeIntegrity, "review inventory has no authenticated drained source")
	}
	if len(inventory.Streams) != len(frozen.Capture.Positions) {
		return fault(api.CodeIntegrity, "review inventory omitted a primary stream")
	}
	seen := map[api.ID]bool{}
	for _, stream := range inventory.Streams {
		if seen[stream.StreamID] || stream.BindingID != frozen.Capture.Binding.ID || stream.StartOffset != 0 || !stream.EOF {
			return fault(api.CodeIntegrity, "review inventory changed its primary stream binding or EOF")
		}
		seen[stream.StreamID] = true
		found := false
		for _, position := range frozen.Capture.Positions {
			found = found || position.StreamID == stream.StreamID && position.NextOffset == stream.EndOffset && position.EOF == stream.EOF
		}
		if !found {
			return fault(api.CodeIntegrity, "review inventory differs from its measured captured ranges")
		}
		name := ""
		for _, binding := range subject.Streams {
			if binding.ID == stream.StreamID {
				name = binding.Stream
			}
		}
		if name == "vendor" {
			name = "structured"
		}
		reader, ok := db.(readDatabase)
		if !ok {
			return fault(api.CodeIntegrity, "review gaps have no complete reader")
		}
		rows, err := reader.QueryContext(ctx, "SELECT id FROM events WHERE seq<=? AND json_extract(data,'$.kind')='capture.gap' AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND (json_extract(data,'$.payload.binding_id')=? OR json_extract(data,'$.payload.binding_id') IS NULL) AND (json_extract(data,'$.payload.stream')=? OR json_extract(data,'$.payload.stream')='combined') ORDER BY id", uint64(subject.InventorySeq), string(subject.Target.LifeID), uint64(subject.Target.Run), string(stream.BindingID), name)
		if err != nil {
			return err
		}
		gaps := []api.ID{}
		for rows.Next() {
			var id api.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			gaps = append(gaps, id)
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		candidate := slices.Clone(stream.GapIDs)
		slices.Sort(candidate)
		if !slices.Equal(gaps, candidate) {
			return fault(api.CodeIntegrity, "review inventory changed its retained gap set")
		}
	}
	if inventory.ToolCoverage == api.CoverageComplete {
		if err := s.reviewCompleteTools(ctx, db, frozen, inventory.ToolRecords); err != nil {
			return err
		}
	}
	r.Input.Inventory = api.ReviewInventory{Manifest: request.RecordInventory, ThroughSeq: inventory.ThroughSeq, Streams: inventory.Streams, ToolRecords: inventory.ToolRecords, ToolCoverage: inventory.ToolCoverage}
	for _, id := range request.RefusalResolution {
		var raw []byte
		if err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='record' AND json_extract(data,'$.origin')='service' AND json_extract(data,'$.collection')='decisions' AND EXISTS(SELECT 1 FROM json_each(data,'$.related_ids') WHERE value=?) ORDER BY generation DESC LIMIT 1", string(id)).Scan(&raw); err != nil {
			return err
		}
		var record api.Record
		if err := decodeStored(raw, &record); err != nil {
			return err
		}
		meta, _, err := objectRow(ctx, db, record.Content.ID)
		if err != nil {
			return err
		}
		var seq api.Sequence
		if err := db.QueryRowContext(ctx, "SELECT seq FROM events WHERE json_extract(data,'$.payload.id')=? AND seq<=? ORDER BY seq DESC LIMIT 1", string(record.ID), uint64(subject.InventorySeq)).Scan(&seq); err != nil {
			return err
		}
		if meta.Ref != record.Content || record.Content.Class != "manifest" {
			return fault(api.CodeIntegrity, "refusal resolution lost its retained evidence")
		}
		r.Input.Resolutions = append(r.Input.Resolutions, api.ReviewResolution{RefusalID: id, EventSeq: seq, Evidence: record.Content})
	}
	return nil
}

func (s *Service) reviewClaim(ctx context.Context, db queryer, scope api.Scope, lease api.EffectLease) (r reviewRecord, err error) {
	if err := s.dataScope(ctx, db, scope); err != nil {
		return r, err
	}
	current, err := effectRow(ctx, db, lease.Record.Effect.ID)
	if err != nil {
		return r, err
	}
	if !api.EffectLeaseClaimed(lease) || !sameValue(current, lease.Record) || current.Outcome != nil || current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return r, fault(api.CodeConflict, "review worker lost its original current effect claim")
	}
	if err := storedProjection(ctx, db, "review_job", current.Effect.OperationID, &r); err != nil {
		return r, err
	}
	if current.Effect.Worker == nil || current.Effect.ID != r.Job.Lease.EffectID || !sameValue(*current.Effect.Worker, r.Job.Plan) {
		return r, fault(api.CodeForbidden, "review claim selected another fixed worker")
	}
	if err := s.currentLifecycleRequester(ctx, db, r.Scope.Actor); err != nil {
		return r, err
	}
	var frozen reviewFrozen
	if err := storedProjection(ctx, db, "review_snapshot", reviewSnapshotID(r.Job.Lease.Target), &frozen); err != nil {
		return r, err
	}
	if err := s.reviewFreezeFence(ctx, db, frozen); err != nil {
		return r, err
	}
	if r.Test != nil {
		var grants api.GrantSet
		if err := storedProjection(ctx, db, "grants", r.Test.Plan.GrantSetID, &grants); err != nil {
			return r, err
		}
		if grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) || grants.ID != r.Lane.GrantSetID || grants.PolicyGeneration != r.Scope.PolicyGeneration {
			return r, fault(api.CodeForbidden, "TestChild source grants were revoked, replaced or expired")
		}
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return r, err
	}
	if policy.Generation != r.Scope.PolicyGeneration || !future(r.Job.Lease.ExpiresAt, s.deps.Clock.Now()) {
		return r, fault(api.CodeConflict, "review worker policy changed or its fixed lease expired")
	}
	return r, nil
}

func (s *Service) ReviewJob(ctx context.Context, scope api.Scope, operation api.ID) (archivejob.Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return archivejob.Job{}, err
	}
	var r reviewRecord
	if err := storedProjection(ctx, s.db, "review_job", operation, &r); err != nil {
		return archivejob.Job{}, err
	}
	return r.Job, nil
}

func (s *Service) AwaitReviewResult(ctx context.Context, caller api.Scope, original api.WorkerLease) (api.BlobRef, error) {
	s.mu.RLock()
	pending, err := s.reviewPending(ctx, caller, original.Target)
	var r reviewRecord
	if err == nil {
		err = storedProjection(ctx, s.db, "review_job", pending.Operation.ID, &r)
	}
	executor := s.reviewExecutor
	s.mu.RUnlock()
	if err != nil {
		return api.BlobRef{}, err
	}
	if !sameValue(r.Job.Lease, original) {
		return api.BlobRef{}, fault(api.CodeConflict, "review wait changed its original worker")
	}
	if executor == nil {
		return api.BlobRef{}, fault(api.CodePrerequisite, "review native execution coordinator is not installed")
	}
	if ref, err := s.reviewResult(ctx, r); err == nil {
		return ref, nil
	} else if !reviewMissing(err) {
		return api.BlobRef{}, err
	}
	if err := executor.ExecuteReviewWorker(ctx, caller, r.Job); err != nil {
		return api.BlobRef{}, err
	}
	return s.reviewResult(ctx, r)
}

func (s *Service) reviewResult(ctx context.Context, original reviewRecord) (api.BlobRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var r reviewRecord
	if err := storedProjection(ctx, s.db, "review_job", original.Job.Intent.OperationID, &r); err != nil {
		return api.BlobRef{}, err
	}
	if !sameValue(r.Job, original.Job) {
		return api.BlobRef{}, fault(api.CodeIntegrity, "review result changed its original native job")
	}
	effect, err := effectRow(ctx, s.db, r.Job.Lease.EffectID)
	if err != nil {
		return api.BlobRef{}, err
	}
	if effect.Outcome == nil {
		return api.BlobRef{}, fault(api.CodeNotFound, "original review worker is not measured complete")
	}
	if err := s.validateReviewOutcome(ctx, s.db, effect, *effect.Outcome); err != nil {
		return api.BlobRef{}, err
	}
	return *effect.Outcome.Output, nil
}
