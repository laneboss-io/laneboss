package store

import (
	"context"
	"database/sql"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Immutable input and the gate commit with the original guarded request.
type orgApply struct {
	SimulatedPresence bool
	Change            api.ChangeRequest
	Approval          api.ChangeApproval
	Snapshot          api.OrgSnapshot
	Policy            *orgPolicy
	Deferred          api.DeferredReply
	Effect            api.Effect
	Completed         bool
}

func (s *Service) reserveOrgApply(ctx context.Context, tx *sql.Tx, input api.Transaction) error {
	if input.Deferred == nil || len(input.Effects) != 1 || len(input.Guards) != 1 || input.Guards[0].Approval == nil {
		return fault(api.CodeForbidden, "org publication lacks its exact guarded effect")
	}
	var change api.ChangeRequest
	var approved api.ChangeApproval
	effect := input.Effects[0]
	if effect.ApplyChange == nil || effect.Context == nil {
		return fault(api.CodeForbidden, "org publication has no retained change intent")
	}
	if err := storedProjection(ctx, tx, "change", effect.ApplyChange.ChangeID, &change); err != nil {
		return err
	}
	if err := storedProjection(ctx, tx, "approval", effect.ApplyChange.ApprovalID, &approved); err != nil {
		return err
	}
	if err := approval.ValidateApprovalBinding(s.deps.Clock.Now(), change, approved); err != nil {
		return err
	}
	if change.Requester != input.Scope.Actor || change.Requester.Kind != "lane" || change.Requester.Level != 6 ||
		change.Config != s.deps.Config || change.OrgID != api.ID(s.deps.Config) || change.BaseGeneration != effect.ApplyChange.ExpectedGeneration ||
		!hasCompare(input, api.CompareOrg, change.OrgID, change.BaseGeneration) || effect.Context.Target.LifeID != change.Requester.LifeID || effect.Context.RequestedBy != change.Requester ||
		change.Status != "proposed" && change.Status != "approved" {
		return fault(api.CodeForbidden, "org publication differs from its proposing L6 or exact approved base")
	}
	var launch api.LaunchRecord
	if err := storedProjection(ctx, tx, "launch", input.Scope.LaunchID, &launch); err != nil {
		return err
	}
	if launch.Config != s.deps.Config || launch.Revoked || launch.Actor != change.Requester || launch.Target != effect.Context.Target || launch.EndpointGeneration != input.Scope.EndpointGeneration {
		return fault(api.CodeForbidden, "org publication has no matching current L6 launch")
	}
	if epoch, err := s.cancellationEpoch(ctx, tx, change.Requester.LifeID); err == nil {
		if epoch != effect.Context.CancellationEpoch {
			return fault(api.CodeConflict, "org application requester life revision changed before authorization")
		}
	} else if !absent(err) {
		return err
	}
	var snapshot api.OrgSnapshot
	if err := storedProjection(ctx, tx, "org", change.OrgID, &snapshot); err != nil {
		return err
	}
	if snapshot.Ref != change.SourceSnapshot || snapshot.Config != change.Config || snapshot.Renderer != change.Renderer || snapshot.OwnershipManifest != change.OwnershipManifest {
		return fault(api.CodeConflict, "org publication base or renderer changed")
	}
	if err := changeDeltas(snapshot, change); err != nil {
		return err
	}
	if err := s.changeObjects(ctx, tx, change); err != nil {
		return err
	}
	compiled, err := s.publicationSemantics(ctx, tx, snapshot, change)
	if err != nil {
		return err
	}
	var active orgApply
	err = storedProjection(ctx, tx, "org_apply_gate", change.OrgID, &active)
	if err == nil && !active.Completed {
		return fault(api.CodeConflict, "another publication owns this org generation")
	}
	if err != nil && !absent(err) {
		return err
	}
	var original api.Operation
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(input.Deferred.OperationID)).Scan(&raw); err != nil {
		return err
	}
	if err := decodeStored(raw, &original); err != nil {
		return err
	}
	job := orgApply{SimulatedPresence: approved.SimulatedPresence || original.SimulatedPresence, Change: change, Approval: approved, Snapshot: snapshot, Policy: compiled, Deferred: *input.Deferred, Effect: effect}
	if err := s.checkOrgPolicyStamp(ctx, tx, job, api.CodeConflict); err != nil {
		return err
	}
	if err := put(ctx, tx, "org_apply", job.Deferred.OperationID, 1, job); err != nil {
		return err
	}
	return put(ctx, tx, "org_apply_gate", change.OrgID, change.BaseGeneration, job)
}

// Once D6 authorization commits, this org operation is independent of its
// caller's later process lifetime. The original consumed approval and immutable
// effect/gate fence publication; no new lane authority is minted by recovery.
func (s *Service) orgApplyFence(ctx context.Context, db queryer, effect api.Effect) error {
	var job orgApply
	if err := storedProjection(ctx, db, "org_apply", effect.OperationID, &job); err != nil {
		return err
	}
	if !sameValue(job.Effect, effect) || effect.ApplyChange == nil || effect.Context == nil || job.Change.ID != effect.ApplyChange.ChangeID || job.Approval.ID != effect.ApplyChange.ApprovalID || job.Deferred.EffectID != effect.ID {
		return fault(api.CodeForbidden, "org publication effect differs from its original authorized request")
	}
	if err := s.checkOrgPolicyStamp(ctx, db, job, api.CodeIntegrity); err != nil {
		return err
	}
	var used approvalConsumption
	if err := storedProjection(ctx, db, "approval_use", job.Approval.ID, &used); err != nil {
		return err
	}
	if used.OperationID != effect.OperationID || used.Approval != job.Approval {
		return fault(api.CodeForbidden, "org publication lost its original consumed exact-change approval")
	}
	return nil
}

func (s *Service) validateOrgReceipt(ctx context.Context, db queryer, receipt api.MutationReceipt) error {
	deferred := receipt.Deferred
	if deferred == nil || deferred.Key != receipt.Key || deferred.OperationID != receipt.Operation.ID || receipt.Key.Method != "org.change.apply" {
		return fault(api.CodeIntegrity, "deferred publication receipt changed its original request binding")
	}
	var job orgApply
	if err := storedProjection(ctx, db, "org_apply", deferred.OperationID, &job); err != nil {
		return err
	}
	if job.Deferred != *deferred || job.Change.Requester != receipt.Actor || job.Change.Config != s.deps.Config || job.Effect.ID != deferred.EffectID || job.Effect.OperationID != deferred.OperationID {
		return fault(api.CodeIntegrity, "deferred publication lost its immutable original staging")
	}
	if job.Policy != nil && job.Policy.Before.Generation != receipt.PolicyGeneration {
		return fault(api.CodeIntegrity, "publication policy differs from the original request receipt")
	}
	var request api.Request
	if err := wire.Decode(receipt.RawRequest, &request); err != nil {
		return err
	}
	if request.Config != s.deps.Config || requestKey(request) != receipt.Key || request.Method != "org.change.apply" || job.Effect.ApplyChange == nil {
		return fault(api.CodeIntegrity, "deferred publication changed its retained original frame")
	}
	var apply api.ChangeApplyRequest
	if err := wire.Decode(request.Params, &apply); err != nil {
		return err
	}
	if apply != *job.Effect.ApplyChange {
		return fault(api.CodeIntegrity, "deferred publication frame changed its approved intent")
	}
	record, err := effectRow(ctx, db, deferred.EffectID)
	if err != nil {
		return err
	}
	if !sameValue(record.Effect, job.Effect) || (receipt.Reply == nil) != (record.Outcome == nil) || job.Completed != (receipt.Reply != nil) {
		return fault(api.CodeIntegrity, "deferred reply and publication effect completion disagree")
	}
	if receipt.Reply == nil && (receipt.Operation.Status != "pending" && receipt.Operation.Status != "running") {
		return fault(api.CodeIntegrity, "unfinished publication lost its pending operation")
	}
	if receipt.Operation.SimulatedPresence != job.SimulatedPresence || receipt.SimulatedPresence != job.SimulatedPresence {
		return fault(api.CodeIntegrity, "publication lost its original simulated authority provenance")
	}
	var used approvalConsumption
	if err := storedProjection(ctx, db, "approval_use", job.Approval.ID, &used); err != nil {
		return err
	}
	if used.OperationID != deferred.OperationID || used.Approval != job.Approval {
		return fault(api.CodeIntegrity, "publication lost its original one-use approval")
	}
	return nil
}

func (s *Service) currentOrgApply(ctx context.Context, scope api.Scope, request api.PublishChangeRequest) (orgApply, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var zero orgApply
	if err := s.available(); err != nil {
		return zero, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return zero, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		return zero, fault(api.CodeForbidden, "publication requires the bound internal publisher")
	}
	lease := request.Lease
	record, err := effectRow(ctx, s.db, lease.Record.Effect.ID)
	if err != nil {
		return zero, err
	}
	if !api.EffectLeaseClaimed(lease) || record.Outcome != nil || !sameValue(record, lease.Record) || record.ClaimantID != scope.Actor.ID || record.ClaimID != lease.ClaimID || record.ClaimExpiresAt != lease.ExpiresAt || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return zero, fault(api.CodeConflict, "publication has a stale or foreign current effect claim")
	}
	var job orgApply
	if err := storedProjection(ctx, s.db, "org_apply", record.Effect.OperationID, &job); err != nil {
		return zero, err
	}
	if job.Completed || !sameValue(job.Effect, record.Effect) || request.ChangeID != job.Change.ID || request.ApprovalID != job.Approval.ID || request.BaseGeneration != job.Change.BaseGeneration || request.ManifestSHA256 != job.Change.ManifestSHA256 || request.Renderer != job.Change.Renderer {
		return zero, fault(api.CodeConflict, "publication request differs from its exact retained approval and renderer")
	}
	var gate orgApply
	if err := storedProjection(ctx, s.db, "org_apply_gate", job.Change.OrgID, &gate); err != nil {
		return zero, err
	}
	if !sameValue(gate, job) {
		return zero, fault(api.CodeConflict, "publication lost its exclusive org gate")
	}
	var base api.OrgSnapshot
	if err := storedProjection(ctx, s.db, "org", job.Change.OrgID, &base); err != nil {
		return zero, err
	}
	if !sameValue(base, job.Snapshot) {
		return zero, fault(api.CodeConflict, "publication's approved source base changed")
	}
	if err := s.checkOrgPolicyStamp(ctx, s.db, job, api.CodeIntegrity); err != nil {
		return zero, err
	}
	compiled, err := s.publicationSemantics(ctx, s.db, job.Snapshot, job.Change)
	if err != nil {
		return zero, err
	}
	if !sameValue(compiled, job.Policy) {
		return zero, fault(api.CodeConflict, "publication policy differs from its original compiled inputs")
	}
	return job, nil
}

func (s *Service) checkOrgPolicyStamp(ctx context.Context, db queryer, job orgApply, code api.ErrorCode) error {
	if job.Policy == nil {
		return nil
	}
	var generation api.Generation
	if err := storedProjection(ctx, db, "reservation_policy", job.Deferred.OperationID, &generation); err != nil {
		return err
	}
	if generation != job.Policy.Before.Generation {
		return fault(code, "publication policy differs from its original request stamp")
	}
	return nil
}

func orgPublishRequest(lease api.EffectLease, change api.ChangeRequest, approvalID api.ID) api.PublishChangeRequest {
	return api.PublishChangeRequest{Lease: lease, ChangeID: change.ID, ApprovalID: approvalID, BaseGeneration: change.BaseGeneration, ManifestSHA256: change.ManifestSHA256, Renderer: change.Renderer}
}

// ChangePublication is a private service capability, never a public selector.
// The actual current claim selects the immutable original request and guards.
func (s *Service) ChangePublication(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.PublishChangeRequest, api.MutationReceipt, error) {
	s.mu.RLock()
	var job orgApply
	err := s.available()
	if err == nil {
		err = s.scope(ctx, s.db, scope)
	}
	if err == nil && (!internalScope(scope) || scope.Actor.Kind != "service") {
		err = fault(api.CodeForbidden, "publication preparation is internal")
	}
	if err == nil {
		err = storedProjection(ctx, s.db, "org_apply", lease.Record.Effect.OperationID, &job)
	}
	s.mu.RUnlock()
	if err != nil {
		return api.PublishChangeRequest{}, api.MutationReceipt{}, err
	}
	request := orgPublishRequest(lease, job.Change, job.Approval.ID)
	if _, err := s.currentOrgApply(ctx, scope, request); err != nil {
		return api.PublishChangeRequest{}, api.MutationReceipt{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	receipt, err := s.lookupReceipt(ctx, s.db, api.Scope{Config: s.deps.Config, Actor: job.Change.Requester}, job.Deferred.Key)
	return request, receipt, err
}
