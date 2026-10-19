package store

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type orgPublicationCommitKey struct{}
type orgPublicationCommit struct {
	Store  *Service
	Job    orgApply
	Marker orgPublicationMarker
	Claim  api.EffectLease
}

func (s *Service) completeChangeEffect(ctx context.Context, scope api.Scope, outcome api.EffectOutcome) (commit api.Commit, resultErr error) {
	s.orgMu.Lock()
	defer s.orgMu.Unlock()
	s.mu.RLock()
	if err := s.available(); err != nil {
		s.mu.RUnlock()
		return commit, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		s.mu.RUnlock()
		return commit, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		s.mu.RUnlock()
		return commit, fault(api.CodeForbidden, "publication completion requires the internal publisher")
	}
	record, err := effectRow(ctx, s.db, outcome.EffectID)
	var job orgApply
	if err == nil {
		err = storedProjection(ctx, s.db, "org_apply", record.Effect.OperationID, &job)
	}
	if err != nil {
		s.mu.RUnlock()
		return commit, err
	}
	if record.ClaimantID != scope.Actor.ID {
		s.mu.RUnlock()
		return commit, fault(api.CodeForbidden, "publication completion belongs to another claimant")
	}
	original := api.Scope{Config: scope.Config, Actor: job.Change.Requester}
	receipt, err := s.lookupReceipt(ctx, s.db, original, job.Deferred.Key)
	if err != nil {
		s.mu.RUnlock()
		return commit, err
	}
	if record.Outcome != nil {
		s.mu.RUnlock()
		if !sameValue(*record.Outcome, outcome) || receipt.Reply == nil {
			return commit, fault(api.CodeConflict, "publication already has a different completion")
		}
		return api.Commit{Operation: receipt.Operation, Reply: receipt.Reply, Deferred: receipt.Deferred, FirstSeq: receipt.FirstSeq, LastSeq: receipt.LastSeq, Replayed: true}, nil
	}
	lease := api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
	s.mu.RUnlock()
	if err := api.ValidateDeferredCompletion(receipt, lease, outcome); err != nil {
		return commit, err
	}
	if _, err := s.currentOrgApply(ctx, scope, orgPublishRequest(lease, job.Change, job.Approval.ID)); err != nil {
		return commit, err
	}
	var marker orgPublicationMarker
	if outcome.Status == "failed" {
		if err := s.publicationUnchanged(job); err != nil {
			return commit, err
		}
	} else {
		marker, err = s.publicationReadback(job)
		if err != nil {
			return commit, err
		}
		if outcome.Publication == nil || *outcome.Publication != marker.Receipt {
			return commit, fault(api.CodeIntegrity, "publication completion differs from its independently measured filesystem marker")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return commit, err
	}
	current, err := effectRow(ctx, s.db, outcome.EffectID)
	if err != nil {
		return commit, err
	}
	if !sameValue(current, record) || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return commit, fault(api.CodeConflict, "publication completion lost its current original effect claim")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return commit, err
	}
	defer finish(tx, &resultErr)
	var base api.OrgSnapshot
	if err := storedProjection(ctx, tx, "org", job.Change.OrgID, &base); err != nil {
		return commit, err
	}
	if !sameValue(base, job.Snapshot) {
		return commit, fault(api.CodeConflict, "publication base changed before completion")
	}
	if err := s.checkOrgPolicyStamp(ctx, tx, job, api.CodeIntegrity); err != nil {
		return commit, err
	}
	compiled, err := s.publicationSemantics(ctx, tx, job.Snapshot, job.Change)
	if err != nil {
		return commit, err
	}
	if !sameValue(compiled, job.Policy) {
		return commit, fault(api.CodeConflict, "publication policy changed before measured completion")
	}
	if outcome.Status == "failed" {
		job.Completed = true
		if err := put(ctx, tx, "org_apply", job.Deferred.OperationID, 2, job); err != nil {
			return commit, err
		}
		if err := put(ctx, tx, "org_apply_gate", job.Change.OrgID, job.Change.BaseGeneration, job); err != nil {
			return commit, err
		}
		commit, err = s.finishOwnedEffect(ctx, tx, scope, lease, outcome, 0, &outcome.Reply.Reply)
		if err != nil {
			return commit, err
		}
		commit.Deferred = &job.Deferred
		if err := tx.Commit(); err != nil {
			return commit, err
		}
		s.notifyChanged()
		return commit, nil
	}
	change := job.Change
	change.Status = "applied"
	intent := *record.Effect.Context
	intent.Actor = scope.Actor
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	payload, err := json.Marshal(api.ChangeEvent{Change: change, Approval: &job.Approval, Receipt: &marker.Receipt, Reason: "independent canonical generation readback"})
	if err != nil {
		return commit, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: api.ID("applied-" + hash([]byte(job.Deferred.OperationID))[:32]), Config: scope.Config, Kind: "org.change.applied", Actor: scope.Actor, RequestedBy: job.Change.Requester, OperationID: job.Deferred.OperationID, RequestID: record.Effect.Context.CauseRequestID, LifeID: record.Effect.Context.Target.LifeID, Run: record.Effect.Context.Target.Run, Origin: "service", StarterChain: []api.ID{}, Payload: payload}
	input := api.Transaction{Scope: scope, Internal: &intent, Writes: api.StateWrites{Changes: []api.ChangeRequest{change}, Applications: []api.ChangeReceipt{marker.Receipt}, OrgSnapshots: []api.OrgSnapshot{marker.Snapshot}}, Events: []api.Event{event}}
	if job.Policy != nil {
		input.Writes.Policy = &job.Policy.After
	}
	if err := api.ValidateTransactionShape(input); err != nil {
		return commit, err
	}
	if !allowedInternal(input) {
		return commit, fault(api.CodeForbidden, "publication completion exceeds the org publisher catalog")
	}
	ctx = context.WithValue(ctx, orgPublicationCommitKey{}, orgPublicationCommit{Store: s, Job: job, Marker: marker, Claim: lease})
	if err := s.writeState(ctx, tx, input, job.Deferred.OperationID, now); err != nil {
		return commit, err
	}
	seq, err := appendPrivateEvent(ctx, tx, event, now)
	if err != nil {
		return commit, err
	}
	if err := s.projectChange(ctx, tx, event); err != nil {
		return commit, err
	}
	job.Completed = true
	if err := put(ctx, tx, "org_apply", job.Deferred.OperationID, 2, job); err != nil {
		return commit, err
	}
	if err := put(ctx, tx, "org_apply_gate", job.Change.OrgID, marker.Snapshot.Ref.Generation, job); err != nil {
		return commit, err
	}
	commit, err = s.finishOwnedEffect(ctx, tx, scope, lease, outcome, seq, &outcome.Reply.Reply)
	if err != nil {
		return commit, err
	}
	commit.Deferred = &job.Deferred
	if err := tx.Commit(); err != nil {
		return commit, err
	}
	s.notifyChanged()
	return commit, nil
}

func (s *Service) validateOrgPublicationWrite(ctx context.Context, input api.Transaction) error {
	if input.Internal == nil || input.Internal.Kind != api.InternalOrgPublish || reflect.ValueOf(input.Writes).IsZero() && len(input.Events) == 0 {
		return nil
	}
	bound, ok := ctx.Value(orgPublicationCommitKey{}).(orgPublicationCommit)
	if !ok || bound.Store != s || bound.Job.Deferred.OperationID != input.Internal.CauseOperationID || bound.Job.Deferred.EffectID != input.Internal.EffectID || bound.Claim.Record.ClaimantID != input.Scope.Actor.ID {
		return fault(api.CodeForbidden, "org publication writes require independent canonical readback under the original claim")
	}
	return nil
}

func (s *Service) orgGenerationReady(ctx context.Context, db queryer) error {
	var gate orgApply
	err := storedProjection(ctx, db, "org_apply_gate", api.ID(s.deps.Config), &gate)
	if absent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if gate.Completed {
		return nil
	}
	return &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-service", Message: "org publication is awaiting canonical generation reconciliation", OperationID: gate.Deferred.OperationID, Instead: "Await or reconcile the original guarded publication before reading or dispatching against the org generation."}
}
