package migration

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// MigrationApply authorizes and queues a deployment. Historical import is an
// internal migration_apply completion, never a public event/projection write.
func (s *Service) MigrationApply(ctx context.Context, scope api.Scope, request api.MigrationApplyRequest) (api.Operation, error) {
	var zero api.Operation
	if err := validateScopeForApply(scope); err != nil {
		return zero, err
	}
	if !ValidID(request.PlanID) || scope.Request.Method != "migration.apply" || scope.Request.Config != scope.Config || scope.Request.IdempotencyKey == "" {
		return zero, invalidErr("migration.apply requires its exact request and a retained idempotency key")
	}
	digest, err := RequestDigest(scope.Config, "migration.apply", request)
	if err != nil {
		return zero, err
	}
	proof := scope.Request.Proof
	if proof == nil {
		return zero, &api.Error{Code: api.CodeUnauthenticated, Message: "migration.apply requires an operation-bound human proof", Instead: "Confirm this exact migration operation before applying it.", Owner: "lb-v2-migration"}
	}
	if scope.Request.RequestSHA256 != digest || !ValidID(proof.ID) || proof.RequestSHA256 != digest || !ValidTimestamp(proof.ExpiresAt) {
		return zero, invalidErr("migration.apply requires a valid operation proof for its exact intent")
	}
	key := api.RequestKey{Method: "migration.apply", IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: digest}
	if operation, found, err := s.replayApply(ctx, scope, key); found || err != nil {
		return operation, err
	}
	expiry, err := time.Parse(time.RFC3339Nano, string(proof.ExpiresAt))
	if err != nil || !expiry.After(time.Now()) {
		return zero, forbiddenErr("proof.expires_at has expired")
	}

	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	// Another caller can have committed while this caller waited for the lock.
	if operation, found, err := s.replayApply(ctx, scope, key); found || err != nil {
		return operation, err
	}
	state, exists := s.lookupPlan(request.PlanID)
	if !exists || state.config != scope.Config {
		return zero, &api.Error{Code: api.CodeNotFound, Message: "migration plan is not available in this configuration", Instead: "Read the same retained manifest with migration.plan before applying it.", Owner: "lb-v2-migration"}
	}
	if len(state.plan.Problems) != 0 {
		return zero, integrityErr("cannot apply a migration plan that has unresolved problems")
	}
	if scope.Connection == nil || scope.Connection.Binding().Class != api.EndpointHuman || scope.EndpointGeneration == 0 {
		return zero, forbiddenErr("migration.apply requires a live installed human connection")
	}
	binding := scope.Connection.Binding()
	if binding.Config != scope.Config || binding.EndpointGeneration != scope.EndpointGeneration || binding.InstallationGeneration == 0 {
		return zero, forbiddenErr("migration.apply connection binding is stale or mismatched")
	}
	target := api.HumanChallengeRequest{Method: "migration.apply", TargetID: request.PlanID, RequestSHA256: digest, BaseGeneration: 0}
	facts, err := s.deps.Human.CheckProof(ctx, scope, *proof, target)
	if err != nil {
		return zero, err
	}
	if facts.Config != scope.Config || facts.PrincipalID != scope.Actor.ID || facts.Ref != *proof || facts.Target != target ||
		facts.EndpointClass != api.EndpointHuman || facts.EndpointGeneration != scope.EndpointGeneration || !ValidID(facts.CredentialID) || !ValidID(facts.NonceID) || facts.ConsumedBy != "" {
		return zero, forbiddenErr("human confirmation proof is mismatched or already consumed")
	}
	if _, err := inspectAndVerifyBundle(ctx, s.deps.Store, scope, state.request); err != nil {
		return zero, err
	}
	opID := DeterministicID("op-mig-", scope.Config, scope.Actor.Kind, string(scope.Actor.ID), string(scope.Actor.LifeID), string(key.IdempotencyKey))
	effectID := DeterministicID("eff-mig-", scope.Config, string(request.PlanID))
	intent := api.InternalIntent{ID: DeterministicID("intent-mig-", string(effectID)), Kind: api.InternalMigrationApply,
		Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "migration-coordinator"}, RequestedBy: scope.Actor,
		CauseOperationID: opID, CauseRequestID: scope.Request.RequestID, EffectID: effectID}
	deployment := api.DeploymentPlan{ID: request.PlanID, Config: scope.Config, Actor: scope.Actor,
		InstallationGeneration: binding.InstallationGeneration, EndpointGeneration: binding.EndpointGeneration,
		Generation: 1, Phase: "planned", OperationID: opID, MigrationPlanID: request.PlanID}
	pending := api.Operation{ID: opID, Status: "pending"}
	reply, err := json.Marshal(pending)
	if err != nil {
		return zero, err
	}
	tx := api.Transaction{Scope: scope, Reply: &api.RPCReply{Result: reply},
		Compare: []api.Compare{{Kind: api.CompareUpgrade, ID: request.PlanID, Generation: 0}},
		Guards:  []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *proof, Target: target}}},
		Writes:  api.StateWrites{Deployments: []api.DeploymentPlan{deployment}},
		Effects: []api.Effect{{ID: effectID, OperationID: opID, Context: &intent, Migration: &request}}}
	if scope.Frame != nil {
		tx.RawRequest = append([]byte(nil), scope.Frame.Bytes()...)
	}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return zero, err
	}
	commit, err := s.deps.Store.Transact(ctx, tx)
	if err != nil {
		return zero, err
	}
	return applyReply(commit.Reply, opID)
}

func (s *Service) replayApply(ctx context.Context, scope api.Scope, key api.RequestKey) (api.Operation, bool, error) {
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return api.Operation{}, false, nil
		}
		return api.Operation{}, false, err
	}
	matches := func(receipt api.MutationReceipt) bool {
		return receipt.Config == scope.Config && receipt.Key == key && receipt.Actor.Kind == scope.Actor.Kind &&
			receipt.Actor.ID == scope.Actor.ID && receipt.Actor.LifeID == scope.Actor.LifeID
	}
	if !matches(receipt) {
		return api.Operation{}, true, integrityErr("migration receipt belongs to another configuration, request or principal")
	}
	if receipt.Reply == nil && (receipt.Operation.Status == "pending" || receipt.Operation.Status == "running") {
		receipt, err = s.deps.Store.AwaitReceipt(ctx, scope, key)
		if err != nil {
			return api.Operation{}, true, err
		}
		if !matches(receipt) {
			return api.Operation{}, true, integrityErr("awaited migration receipt belongs to another configuration, request or principal")
		}
	}
	operation, err := applyReply(receipt.Reply, receipt.Operation.ID)
	return operation, true, err
}

func applyReply(reply *api.RPCReply, operationID api.ID) (api.Operation, error) {
	if reply == nil || (reply.Error == nil) == (len(reply.Result) == 0) {
		return api.Operation{}, integrityErr("migration transaction omitted its exact durable reply")
	}
	if reply.Error != nil {
		if reply.Error.Retryable {
			return api.Operation{}, integrityErr("migration final error receipt cannot be retryable")
		}
		return api.Operation{}, reply.Error
	}
	var operation api.Operation
	if err := api.DecodeObject(reply.Result, &operation); err != nil || operation.ID == "" || operation.ID != operationID {
		return api.Operation{}, integrityErr("migration transaction returned an unrelated typed receipt")
	}
	switch operation.Status {
	case "pending", "running", "succeeded", "failed", "cancelled":
	default:
		return api.Operation{}, integrityErr("migration transaction returned an unknown operation status")
	}
	if operation.LastSeq < operation.FirstSeq {
		return api.Operation{}, integrityErr("migration transaction returned reversed commit sequences")
	}
	return operation, nil
}

// CompleteMigration is a trusted coordinator entry, not an RPC. The service
// must first persist its measured freeze/drain/backup phases and claim the
// immutable effect. The store independently checks this causality at commit.
func (s *Service) CompleteMigration(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.Operation, error) {
	var zero api.Operation
	if scope.Actor.Kind != "service" || scope.Request.Method != "" || !ValidConfigName(scope.Config) {
		return zero, forbiddenErr("migration completion requires the bound service coordinator")
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	effect := lease.Record.Effect
	if effect.Migration == nil || effect.Context == nil || effect.Context.Kind != api.InternalMigrationApply || effect.Context.Config != scope.Config ||
		effect.Context.Actor != scope.Actor || effect.Context.EffectID != effect.ID || effect.Context.CauseOperationID != effect.OperationID || lease.ClaimID == "" {
		return zero, forbiddenErr("migration completion lacks its original effect intent and claim")
	}
	retained, err := s.deps.Store.Effect(ctx, scope, effect.ID)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(retained, lease.Record) || retained.ClaimID != lease.ClaimID || retained.ClaimantID != scope.Actor.ID {
		return zero, forbiddenErr("migration completion effect claim is stale or foreign")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if err != nil || !expires.After(time.Now()) || lease.ExpiresAt != retained.ClaimExpiresAt {
		return zero, forbiddenErr("migration completion effect claim expired")
	}
	deployment, err := s.deps.Store.Deployment(ctx, scope, effect.Migration.PlanID)
	if err != nil {
		return zero, err
	}
	if deployment.Config != scope.Config || deployment.OperationID != effect.OperationID || deployment.MigrationPlanID != effect.Migration.PlanID ||
		deployment.Generation == 0 || deployment.Backup == nil || deployment.Freeze == nil ||
		(deployment.Phase != "migrating" && deployment.Phase != "activating" && deployment.Phase != "complete") {
		return zero, conflictErr("migration completion requires the persisted freeze, backup and migrating phase")
	}
	backup, err := s.deps.Store.FrozenBackup(ctx, scope, deployment.Backup.ID)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(backup, *deployment.Backup) || !reflect.DeepEqual(backup.Quiescence.Freeze, *deployment.Freeze) ||
		backup.Quiescence.Freeze.Config != scope.Config || backup.Quiescence.Freeze.OperationID != effect.OperationID ||
		backup.Quiescence.Freeze.InstallationGeneration != deployment.InstallationGeneration || backup.Quiescence.PendingCaptureBytes != 0 || len(backup.Quiescence.PendingEffectIDs) != 0 || !ValidTimestamp(backup.VerifiedAt) {
		return zero, integrityErr("migration backup is not matched to the measured frozen deployment")
	}
	for _, observation := range backup.Quiescence.Observations {
		if observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 {
			return zero, &api.Error{Code: api.CodeContainmentUnknown, Message: "migration backup has unknown or live processes", Instead: "Retain the frozen deployment and re-observe its containment.", Owner: "lb-v2-migration"}
		}
	}
	for _, ref := range []api.BlobRef{backup.StateManifest, backup.ConfigManifest, backup.ReleaseManifest, backup.RecoveryEvidence} {
		if _, err := readBlobFull(ctx, s.deps.Store, scope, ref); err != nil {
			return zero, err
		}
	}
	state, exists := s.lookupPlan(effect.Migration.PlanID)
	if !exists || state.config != scope.Config {
		return zero, &api.Error{Code: api.CodeNotFound, Message: "migration completion requires its retained source plan", Instead: "Reopen the same frozen manifest with migration.plan; do not repeat an unknown effect.", Owner: "lb-v2-migration"}
	}
	if backup.StateManifest != state.plan.SourceManifest {
		return zero, integrityErr("migration backup does not retain the approved source manifest")
	}
	s.mu.Lock()
	current, present := s.plans[state.plan.ID]
	if !present || current == nil || current.config != scope.Config {
		s.mu.Unlock()
		return zero, integrityErr("migration.plan disappeared before completion")
	}
	if len(current.plan.Problems) != 0 || len(migrationPlanProblems(current.bundle, s.deps.Store)) != 0 {
		s.mu.Unlock()
		return zero, conflictErr("migration.plan has unresolved problems")
	}
	s.mu.Unlock()
	bundle, err := inspectAndVerifyBundle(ctx, s.deps.Store, scope, state.request)
	if err != nil {
		return zero, err
	}
	if deployment.Phase == "migrating" {
		tx, err := buildImportTransaction(scope, state.plan, bundle, *effect.Context, deployment)
		if err != nil {
			return zero, err
		}
		if err := api.ValidateTransactionShape(tx); err != nil {
			return zero, err
		}
		if _, err := s.deps.Store.Transact(ctx, tx); err != nil {
			return zero, err
		}
		deployment = tx.Writes.Deployments[0]
	}
	s.mu.Lock()
	current, present = s.plans[state.plan.ID]
	if !present || current == nil || len(current.plan.Problems) != 0 || len(migrationPlanProblems(current.bundle, s.deps.Store)) != 0 {
		s.mu.Unlock()
		return zero, conflictErr("migration.plan disappeared or has unresolved problems")
	}
	current.bundle = bundle
	s.mu.Unlock()
	if _, err := s.verifyMigratedState(ctx, scope, state.plan.ID, true); err != nil {
		return zero, err
	}
	if deployment.Phase != "complete" {
		complete := deployment
		complete.Phase, complete.Generation = "complete", deployment.Generation+1
		payload, err := json.Marshal(api.MigrationEvent{Plan: state.plan, Manifest: state.plan.SourceManifest, LegacyEventCount: uint64(len(bundle.Events))})
		if err != nil {
			return zero, err
		}
		now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		completed := api.Event{Schema: api.SchemaVersion, ID: DeterministicID("ev-mig-complete-", scope.Config, string(state.plan.ID)),
			Config: scope.Config, Kind: "migration.completed", Actor: effect.Context.Actor, RequestedBy: effect.Context.RequestedBy,
			RequestID: effect.Context.CauseRequestID, OperationID: effect.OperationID, StarterChain: []api.ID{},
			RecordedAt: now, RequestedAt: now, ObservedAt: now, Origin: "service", Payload: payload}
		tx := api.Transaction{Scope: scope, Internal: effect.Context,
			Compare: []api.Compare{{Kind: api.CompareUpgrade, ID: deployment.ID, Generation: deployment.Generation}},
			Events:  []api.Event{completed},
			Writes:  api.StateWrites{Deployments: []api.DeploymentPlan{complete}}}
		if err := api.ValidateTransactionShape(tx); err != nil {
			return zero, err
		}
		if _, err := s.deps.Store.Transact(ctx, tx); err != nil {
			return zero, err
		}
	}
	commit, err := s.deps.Store.CompleteEffect(ctx, scope, api.EffectOutcome{EffectID: effect.ID, ClaimID: lease.ClaimID,
		ExpectedGeneration: retained.Generation, Status: "succeeded", Output: &state.plan.SourceManifest})
	if err != nil {
		return zero, err
	}
	if commit.Operation.ID != effect.OperationID || commit.Operation.Status != "succeeded" {
		return zero, integrityErr("migration effect completion omitted the correlated successful operation")
	}
	return commit.Operation, nil
}
