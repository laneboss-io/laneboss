package store

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.CredentialProjectionStore = (*Service)(nil)

type storedCredentialProjection struct {
	Owner      api.Actor
	ReservedAt api.Timestamp
	Record     api.CredentialProjectionRecord
}

func (s *Service) credentialScope(ctx context.Context, db queryer, scope api.Scope) error {
	if err := s.scope(ctx, db, scope); err != nil {
		return err
	}
	if scope.Config != s.deps.Config || scope.Actor.Kind != "service" || !wire.ValidID(string(scope.Actor.ID)) ||
		!internalScope(scope) || scope.ReadView != nil || scope.Frame != nil || !reflect.ValueOf(scope.Request).IsZero() {
		return fault(api.CodeForbidden, "credential mutation requires its private service component scope")
	}
	return nil
}

func (s *Service) credentialRow(ctx context.Context, db queryer, prepared api.ID) (storedCredentialProjection, error) {
	var row storedCredentialProjection
	if !wire.ValidID(string(prepared)) {
		return row, fault(api.CodeInvalid, "credential projection requires a prepared gate ID")
	}
	if err := storedProjection(ctx, db, "credential_projection", prepared, &row); err != nil {
		return row, err
	}
	r := row.Record
	if row.Owner.Kind != "service" || !wire.ValidID(string(row.Owner.ID)) || r.Authority.Request.Handoff.Config != s.deps.Config || r.Authority.Request.Prepared.ID != prepared ||
		!wire.ValidID(string(r.Authority.ID)) || r.Authority.Generation != 1 || r.Generation == 0 {
		return storedCredentialProjection{}, fault(api.CodeIntegrity, "credential projection lost its private gate ownership")
	}
	at, err := time.Parse(time.RFC3339Nano, string(row.ReservedAt))
	if err != nil || at.IsZero() || api.ValidateCredentialProjectionRequest(r.Authority.Request, at) != nil || validateCredentialMetadata(r.Authority) != nil {
		return storedCredentialProjection{}, fault(api.CodeIntegrity, "credential projection lost its original reservation metadata")
	}
	targets, err := api.CredentialTargets(r.Authority.Request, at)
	if err != nil || !sameValue(targets, r.Authority.Targets) {
		return storedCredentialProjection{}, fault(api.CodeIntegrity, "credential projection changed its derived destinations")
	}
	base := r
	base.State, base.Generation, base.Fence, base.Withdrawal = "reserved", 1, nil, nil
	base.Revoked, base.PriorFence = false, nil
	if r.Receipt != nil {
		base.State, base.Generation = "held", 2
		if api.ValidateCredentialHolding(r.Authority, *r.Receipt, at) != nil {
			return storedCredentialProjection{}, fault(api.CodeIntegrity, "credential projection retained an invalid held receipt")
		}
	}
	valid := r.State == base.State && r.Generation == base.Generation && r.Fence == nil && r.PriorFence == nil && r.Withdrawal == nil && !r.Revoked
	if r.PriorFence != nil {
		if api.ValidateCredentialWithdrawalRequest(base, *r.PriorFence) != nil {
			return storedCredentialProjection{}, fault(api.CodeIntegrity, "credential revocation lost its original withdrawal fence")
		}
		base.State, base.Generation, base.Fence = "withdrawing", base.Generation+1, r.PriorFence
		base.Revoked = r.PriorFence.Reason == "revoked"
	}
	if r.Fence != nil && api.ValidateCredentialWithdrawalRequest(base, *r.Fence) == nil {
		base.State, base.Generation, base.Fence = "withdrawing", base.Generation+1, r.Fence
		base.Revoked, base.PriorFence = r.Revoked || r.Fence.Reason == "revoked", r.PriorFence
		valid = r.State == "withdrawing" && r.Generation == base.Generation && r.Withdrawal == nil ||
			r.State == "withdrawn" && r.Generation == base.Generation+1 && r.Withdrawal != nil && api.ValidateCredentialWithdrawal(base, *r.Withdrawal) == nil
	}
	var indexed api.ID
	if !valid || storedProjection(ctx, db, "credential_projection_id", r.Authority.ID, &indexed) != nil || indexed != prepared {
		return storedCredentialProjection{}, fault(api.CodeIntegrity, "credential projection revision or reverse index differs")
	}
	return row, nil
}

func (s *Service) credentialByID(ctx context.Context, db queryer, id api.ID) (storedCredentialProjection, error) {
	var prepared api.ID
	if !wire.ValidID(string(id)) {
		return storedCredentialProjection{}, fault(api.CodeInvalid, "credential projection requires its retained ID")
	}
	if err := storedProjection(ctx, db, "credential_projection_id", id, &prepared); err != nil {
		return storedCredentialProjection{}, err
	}
	row, err := s.credentialRow(ctx, db, prepared)
	if err == nil && row.Record.Authority.ID != id {
		return storedCredentialProjection{}, fault(api.CodeIntegrity, "credential projection ID index differs")
	}
	return row, err
}

func (s *Service) CredentialProjection(ctx context.Context, config string, prepared api.ID) (api.CredentialProjectionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if config != s.deps.Config {
		return api.CredentialProjectionRecord{}, fault(api.CodeForbidden, "credential projection belongs to another configuration")
	}
	row, err := s.credentialRow(ctx, s.db, prepared)
	return row.Record, err
}

func (s *Service) credentialPrepare(ctx context.Context, db queryer, request api.CredentialProjectionRequest) error {
	if err := api.ValidateCredentialProjectionRequest(request, s.deps.Clock.Now()); err != nil {
		return err
	}
	current, err := effectRow(ctx, db, request.Cause.EffectID)
	if err != nil {
		return err
	}
	if !sameValue(current, request.Claim.Record) || current.State != api.EffectClaimed || current.Outcome != nil ||
		current.ClaimID != request.Claim.ClaimID || current.ClaimExpiresAt != request.Claim.ExpiresAt || !future(current.ClaimExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeConflict, "credential projection prepare claim is stale or foreign")
	}
	if request.Handoff.Spec.Kind != "agent" {
		return s.credentialWorkerRequest(ctx, db, request)
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", request.Handoff.Spec.PlanID, &plan); err != nil {
		return err
	}
	if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
		return err
	}
	r := plan.Reservation
	if plan.Plan == nil || plan.Handoff == nil || plan.Phase != "spec_retained" && plan.Phase != "bound" ||
		!sameValue(*plan.Handoff, request.Handoff) || request.Lease != plan.Plan.Lease || request.Home != plan.Plan.Data.Home ||
		r.OperationID != request.Cause.CauseOperationID || r.RequestID != request.Cause.CauseRequestID || r.RequestedBy != request.Cause.RequestedBy ||
		r.Target != request.Prepared.Target || r.CancellationEpoch != request.Cause.CancellationEpoch {
		return fault(api.CodeForbidden, "credential request differs from its exact retained launch and lease")
	}
	if err := api.ValidateAgentLaunchSpec(request.Handoff.Spec, *plan.Plan); err != nil {
		return err
	}
	return s.currentLaunch(ctx, db, plan)
}

func freezeCredential[T any](value T) (T, error) {
	var result T
	raw, err := json.Marshal(value)
	if err == nil && len(raw) > api.MaxFrameBytes {
		return result, fault(api.CodeBudget, "credential metadata exceeds its private record bound")
	}
	if err != nil {
		return result, err
	}
	err = decodeStored(raw, &result)
	return result, err
}

func (s *Service) saveCredential(ctx context.Context, row storedCredentialProjection, initial bool) (resultErr error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	r := row.Record
	if initial {
		if err := put(ctx, tx, "credential_projection_id", r.Authority.ID, 1, r.Authority.Request.Prepared.ID); err != nil {
			return err
		}
	}
	if err := put(ctx, tx, "credential_projection", r.Authority.Request.Prepared.ID, r.Generation, row); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notifyChanged()
	return nil
}

func (s *Service) ReserveCredentialProjection(ctx context.Context, scope api.Scope, input api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error) {
	request, err := freezeCredential(input)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	// Authenticate private metadata before entering the writer. The native
	// owner can perform I/O here; the transaction below never waits for it.
	if scope.Actor.Kind != "service" || !wire.ValidID(string(scope.Actor.ID)) || scope.Config != s.deps.Config || !internalScope(scope) || scope.Frame != nil || scope.ReadView != nil || !reflect.ValueOf(scope.Request).IsZero() {
		return api.CredentialProjectionRecord{}, fault(api.CodeForbidden, "credential reservation requires its private service component")
	}
	if err := api.ValidateCredentialProjectionRequest(request, s.deps.Clock.Now()); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	authority, err := s.credentialSource(ctx, scope, request)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	authority, err = freezeCredential(authority)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if err := s.credentialScope(ctx, s.db, scope); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if err := s.credentialPrepare(ctx, s.db, request); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	prior, err := s.credentialRow(ctx, s.db, request.Prepared.ID)
	if err == nil {
		if prior.Owner != scope.Actor || !sameCredentialPins(prior.Record.Authority.Request, request) {
			return api.CredentialProjectionRecord{}, fault(api.CodeConflict, "credential reservation retry changed its owner or stable launch pins")
		}
		authority.ID, authority.Generation = prior.Record.Authority.ID, prior.Record.Authority.Generation
		if !sameValue(authority.Sources, prior.Record.Authority.Sources) || authority.Helper != prior.Record.Authority.Helper || authority.Broker != prior.Record.Authority.Broker ||
			authority.HelperPeer != prior.Record.Authority.HelperPeer || authority.BrokerPeer != prior.Record.Authority.BrokerPeer || authority.BootID != prior.Record.Authority.BootID ||
			authority.InstallationGeneration != prior.Record.Authority.InstallationGeneration || authority.ServiceUID != prior.Record.Authority.ServiceUID {
			return api.CredentialProjectionRecord{}, fault(api.CodeForbidden, "credential reservation native authority or source inventory changed")
		}
		if prior.Record.State != "reserved" && prior.Record.State != "held" {
			return api.CredentialProjectionRecord{}, fault(api.CodeConflict, "credential reservation is fenced for withdrawal")
		}
		if prior.Record.State == "reserved" && !sameValue(prior.Record.Authority.Request, request) {
			prior.Record.Authority = authority
			if err := s.saveCredential(ctx, prior, false); err != nil {
				return api.CredentialProjectionRecord{}, err
			}
		}
		return prior.Record, nil
	}
	if !absent(err) {
		return api.CredentialProjectionRecord{}, err
	}
	authority.ID, err = wire.NewID()
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	authority.Generation = 1
	row := storedCredentialProjection{Owner: scope.Actor, ReservedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)),
		Record: api.CredentialProjectionRecord{Authority: authority, Generation: 1, State: "reserved"}}
	if err := s.saveCredential(ctx, row, true); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return row.Record, nil
}

func (s *Service) CommitCredentialProjection(ctx context.Context, scope api.Scope, input api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	receipt, err := freezeCredential(input)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	s.mu.RLock()
	if err := s.available(); err != nil {
		s.mu.RUnlock()
		return api.CredentialProjectionRecord{}, err
	}
	if err := s.credentialScope(ctx, s.db, scope); err != nil {
		s.mu.RUnlock()
		return api.CredentialProjectionRecord{}, err
	}
	row, err := s.credentialRow(ctx, s.db, receipt.Prepared.ID)
	s.mu.RUnlock()
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if row.Owner != scope.Actor || row.Record.State != "reserved" || receipt.ProjectionID != row.Record.Authority.ID || receipt.Generation != row.Record.Generation+1 {
		return api.CredentialProjectionRecord{}, fault(api.CodeConflict, "credential commit requires its original uncommitted reservation revision")
	}
	current, err := s.credentialSource(ctx, scope, row.Record.Authority.Request)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	current.ID, current.Generation = row.Record.Authority.ID, row.Record.Authority.Generation
	if !sameValue(current, row.Record.Authority) {
		return api.CredentialProjectionRecord{}, fault(api.CodeForbidden, "credential source inventory changed before holding commit")
	}
	observed, err := s.deps.CredentialProjection.ObserveCredentialProjection(ctx, row.Record.Authority)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if api.ValidateCredentialReobservation(row.Record.Authority, receipt, observed, s.deps.Clock.Now()) != nil {
		return api.CredentialProjectionRecord{}, fault(api.CodeIntegrity, "credential commit differs from the helper's actual held receipt")
	}
	if err := api.ValidateCredentialHolding(row.Record.Authority, receipt, s.deps.Clock.Now()); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if !credentialTimestamp(receipt.ObservedAt, s.deps.Clock.Now()) {
		return api.CredentialProjectionRecord{}, fault(api.CodeInvalid, "credential holding has no current private observation time")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if err := s.credentialScope(ctx, s.db, scope); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	live, err := s.credentialRow(ctx, s.db, receipt.Prepared.ID)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if !sameValue(live, row) {
		return api.CredentialProjectionRecord{}, fault(api.CodeConflict, "credential reservation changed during helper observation")
	}
	if err := s.credentialPrepare(ctx, s.db, row.Record.Authority.Request); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	row.Record.State, row.Record.Generation, row.Record.Receipt = "held", receipt.Generation, &receipt
	if err := s.saveCredential(ctx, row, false); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return row.Record, nil
}

func (s *Service) credentialCleanup(ctx context.Context, db queryer, row storedCredentialProjection, cause api.InternalIntent) error {
	current, err := effectRow(ctx, db, cause.EffectID)
	if err != nil {
		return err
	}
	lease, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !api.EffectLeaseClaimed(lease) || !sameValue(lease.Record, current) || lease.ClaimID != current.ClaimID || lease.ExpiresAt != current.ClaimExpiresAt {
		return fault(api.CodeForbidden, "credential cleanup requires its explicit current effect attempt")
	}
	if current.State != api.EffectClaimed || current.Outcome != nil || !future(current.ClaimExpiresAt, s.deps.Clock.Now()) || current.Effect.Context == nil {
		return fault(api.CodeConflict, "credential withdrawal requires its current durable cleanup claim")
	}
	cleanup, cleanupBound := api.PlanCleanupClaimFromContext(ctx)
	if !cleanupBound {
		// Native helper callbacks carry their exact EffectLease over the private
		// channel. Join that independently retained teardown effect to its live
		// cleanup attempt, never to a planner discovered from a life label.
		var saved storedPlanCleanup
		err := storedProjection(ctx, db, "plan_cleanup", cause.EffectID, &saved)
		if err != nil && !absent(err) {
			return err
		}
		if err == nil && saved.Request.Kind == "withdraw" && saved.Attempt != nil && saved.Attempt.ClaimantID == current.ClaimantID {
			cleanup, cleanupBound = *saved.Attempt, true
		}
	}
	if cleanupBound {
		scope := api.Scope{Config: cause.Config, Actor: api.Actor{Kind: "service", ID: cleanup.ClaimantID}, Source: "worker"}
		saved, err := s.currentPlanCleanup(ctx, scope, cleanup)
		if err != nil {
			return err
		}
		job, request := saved.Request, row.Record.Authority.Request
		allocation, err := s.cleanupAllocation(ctx, db, job)
		if err != nil {
			return err
		}
		if job.Kind != "withdraw" || job.Withdrawal == nil || job.Prepared == nil || !sameValue(job.Cause, cause) ||
			job.Withdrawal.ProjectionID != row.Record.Authority.ID || *job.Prepared != request.Prepared || allocation != request.Lease ||
			current.ClaimantID != cleanup.ClaimantID || current.Effect.ID != job.ID || current.Effect.OperationID != cause.CauseOperationID ||
			current.Effect.Context.Target != cause.Target ||
			(current.Effect.HelperAbort == nil || current.Effect.HelperAbort.LeaseID != allocation.ID || current.Effect.HelperAbort.PreparedID != job.Prepared.ID) &&
				(current.Effect.HelperRelease == nil || current.Effect.HelperRelease.LeaseID != allocation.ID) {
			return fault(api.CodeForbidden, "failed-plan credential withdrawal differs from its original cleanup and native attempt")
		}
		return nil
	}
	actual := *current.Effect.Context
	if actual.Kind == api.InternalLifecycleEffect && cause.Kind == api.InternalHelperStop && current.Effect.Stop != nil {
		key := api.ID(hash([]byte(string(current.Effect.ID) + ":" + string(cause.Kind) + ":" + string(current.ClaimID))))
		var retained struct {
			Claim      api.ID
			Generation api.Generation
			Cause      api.InternalIntent
		}
		if err := storedProjection(ctx, db, "launch_control", key, &retained); err != nil || retained.Claim != current.ClaimID ||
			retained.Generation != current.Generation || retained.Cause != cause {
			return fault(api.CodeForbidden, "credential stop cleanup requires its exact retained stage cause")
		}
		actual.Kind, actual.ID = cause.Kind, cause.ID
	}
	actual.Actor = api.Actor{Kind: "service", ID: lease.Record.ClaimantID}
	request := row.Record.Authority.Request
	if actual != cause || cause.Target != request.Prepared.Target || current.Effect.OperationID != cause.CauseOperationID {
		return fault(api.CodeForbidden, "credential cleanup differs from its retained effect cause")
	}
	matched := false
	switch cause.Kind {
	case api.InternalHelperAbort:
		abort := current.Effect.HelperAbort
		matched = abort != nil && abort.LeaseID == request.Lease.ID && abort.PreparedID == request.Prepared.ID && abort.SpecSHA256 == request.Handoff.SpecSHA256
	case api.InternalHelperRelease:
		release := current.Effect.HelperRelease
		matched = release != nil && release.LeaseID == request.Lease.ID
	case api.InternalHelperStop:
		stop := current.Effect.Stop
		matched = stop != nil && stop.Target == request.Prepared.Target && stop.ContainmentID == request.Prepared.ContainmentID && stop.Generation == request.Prepared.ProcessGeneration
	}
	if !matched {
		return fault(api.CodeForbidden, "credential cleanup effect belongs to another lease or prepared gate")
	}
	return nil
}

func (s *Service) FenceCredentialProjection(ctx context.Context, scope api.Scope, input api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	request, err := freezeCredential(input)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if err := s.credentialScope(ctx, s.db, scope); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	row, err := s.credentialByID(ctx, s.db, request.ProjectionID)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if row.Owner != scope.Actor {
		return api.CredentialProjectionRecord{}, fault(api.CodeForbidden, "credential fence belongs to another component")
	}
	if err := s.credentialCleanup(ctx, s.db, row, request.Cause); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if row.Record.Fence != nil && sameValue(*row.Record.Fence, request) {
		return row.Record, nil
	}
	if err := api.ValidateCredentialWithdrawalRequest(row.Record, request); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if row.Record.State == "withdrawing" {
		row.Record.PriorFence = row.Record.Fence
	}
	row.Record.State, row.Record.Generation, row.Record.Fence = "withdrawing", row.Record.Generation+1, &request
	row.Record.Revoked = row.Record.Revoked || request.Reason == "revoked"
	if err := s.saveCredential(ctx, row, false); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return row.Record, nil
}

func (s *Service) CompleteCredentialWithdrawal(ctx context.Context, scope api.Scope, input api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	receipt, err := freezeCredential(input)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if err := s.credentialScope(ctx, s.db, scope); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	row, err := s.credentialByID(ctx, s.db, receipt.ProjectionID)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if row.Owner != scope.Actor {
		return api.CredentialProjectionRecord{}, fault(api.CodeForbidden, "credential completion belongs to another component")
	}
	if err := s.credentialCleanup(ctx, s.db, row, receipt.Cause); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if row.Record.State == "withdrawn" && row.Record.Withdrawal != nil && sameValue(*row.Record.Withdrawal, receipt) {
		return row.Record, nil
	}
	if err := api.ValidateCredentialWithdrawal(row.Record, receipt); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if !credentialTimestamp(receipt.ObservedAt, s.deps.Clock.Now()) || !credentialTimestamp(receipt.Observation.ObservedAt, s.deps.Clock.Now()) {
		return api.CredentialProjectionRecord{}, fault(api.CodeInvalid, "credential withdrawal has no bounded observation time")
	}
	row.Record.State, row.Record.Generation, row.Record.Withdrawal = "withdrawn", receipt.Generation, &receipt
	if err := s.saveCredential(ctx, row, false); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return row.Record, nil
}
