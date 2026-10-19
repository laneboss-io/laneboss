package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.FailedPlanStore = (*Service)(nil)
var _ api.PlanCleanupStore = (*Service)(nil)

type planCleanupRequests = []api.PlanCleanup
type planCleanupKey struct{}
type planObjectKey struct{}
type planObjectAuthority struct {
	Store      *Service
	Owner      api.Actor
	LifeID     api.ID
	Generation api.Generation
}
type planCleanupAuthority struct {
	Store *Service
	Jobs  planCleanupRequests
}

type storedPlanCleanup struct {
	Request         api.PlanCleanup
	IntentID        api.ID
	ReceiptID       api.ID
	ClaimID         api.ID
	ClaimGeneration api.Generation
	Generation      api.Generation
	State           string
	Attempt         *api.PlanCleanupClaim   `json:",omitempty"`
	Completion      *api.PlanCleanupReceipt `json:",omitempty"`
	Refusal         *api.Error              `json:",omitempty"`
}

func (s *Service) cleanupRequests(ctx context.Context) planCleanupRequests {
	bound, ok := ctx.Value(planCleanupKey{}).(planCleanupAuthority)
	if !ok || bound.Store != s {
		return nil
	}
	return bound.Jobs
}

// Only FailPlan binds this private capability after freezing the complete API
// cleanup batch. Ordinary transactions retain the shared failed-write refusal.
func (s *Service) validateInternalShape(ctx context.Context, input api.Transaction) error {
	if jobs := s.cleanupRequests(ctx); len(jobs) != 0 {
		return api.ValidateFailedPlanWrite(input, jobs)
	}
	return api.ValidateTransactionShape(input)
}

func (s *Service) internalReceiptID(ctx context.Context, input api.Transaction) api.ID {
	if len(s.cleanupRequests(ctx)) != 0 {
		return cleanupObjectID(input.Writes.LaunchPlans[0].Reservation.ID, "cleanup-commit")
	}
	return input.Internal.ID
}

// This private port keeps the failed revision and cleanup requests inside the
// existing internal transaction. Nothing here executes or acknowledges cleanup.
func (s *Service) FailPlan(ctx context.Context, input api.Transaction, jobs []api.PlanCleanup) (api.Commit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return api.Commit{}, err
	}
	if err := s.scope(ctx, s.db, input.Scope); err != nil {
		return api.Commit{}, err
	}
	if !internalScope(input.Scope) || input.Scope.Actor.Kind != "service" || input.Internal == nil ||
		input.Internal.Kind != api.InternalLaunchPlan || len(input.Writes.LaunchPlans) != 1 || len(jobs) == 0 || len(jobs) > 2 ||
		len(input.Effects) != 0 || input.Reply != nil || input.Deferred != nil ||
		!reflect.DeepEqual(input.Writes, api.StateWrites{LaunchPlans: input.Writes.LaunchPlans}) {
		return api.Commit{}, fault(api.CodeForbidden, "failed-plan cleanup requires its sole planning revision and private requests")
	}
	// Freeze the caller-owned slice and pointer fields before constructing the
	// replay digest. The private capability cannot be supplied on an RPC.
	raw, err := json.Marshal(jobs)
	if err != nil {
		return api.Commit{}, err
	}
	if len(raw) > api.MaxFrameBytes {
		return api.Commit{}, fault(api.CodeInvalid, "failed-plan cleanup exceeds its metadata bound")
	}
	var retained planCleanupRequests
	// These are in-process private requests, not RPC envelopes. Preserve the
	// original cause's absent logical turn, nil stage results and unknown slot
	// instead of applying the public wire schema to those retained facts.
	// validatePlanCleanup resolves every required selector under this same lock.
	if err := decodeStored(raw, &retained); err != nil {
		return api.Commit{}, err
	}
	ctx = context.WithValue(ctx, planCleanupKey{}, planCleanupAuthority{Store: s, Jobs: retained})
	return s.transactInternal(ctx, input)
}

func cleanupObjectID(reservation api.ID, stage string) api.ID {
	return api.ID(hash([]byte("launch\x00" + string(reservation) + "\x00" + stage)))
}

func (s *Service) privatePlanObject(ctx context.Context, scope api.Scope, object api.ObjectWrite) bool {
	bound, ok := ctx.Value(planObjectKey{}).(planObjectAuthority)
	return ok && bound.Store == s && scope.Connection == nil && scope.Actor.Kind == "service" &&
		object.ACL.Owner == bound.Owner && object.ACL.LifeID == bound.LifeID && object.ACL.Generation == bound.Generation &&
		object.ACL.Config == s.deps.Config && object.ACL.Audience == "service" && len(object.ACL.Participants) == 0 &&
		(object.Class == "manifest" || object.Class == "launch_spec") && object.Origin == "service"
}

type cleanupStageResult struct {
	Schema string          `json:"schema"`
	Input  api.Digest      `json:"input"`
	Value  json.RawMessage `json:"value,omitempty"`
	Error  *api.Error      `json:"error,omitempty"`
}

func (s *Service) cleanupObject(ctx context.Context, db queryer, r api.LaunchReservation, ref api.BlobRef, stage string) ([]byte, error) {
	meta, raw, err := objectRow(ctx, db, ref.ID)
	if err != nil {
		return nil, err
	}
	if ref.ID != cleanupObjectID(r.ID, stage) || ref.Class != "manifest" || meta.Ref != ref || meta.SourceOperationID != r.OperationID ||
		meta.Origin != "service" || meta.ACL.Config != r.Config || meta.ACL.LifeID != r.Target.LifeID || meta.ACL.Owner.Kind != "service" ||
		(meta.ACL.Audience != "owner" && meta.ACL.Audience != "service") || len(meta.ACL.Participants) != 0 {
		return nil, fault(api.CodeForbidden, "cleanup stage differs from its original private selector")
	}
	return raw, nil
}

func (s *Service) cleanupResult(ctx context.Context, db queryer, r api.LaunchReservation, ref api.BlobRef, stage string) (cleanupStageResult, error) {
	var result cleanupStageResult
	raw, err := s.cleanupObject(ctx, db, r, ref, "result-"+stage)
	if err != nil {
		return result, err
	}
	if err := wire.Decode(raw, &result); err != nil {
		return result, err
	}
	input, _, err := objectRow(ctx, db, cleanupObjectID(r.ID, "input-"+stage))
	if err != nil {
		return result, err
	}
	if _, err := s.cleanupObject(ctx, db, r, input.Ref, "input-"+stage); err != nil {
		return result, err
	}
	if result.Schema != "laneboss.launch-stage.v2" || result.Input != input.Ref.SHA256 {
		return result, fault(api.CodeIntegrity, "cleanup result changed its retained stage input")
	}
	return result, nil
}

func (s *Service) validatePlanCleanup(ctx context.Context, db queryer, input api.Transaction) error {
	jobs := s.cleanupRequests(ctx)
	if len(jobs) == 0 {
		return nil
	}
	next := input.Writes.LaunchPlans[0]
	r := next.Reservation
	var old api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", r.ID, &old); err != nil {
		return err
	}
	if old.Phase == "opened" || old.Phase == "failed" || next.Phase != "failed" || next.Error == nil {
		return fault(api.CodeConflict, "cleanup cannot replace an opened or terminal launch")
	}
	expected := old
	expected.Phase, expected.Error, expected.Generation = "failed", next.Error, old.Generation+1
	if !sameValue(expected, next) {
		return fault(api.CodeConflict, "failed-plan cleanup changed immutable launch stages")
	}
	if err := s.checkLaunchBytes(ctx, db, old); err != nil {
		return err
	}
	claim, err := s.launchClaim(ctx, db, input.Scope, *input.Internal)
	if err != nil {
		return err
	}
	if claim.Effect.PlanLaunch == nil || claim.Effect.PlanLaunch.ReservationID != r.ID || input.Internal.LogicalTurnID != claim.Effect.Context.LogicalTurnID {
		return fault(api.CodeForbidden, "cleanup has no original planning claim")
	}
	epoch, err := s.cancellationEpoch(ctx, db, r.Target.LifeID)
	if err != nil {
		return err
	}
	if epoch != r.CancellationEpoch {
		return fault(api.CodeConflict, "failed-plan cleanup cancellation epoch changed")
	}
	if len(input.Compare) != 1 || input.Compare[0] != (api.Compare{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: old.Generation}) ||
		len(input.Guards) != 1 || input.Guards[0].Cancellation == nil || !reflect.DeepEqual(input.Guards[0], api.TransactionGuard{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}) {
		return fault(api.CodeForbidden, "cleanup requires its exact plan CAS and cancellation guard")
	}
	binding, bindingErr := s.launchBinding(ctx, db, r.LaunchID)
	var projected int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='credential_projection' AND json_extract(data,'$.Record.Authority.Request.Handoff.spec.launch_id')=?", string(r.LaunchID)).Scan(&projected); err != nil {
		return err
	}
	// A failed lookup is never authority to release unprojected material.
	withdraw := bindingErr == nil || !absent(bindingErr) || old.Phase == "bound" || projected != 0
	kinds, ids := map[string]bool{}, map[api.ID]bool{}
	for _, job := range jobs {
		cause := job.Cause
		if !wire.ValidID(string(job.ID)) || job.ID != cleanupObjectID(r.ID, "cleanup-"+job.Kind) || ids[job.ID] || kinds[job.Kind] ||
			job.ReservationID != r.ID || job.LaunchID != r.LaunchID || cause.EffectID != job.ID ||
			cause.ID != cleanupObjectID(r.ID, "cause-cleanup-"+job.Kind) || cause.Config != r.Config || cause.Actor != input.Scope.Actor ||
			cause.RequestedBy != r.RequestedBy || cause.Target != r.Target || cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID ||
			cause.CancellationEpoch != r.CancellationEpoch || cause.LogicalTurnID != claim.Effect.Context.LogicalTurnID {
			return fault(api.CodeForbidden, "cleanup request changed its original causal selector")
		}
		ids[job.ID], kinds[job.Kind] = true, true
		if job.Kind != "withdraw" && job.Kind != "release" && job.Kind != "revoke_injection" ||
			job.Kind == "withdraw" && cause.Kind != api.InternalHelperAbort || job.Kind != "withdraw" && cause.Kind != api.InternalHelperRelease {
			return fault(api.CodeForbidden, "cleanup request has an unknown teardown kind")
		}
		if _, err := s.cleanupObject(ctx, db, r, job.SlotResult, "result-credential-slot"); err != nil {
			return err
		}
		if job.SlotKnown {
			result, err := s.cleanupResult(ctx, db, r, job.SlotResult, "credential-slot")
			var slot api.CredentialSlot
			if err != nil || result.Error != nil || wire.Decode(result.Value, &slot) != nil || !wire.ValidID(string(slot.ID)) || !wire.ValidID(string(slot.LeaseID)) || slot != job.Slot {
				return fault(api.CodeIntegrity, "cleanup slot differs from its exact retained result")
			}
		} else if job.Slot != (api.CredentialSlot{}) || len(job.Issues) == 0 {
			return fault(api.CodeIntegrity, "unknown cleanup slot lost its reconciliation facts")
		}
		for _, selected := range []struct {
			stage string
			ref   *api.BlobRef
		}{{"input-injection", job.InjectionIn}, {"result-injection", job.InjectionOut}} {
			meta, _, err := objectRow(ctx, db, cleanupObjectID(r.ID, selected.stage))
			if err == nil && (selected.ref == nil || meta.Ref != *selected.ref) || absent(err) && selected.ref != nil {
				return fault(api.CodeIntegrity, "cleanup omitted or replaced its protected injection selector")
			}
			if err != nil && !absent(err) {
				return err
			}
		}
		if job.InjectionIn != nil {
			if _, err := s.cleanupObject(ctx, db, r, *job.InjectionIn, "input-injection"); err != nil {
				return err
			}
		}
		if job.InjectionOut != nil {
			if _, err := s.cleanupObject(ctx, db, r, *job.InjectionOut, "result-injection"); err != nil {
				return err
			}
		}
		if job.Injection != nil {
			if job.InjectionOut == nil {
				return fault(api.CodeIntegrity, "cleanup injection has no retained result")
			}
			result, err := s.cleanupResult(ctx, db, r, *job.InjectionOut, "injection")
			var injection api.Injection
			if err != nil || result.Error != nil || wire.Decode(result.Value, &injection) != nil || injection.Target != r.Target || !sameValue(injection, *job.Injection) {
				return fault(api.CodeIntegrity, "cleanup injection changed its retained outcome")
			}
		}
		if job.Kind == "withdraw" {
			if bindingErr == nil && (job.Prepared == nil || *job.Prepared != binding.Prepared || old.Handoff == nil || binding.Recovery == nil || !sameValue(binding.Recovery.Handoff, *old.Handoff)) {
				return fault(api.CodeConflict, "cleanup withdrawal changed its original prepared gate")
			}
			if bindingErr != nil && (job.Prepared != nil || job.Withdrawal != nil || len(job.Issues) == 0) {
				return fault(api.CodeContainmentUnknown, "cleanup lookup uncertainty requires original-selector reconciliation")
			}
			if job.Withdrawal != nil {
				row, err := s.credentialByID(ctx, db, job.Withdrawal.ProjectionID)
				if err != nil {
					return err
				}
				projection := row.Record
				request := projection.Authority.Request
				if job.Prepared == nil || request.Prepared != *job.Prepared || old.Handoff == nil || !sameValue(request.Handoff, *old.Handoff) ||
					job.Withdrawal.Cause != cause || job.Withdrawal.Reason != "refused" {
					return fault(api.CodeForbidden, "cleanup projection selector differs from its original handoff")
				}
				if err := api.ValidateCredentialWithdrawalRequest(projection, *job.Withdrawal); err != nil {
					return err
				}
			} else if len(job.Issues) == 0 {
				return fault(api.CodeContainmentUnknown, "cleanup withdrawal has no projection result or uncertainty")
			}
		} else if withdraw || job.Prepared != nil || job.Withdrawal != nil {
			return fault(api.CodeForbidden, "projected or uncertain material requires withdrawal before release")
		}
	}
	if kinds["withdraw"] && len(jobs) != 1 || !kinds["withdraw"] && (!kinds["release"] || !kinds["revoke_injection"]) {
		return fault(api.CodeForbidden, "cleanup must retain the complete teardown request set")
	}
	return nil
}

// Generic transaction callers cannot record a credential-bearing failed plan
// and omit its outbox. Only FailPlan can provide the private writer capability.
func (s *Service) requirePlanCleanup(ctx context.Context, db queryer, input api.Transaction) error {
	if input.Internal == nil || input.Internal.Kind != api.InternalLaunchPlan || len(s.cleanupRequests(ctx)) != 0 {
		return nil
	}
	for _, plan := range input.Writes.LaunchPlans {
		if plan.Phase != "failed" {
			continue
		}
		_, _, err := objectRow(ctx, db, cleanupObjectID(plan.Reservation.ID, "result-credential-slot"))
		if err == nil {
			return fault(api.CodeForbidden, "credential-bearing failed plan requires its atomic cleanup outbox")
		}
		if !absent(err) {
			return err
		}
	}
	return nil
}

func (s *Service) writePlanCleanup(ctx context.Context, tx *sql.Tx, input api.Transaction) error {
	jobs := s.cleanupRequests(ctx)
	if len(jobs) == 0 {
		return nil
	}
	claim, err := effectRow(ctx, tx, input.Internal.EffectID)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		saved := storedPlanCleanup{Request: job, IntentID: input.Internal.ID, ReceiptID: s.internalReceiptID(ctx, input), ClaimID: claim.ClaimID,
			ClaimGeneration: claim.Generation, Generation: 1, State: "pending"}
		if err := putGenerated(ctx, tx, "plan_cleanup", job.ID, 1, saved); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) PlanCleanup(ctx context.Context, scope api.Scope, id api.ID) (api.PlanCleanup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.PlanCleanup{}, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return api.PlanCleanup{}, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		return api.PlanCleanup{}, fault(api.CodeForbidden, "cleanup outbox is service-internal")
	}
	var saved storedPlanCleanup
	if err := storedProjection(ctx, s.db, "plan_cleanup", id, &saved); err != nil {
		return api.PlanCleanup{}, err
	}
	if err := s.cleanupState(saved, id); err != nil {
		return api.PlanCleanup{}, err
	}
	return saved.Request, nil
}

func (s *Service) PendingPlanCleanup(ctx context.Context, scope api.Scope) ([]api.PlanCleanup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return nil, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		return nil, fault(api.CodeForbidden, "cleanup inventory requires the service coordinator")
	}
	return s.pendingPlanCleanup(ctx)
}

func (s *Service) pendingPlanCleanup(ctx context.Context) ([]api.PlanCleanup, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,data FROM projections WHERE kind='plan_cleanup' ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []api.PlanCleanup{}
	for rows.Next() {
		var id api.ID
		var raw []byte
		var saved storedPlanCleanup
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		if err := decodeStored(raw, &saved); err != nil {
			return nil, err
		}
		if err := s.cleanupState(saved, id); err != nil {
			return nil, err
		}
		if saved.State == "completed" {
			continue
		}
		jobs = append(jobs, saved.Request)
	}
	return jobs, errors.Join(rows.Err(), rows.Close())
}

func (s *Service) verifyCleanupOutbox(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id,data FROM projections WHERE kind='plan_cleanup' ORDER BY id")
	if err != nil {
		return err
	}
	var saved []storedPlanCleanup
	for rows.Next() {
		var id api.ID
		var raw []byte
		var item storedPlanCleanup
		if err := rows.Scan(&id, &raw); err != nil {
			return errors.Join(err, rows.Close())
		}
		if err := decodeStored(raw, &item); err != nil || s.cleanupState(item, id) != nil ||
			!wire.ValidID(string(item.IntentID)) || !wire.ValidID(string(item.ClaimID)) || item.ClaimGeneration < 2 {
			return errors.Join(fault(api.CodeIntegrity, "cleanup outbox lost its committed request identity"), rows.Close())
		}
		saved = append(saved, item)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, item := range saved {
		job := item.Request
		var plan api.LaunchPlanRecord
		var receipt internalCommit
		if err := storedProjection(ctx, s.db, "launch_plan", job.ReservationID, &plan); err != nil {
			return err
		}
		if err := storedProjection(ctx, s.db, "internal_commit", item.ReceiptID, &receipt); err != nil {
			return err
		}
		r := plan.Reservation
		if plan.Phase != "failed" || plan.Error == nil || item.ReceiptID != cleanupObjectID(r.ID, "cleanup-commit") ||
			job.ID != cleanupObjectID(r.ID, "cleanup-"+job.Kind) || job.LaunchID != r.LaunchID || job.Cause.Config != s.deps.Config ||
			job.Cause.CauseOperationID != r.OperationID || job.Cause.Target != r.Target || receipt.Commit.Operation.ID != r.OperationID {
			return fault(api.CodeIntegrity, "cleanup outbox has no same-commit failed plan and receipt")
		}
		if _, err := s.cleanupObject(ctx, s.db, r, job.SlotResult, "result-credential-slot"); err != nil {
			return err
		}
		if item.Completion != nil {
			if err := s.validateCleanupReceipt(ctx, s.db, item.Request, *item.Completion); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) cleanupState(saved storedPlanCleanup, id api.ID) error {
	job := saved.Request
	if !wire.ValidID(string(id)) || job.ID != id || job.ID != cleanupObjectID(job.ReservationID, "cleanup-"+job.Kind) ||
		job.Cause.Config != s.deps.Config || saved.Generation == 0 || saved.Generation >= 1<<53 ||
		!wire.ValidID(string(saved.IntentID)) || !wire.ValidID(string(saved.ReceiptID)) ||
		!wire.ValidID(string(saved.ClaimID)) || saved.ClaimGeneration < 2 {
		return fault(api.CodeIntegrity, "cleanup outbox identity or provenance changed")
	}
	if saved.Refusal != nil && (saved.Refusal.Code == "" || saved.Refusal.Owner == "") {
		return fault(api.CodeIntegrity, "cleanup refusal lost its owning cause")
	}
	switch saved.State {
	case "pending":
		if saved.Attempt != nil || saved.Completion != nil {
			return fault(api.CodeIntegrity, "pending cleanup carries a live claim or completion")
		}
	case "claimed", "completed":
		a := saved.Attempt
		if a == nil || !sameValue(a.Request, job) || !wire.ValidID(string(a.ClaimID)) || !wire.ValidID(string(a.ClaimantID)) || a.Generation < 2 {
			return fault(api.CodeIntegrity, "cleanup lost its exact durable attempt")
		}
		if _, err := time.Parse(time.RFC3339Nano, string(a.ExpiresAt)); err != nil {
			return fault(api.CodeIntegrity, "cleanup attempt has no deadline")
		}
		if saved.State == "claimed" && (saved.Generation != a.Generation || saved.Completion != nil) ||
			saved.State == "completed" && (saved.Generation != a.Generation+1 || saved.Completion == nil) {
			return fault(api.CodeIntegrity, "cleanup completion differs from its claimed revision")
		}
	default:
		return fault(api.CodeIntegrity, "cleanup outbox has an unknown state")
	}
	return nil
}

func (s *Service) cleanupCoordinator(ctx context.Context, scope api.Scope) error {
	if err := s.available(); err != nil {
		return err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return err
	}
	return dispatchController(scope, s.deps.Config)
}

func (s *Service) PlanCleanupStatus(ctx context.Context, scope api.Scope, id api.ID) (api.PlanCleanupStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.cleanupCoordinator(ctx, scope); err != nil {
		return api.PlanCleanupStatus{}, err
	}
	var saved storedPlanCleanup
	if err := storedProjection(ctx, s.db, "plan_cleanup", id, &saved); err != nil {
		return api.PlanCleanupStatus{}, err
	}
	if err := s.cleanupState(saved, id); err != nil {
		return api.PlanCleanupStatus{}, err
	}
	return api.PlanCleanupStatus{Request: saved.Request, Generation: saved.Generation, State: saved.State,
		Claim: saved.Attempt, Receipt: saved.Completion, Refusal: saved.Refusal}, nil
}

// Revalidate the original private commit independently of the planner's now
// terminal/expired effect. Cleanup cannot inherit planning or opening authority.
func (s *Service) cleanupOrigin(ctx context.Context, db queryer, saved storedPlanCleanup) (api.LaunchPlanRecord, error) {
	var plan api.LaunchPlanRecord
	var receipt internalCommit
	job := saved.Request
	if err := storedProjection(ctx, db, "launch_plan", job.ReservationID, &plan); err != nil {
		return plan, err
	}
	if err := storedProjection(ctx, db, "internal_commit", saved.ReceiptID, &receipt); err != nil {
		return plan, err
	}
	r := plan.Reservation
	if plan.Phase != "failed" || plan.Error == nil || saved.ReceiptID != cleanupObjectID(r.ID, "cleanup-commit") ||
		job.LaunchID != r.LaunchID || job.Cause.Target != r.Target || job.Cause.CauseOperationID != r.OperationID ||
		job.Cause.CauseRequestID != r.RequestID || job.Cause.RequestedBy != r.RequestedBy ||
		job.Cause.CancellationEpoch != r.CancellationEpoch || receipt.Commit.Operation.ID != r.OperationID {
		return plan, fault(api.CodeIntegrity, "cleanup has no original atomic failed-plan commit")
	}
	if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
		return plan, err
	}
	if _, err := s.cleanupObject(ctx, db, r, job.SlotResult, "result-credential-slot"); err != nil {
		return plan, err
	}
	epoch, err := s.cancellationEpoch(ctx, db, r.Target.LifeID)
	if err != nil {
		return plan, err
	}
	if epoch != job.Cause.CancellationEpoch {
		return plan, fault(api.CodeConflict, "cleanup cancellation epoch changed; retain the original allocation")
	}
	return plan, nil
}

func (s *Service) savePlanCleanup(ctx context.Context, saved storedPlanCleanup) (resultErr error) {
	if err := s.cleanupState(saved, saved.Request.ID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := putGenerated(ctx, tx, "plan_cleanup", saved.Request.ID, saved.Generation, saved); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notifyChanged()
	return nil
}

func (s *Service) ClaimPlanCleanup(ctx context.Context, scope api.Scope, job api.PlanCleanup, request api.EffectClaimRequest) (api.PlanCleanupClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cleanupCoordinator(ctx, scope); err != nil {
		return api.PlanCleanupClaim{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(request.Deadline))
	if err != nil || !deadline.After(s.deps.Clock.Now()) || deadline.After(s.deps.Clock.Now().Add(30*time.Second)) ||
		request.EffectID != job.ID || request.ClaimantID != scope.Actor.ID {
		return api.PlanCleanupClaim{}, fault(api.CodeForbidden, "cleanup claim requires its authentic bounded coordinator")
	}
	var saved storedPlanCleanup
	if err := storedProjection(ctx, s.db, "plan_cleanup", job.ID, &saved); err != nil {
		return api.PlanCleanupClaim{}, err
	}
	if err := s.cleanupState(saved, job.ID); err != nil {
		return api.PlanCleanupClaim{}, err
	}
	if !sameValue(saved.Request, job) {
		return api.PlanCleanupClaim{}, fault(api.CodeForbidden, "cleanup claim changed its immutable request")
	}
	if saved.Generation != request.ExpectedGeneration || saved.State == "completed" || saved.Attempt != nil && future(saved.Attempt.ExpiresAt, s.deps.Clock.Now()) {
		return api.PlanCleanupClaim{}, fault(api.CodeConflict, "cleanup request is completed or has another live claim")
	}
	if _, err := s.cleanupOrigin(ctx, s.db, saved); err != nil {
		return api.PlanCleanupClaim{}, err
	}
	if job.Kind == "revoke_injection" {
		var release storedPlanCleanup
		if err := storedProjection(ctx, s.db, "plan_cleanup", cleanupObjectID(job.ReservationID, "cleanup-release"), &release); err != nil {
			return api.PlanCleanupClaim{}, err
		}
		if release.State != "completed" || release.Completion == nil {
			return api.PlanCleanupClaim{}, fault(api.CodeContainmentUnknown, "injection revocation waits for the original measured release")
		}
	}
	id, err := wire.NewID()
	if err != nil {
		return api.PlanCleanupClaim{}, err
	}
	saved.Generation++
	claim := api.PlanCleanupClaim{Request: saved.Request, Generation: saved.Generation, ClaimID: id, ClaimantID: scope.Actor.ID, ExpiresAt: request.Deadline}
	saved.State, saved.Attempt = "claimed", &claim
	if err := s.savePlanCleanup(ctx, saved); err != nil {
		return api.PlanCleanupClaim{}, err
	}
	return claim, nil
}

func (s *Service) currentPlanCleanup(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) (storedPlanCleanup, error) {
	var saved storedPlanCleanup
	if err := s.cleanupCoordinator(ctx, scope); err != nil {
		return saved, err
	}
	if err := storedProjection(ctx, s.db, "plan_cleanup", claim.Request.ID, &saved); err != nil {
		return saved, err
	}
	if err := s.cleanupState(saved, claim.Request.ID); err != nil {
		return saved, err
	}
	if saved.State != "claimed" || saved.Attempt == nil || !sameValue(*saved.Attempt, claim) || claim.ClaimantID != scope.Actor.ID || !future(claim.ExpiresAt, s.deps.Clock.Now()) {
		return saved, fault(api.CodeConflict, "cleanup execution lost its actual current durable claim")
	}
	_, err := s.cleanupOrigin(ctx, s.db, saved)
	return saved, err
}

func (s *Service) CheckPlanCleanupClaim(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := s.currentPlanCleanup(ctx, scope, claim)
	return err
}

func (s *Service) cleanupAllocation(ctx context.Context, db queryer, job api.PlanCleanup) (api.HelperLease, error) {
	var count int
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT count(*),coalesce(min(data),'') FROM effect_states WHERE json_extract(data,'$.Effect.HelperAllocate.reservation_id')=?", string(job.ReservationID)).Scan(&count, &raw); err != nil {
		return api.HelperLease{}, err
	}
	if count != 1 {
		return api.HelperLease{}, fault(api.CodeContainmentUnknown, "cleanup requires one original measured helper allocation")
	}
	var record api.EffectRecord
	if err := decodeStored(raw, &record); err != nil {
		return api.HelperLease{}, err
	}
	if validateEffectState(record) != nil || record.Effect.Context == nil || record.Effect.Context.Target != job.Cause.Target ||
		record.Effect.OperationID != job.Cause.CauseOperationID || record.State != api.EffectCompleted || record.Outcome == nil || record.Outcome.HelperLease == nil {
		return api.HelperLease{}, fault(api.CodeContainmentUnknown, "cleanup allocation has an unacknowledged or foreign outcome")
	}
	return *record.Outcome.HelperLease, nil
}

func (s *Service) PlanCleanupAllocation(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) (api.HelperLease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := s.currentPlanCleanup(ctx, scope, claim)
	if err != nil {
		return api.HelperLease{}, err
	}
	return s.cleanupAllocation(ctx, s.db, saved.Request)
}

func (s *Service) RecordPlanCleanupRefusal(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, refusal *api.Error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.currentPlanCleanup(ctx, scope, claim)
	if err != nil {
		return err
	}
	if refusal == nil || refusal.Code == "" || refusal.Owner == "" {
		return fault(api.CodeInvalid, "cleanup refusal requires its complete owning error")
	}
	raw, err := json.Marshal(refusal)
	if err != nil || len(raw) > api.MaxFrameBytes {
		return fault(api.CodeInvalid, "cleanup refusal exceeds its metadata bound")
	}
	if err := decodeStored(raw, &saved.Refusal); err != nil {
		return err
	}
	saved.Generation++
	saved.State, saved.Attempt = "pending", nil
	return s.savePlanCleanup(ctx, saved)
}

func (s *Service) validateCleanupReceipt(ctx context.Context, db queryer, job api.PlanCleanup, receipt api.PlanCleanupReceipt) error {
	if !wire.ValidID(string(receipt.ID)) || receipt.CleanupID != job.ID || receipt.ReservationID != job.ReservationID ||
		receipt.LaunchID != job.LaunchID || receipt.Kind != job.Kind || !job.SlotKnown || receipt.SlotID != job.Slot.ID ||
		(receipt.Release == nil) == (receipt.Abort == nil) {
		return fault(api.CodeIntegrity, "cleanup completion lacks exact broker and native selectors")
	}
	completed, err := time.Parse(time.RFC3339Nano, string(receipt.CompletedAt))
	if err != nil || completed.IsZero() || completed.After(s.deps.Clock.Now()) {
		return fault(api.CodeIntegrity, "cleanup completion has no measured terminal time")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", job.ReservationID, &plan); err != nil {
		return err
	}
	allocation, err := s.cleanupAllocation(ctx, db, job)
	if err != nil {
		return err
	}
	if receipt.Allocation != allocation || plan.Plan != nil && receipt.Allocation != plan.Plan.Lease {
		return fault(api.CodeContainmentUnknown, "cleanup completion requires the original measured helper allocation")
	}
	var observation api.ProcessObservation
	var nativeID api.ID
	if receipt.Release != nil {
		r := receipt.Release
		if err := api.ValidateReleaseReceipt(*r); err != nil {
			return err
		}
		expectedEffect := job.ID
		if job.Kind == "revoke_injection" {
			expectedEffect = cleanupObjectID(job.ReservationID, "cleanup-release")
		}
		if r.LeaseID != receipt.Allocation.ID || r.ContainmentID != receipt.Allocation.ContainmentID || r.OperationID != job.Cause.CauseOperationID ||
			r.EffectID != expectedEffect || r.Quiescence.Handle.ID != job.LaunchID || r.Quiescence.Handle.Generation == "" || r.ObservedAt != r.Quiescence.ObservedAt ||
			(r.Quiescence.ExitCode == nil) == (r.Quiescence.Signal == nil) {
			return fault(api.CodeIntegrity, "cleanup release changed its native lease or operation")
		}
		observation = r.Quiescence
		nativeID = r.ID
	} else {
		r := receipt.Abort
		if !wire.ValidID(string(r.ID)) || r.LeaseID != receipt.Allocation.ID || r.AgentExecuted || r.ObservedAt != r.Quiescence.ObservedAt ||
			r.Quiescence.State != "not_started" || r.Quiescence.Handle.ID != "" || r.Quiescence.Handle.Generation != "" ||
			r.Quiescence.ExitCode != nil || r.Quiescence.Signal != nil || r.Quiescence.PromptStatus != "not_written" ||
			job.Prepared != nil && r.PreparedID != job.Prepared.ID {
			return fault(api.CodeContainmentUnknown, "cleanup abort lacks original nonexecuting quiescence")
		}
		observation = r.Quiescence
		nativeID = r.ID
	}
	observed, err := time.Parse(time.RFC3339Nano, string(observation.ObservedAt))
	if err != nil || observed.IsZero() || observed.After(completed) || observation.Handle.Target != job.Cause.Target ||
		observation.Handle.ContainmentID != receipt.Allocation.ContainmentID || observation.Survivors == nil || *observation.Survivors != 0 {
		return fault(api.CodeContainmentUnknown, "cleanup completion has unknown or foreign native survivors")
	}
	if job.Kind == "withdraw" {
		p := receipt.Withdrawal
		if p == nil || p.State != "withdrawn" || p.Withdrawal == nil || p.Fence == nil || job.Withdrawal == nil || job.Prepared == nil ||
			!sameValue(*p.Fence, *job.Withdrawal) || p.Authority.ID != job.Withdrawal.ProjectionID ||
			p.Authority.Request.Prepared != *job.Prepared {
			return fault(api.CodeContainmentUnknown, "cleanup projection has no original completed withdrawal")
		}
		actual, err := s.credentialByID(ctx, db, p.Authority.ID)
		if err != nil || !sameValue(actual.Record, *p) {
			return errors.Join(fault(api.CodeIntegrity, "cleanup withdrawal differs from its retained owner result"), err)
		}
		validation := *p
		validation.State, validation.Generation = "withdrawing", p.Generation-1
		if err := api.ValidateCredentialWithdrawal(validation, *p.Withdrawal); err != nil {
			return err
		}
	} else if receipt.Withdrawal != nil {
		return fault(api.CodeForbidden, "unprojected cleanup supplied a foreign withdrawal")
	}
	meta, raw, err := objectRow(ctx, db, receipt.Broker.ID)
	if err != nil {
		return err
	}
	if receipt.Broker.Class != "manifest" || meta.Ref != receipt.Broker || meta.Origin != "service" ||
		meta.SourceOperationID != job.Cause.CauseOperationID || meta.ACL.Config != job.Cause.Config ||
		meta.ACL.LifeID != job.Cause.Target.LifeID || meta.ACL.Owner.Kind != "service" {
		return fault(api.CodeIntegrity, "cleanup has no retained original broker acknowledgement")
	}
	var broker api.PlanCleanupBrokerReceipt
	if err := decodeStored(raw, &broker); err != nil {
		return err
	}
	projectionID := api.ID("")
	if receipt.Withdrawal != nil {
		projectionID = receipt.Withdrawal.Authority.ID
	}
	expected := api.PlanCleanupBrokerReceipt{CleanupID: job.ID, ReservationID: job.ReservationID, LaunchID: job.LaunchID,
		Kind: job.Kind, Slot: job.Slot, Injection: job.Injection, NativeReceiptID: nativeID, ProjectionID: projectionID, CompletedAt: receipt.CompletedAt}
	if !sameValue(broker, expected) {
		return fault(api.CodeIntegrity, "cleanup broker acknowledgement changed its original resource selectors")
	}
	if job.Kind == "revoke_injection" {
		var release storedPlanCleanup
		if err := storedProjection(ctx, db, "plan_cleanup", cleanupObjectID(job.ReservationID, "cleanup-release"), &release); err != nil {
			return err
		}
		if release.State != "completed" || release.Completion == nil || !sameValue(release.Completion.Release, receipt.Release) || !sameValue(release.Completion.Abort, receipt.Abort) {
			return fault(api.CodeIntegrity, "injection revocation changed its prerequisite release measurement")
		}
	}
	return nil
}

func (s *Service) CompletePlanCleanup(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, proposed api.PlanCleanupReceipt, executor api.PlanCleanupExecutor) (api.PlanCleanupReceipt, error) {
	// Owner I/O is outside the writer lock. Reacquire and recheck the live claim
	// after it returns, so a timeout/reclaim cannot publish a stale measurement.
	if err := s.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		status, readErr := s.PlanCleanupStatus(ctx, scope, claim.Request.ID)
		if readErr == nil && status.State == "completed" && status.Claim != nil && sameValue(*status.Claim, claim) &&
			claim.ClaimantID == scope.Actor.ID && status.Receipt != nil && sameValue(*status.Receipt, proposed) {
			return *status.Receipt, nil
		}
		return api.PlanCleanupReceipt{}, err
	}
	if executor == nil || reflect.ValueOf(executor).Kind() == reflect.Pointer && reflect.ValueOf(executor).IsNil() {
		return api.PlanCleanupReceipt{}, api.NotImplemented("lb-v2-secrets", "protected failed-plan cleanup journal read-back")
	}
	actual, err := executor.ReadPlanCleanupReceipt(ctx, scope, claim)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	if !sameValue(actual, proposed) {
		return api.PlanCleanupReceipt{}, fault(api.CodeIntegrity, "cleanup completion differs from independent resource-owner read-back")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.currentPlanCleanup(ctx, scope, claim)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	if err := s.validateCleanupReceipt(ctx, s.db, saved.Request, actual); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	saved.Generation++
	saved.State, saved.Completion = "completed", &actual
	if err := s.savePlanCleanup(ctx, saved); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	return actual, nil
}
