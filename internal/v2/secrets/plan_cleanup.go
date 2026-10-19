package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

var _ api.PlanCleanupExecutor = (*Service)(nil)

func cleanupStageID(reservation api.ID, stage string) api.ID {
	sum := sha256.Sum256([]byte("launch\x00" + string(reservation) + "\x00" + stage))
	return api.ID(hex.EncodeToString(sum[:]))
}

func freezeCleanup(claim api.PlanCleanupClaim) (api.PlanCleanupClaim, error) {
	raw, err := json.Marshal(claim)
	if err != nil || len(raw) > api.MaxFrameBytes {
		return api.PlanCleanupClaim{}, wire.Error(api.CodeInvalid, "cleanup claim exceeds its private metadata bound")
	}
	var frozen api.PlanCleanupClaim
	err = json.Unmarshal(raw, &frozen)
	return frozen, err
}

func (s *Service) cleanupAuthority(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) (api.PlanCleanupStore, api.HelperLease, error) {
	store, ok := s.deps.Store.(api.PlanCleanupStore)
	if !ok || wire.Nil(store) {
		return nil, api.HelperLease{}, api.NotImplemented("lb-v2-secrets", "live failed-plan cleanup authority")
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return nil, api.HelperLease{}, err
	}
	allocation, err := store.PlanCleanupAllocation(ctx, scope, claim)
	if err != nil {
		return nil, api.HelperLease{}, err
	}
	if wire.Nil(s.deps.Helper) || wire.Nil(s.deps.CleanupNative) {
		return nil, api.HelperLease{}, api.NotImplemented("lb-v2-admin", "installed failed-plan cleanup helper and journal read-back")
	}
	job := claim.Request
	if !job.SlotKnown || len(job.Issues) != 0 {
		for _, issue := range job.Issues {
			if issue != nil {
				return nil, api.HelperLease{}, issue
			}
		}
		return nil, api.HelperLease{}, wire.Error(api.CodeContainmentUnknown, "failed-plan cleanup retains an unknown original resource outcome")
	}
	for _, ref := range []*api.BlobRef{&job.SlotResult, job.InjectionIn, job.InjectionOut} {
		if ref != nil {
			if _, err := s.protectedObject(ctx, *ref, job.Cause.CauseOperationID, job.Cause.Target.LifeID); err != nil {
				return nil, api.HelperLease{}, err
			}
		}
	}
	return store, allocation, nil
}

func (s *Service) cleanupNativeEffect(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, allocation api.HelperLease) (api.EffectRecord, error) {
	job := claim.Request
	id := job.ID
	if job.Kind == "revoke_injection" {
		id = cleanupStageID(job.ReservationID, "cleanup-release")
	}
	current, err := s.deps.Store.Effect(ctx, scope, id)
	if err == nil {
		cause := current.Effect.Context
		if cause == nil || current.Effect.ID != id || cause.Config != job.Cause.Config || cause.Target != job.Cause.Target ||
			cause.CauseOperationID != job.Cause.CauseOperationID || cause.CauseRequestID != job.Cause.CauseRequestID || cause.RequestedBy != job.Cause.RequestedBy ||
			cause.CancellationEpoch != job.Cause.CancellationEpoch ||
			(current.Effect.HelperAbort == nil || current.Effect.HelperAbort.LeaseID != allocation.ID) &&
				(current.Effect.HelperRelease == nil || current.Effect.HelperRelease.LeaseID != allocation.ID) {
			return api.EffectRecord{}, wire.Error(api.CodeIntegrity, "cleanup native effect changed its original allocation or cause")
		}
		return current, nil
	}
	if !hasCode(err, api.CodeNotFound) || job.Kind == "revoke_injection" {
		return api.EffectRecord{}, err
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, scope, job.ReservationID)
	if err != nil {
		return api.EffectRecord{}, err
	}
	cause := job.Cause
	cause.Kind = api.InternalHelperAbort
	effect := api.Effect{ID: id, OperationID: cause.CauseOperationID}
	request := api.HelperAbortRequest{Cause: cause, LeaseID: allocation.ID, OperationID: cause.CauseOperationID, EffectID: id}
	if plan.Handoff != nil {
		request.SpecSHA256 = plan.Handoff.SpecSHA256
	}
	if job.Prepared != nil {
		request.PreparedID = job.Prepared.ID
		measured, err := s.deps.Helper.ReconcileGate(ctx, api.HelperReconcileRequest{LeaseID: allocation.ID, LaunchID: job.LaunchID, PreparedID: job.Prepared.ID, OperationID: cause.CauseOperationID})
		if err != nil {
			return api.EffectRecord{}, err
		}
		if measured.Prepared == nil || *measured.Prepared != *job.Prepared {
			return api.EffectRecord{}, wire.Error(api.CodeContainmentUnknown, "cleanup reconciliation replaced the original prepared gate")
		}
		if measured.ConsumedPermit != nil {
			if err := quiescent(ctx, measured.Observation, cause.Target); err != nil {
				return api.EffectRecord{}, err
			}
			if measured.Process == nil || *measured.Process != measured.Observation.Handle || measured.Process.ID != job.LaunchID {
				return api.EffectRecord{}, wire.Error(api.CodeContainmentUnknown, "executed cleanup has no original terminal process")
			}
			cause.Kind = api.InternalHelperRelease
			effect.HelperRelease = &api.HelperReleaseRequest{Cause: cause, LeaseID: allocation.ID, Observation: measured.Observation}
		} else if measured.GateState != "prepared" && measured.GateState != "aborted" {
			return api.EffectRecord{}, wire.Error(api.CodeContainmentUnknown, "unopened cleanup gate has an uncertain transition")
		}
	}
	if effect.HelperRelease == nil {
		effect.HelperAbort = &request
	}
	effect.Context = &cause
	emit := cause
	emit.ID = credentialID("cleanup-native-emission", job.ID)
	emitter := api.Scope{Config: scope.Config, Actor: cause.Actor, Source: "service"}
	if _, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: emitter, Internal: &emit, Effects: []api.Effect{effect},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: cause.Target.LifeID, Epoch: cause.CancellationEpoch}}}}); err != nil {
		return api.EffectRecord{}, err
	}
	return s.deps.Store.Effect(ctx, scope, id)
}

func (s *Service) executeCleanupNative(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, record api.EffectRecord) (api.EffectOutcome, error) {
	store := s.deps.Store.(api.PlanCleanupStore)
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.EffectOutcome{}, err
	}
	if record.Outcome != nil {
		actual, err := s.deps.CleanupNative.ReadPlanCleanupNative(ctx, scope, claim, record.Effect)
		if err != nil {
			return api.EffectOutcome{}, err
		}
		if record.State != api.EffectCompleted || record.Outcome.Status != "succeeded" || !reflect.DeepEqual(record.Outcome.Abort, actual.Abort) || !reflect.DeepEqual(record.Outcome.Release, actual.Release) {
			return api.EffectOutcome{}, wire.Error(api.CodeIntegrity, "completed native cleanup differs from its independently retained journal")
		}
		return actual, nil
	}
	var lease api.EffectLease
	if record.State == api.EffectClaimed && future(record.ClaimExpiresAt, s.deps.Clock.Now()) {
		if record.ClaimantID != scope.Actor.ID {
			return api.EffectOutcome{}, wire.Error(api.CodeConflict, "native cleanup has another live claimant")
		}
		lease = api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
	} else {
		var err error
		lease, err = s.deps.Store.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: record.Effect.ID, ExpectedGeneration: record.Generation, ClaimantID: scope.Actor.ID, Deadline: claim.ExpiresAt})
		if err != nil {
			return api.EffectOutcome{}, err
		}
	}
	ctx = api.WithEffectLease(api.WithPlanCleanupClaim(ctx, claim), lease)
	if claim.Request.Kind == "withdraw" {
		if err := s.cleanupWithdrawal(ctx, scope, claim); err != nil {
			return api.EffectOutcome{}, err
		}
	}
	outcome := api.EffectOutcome{EffectID: record.Effect.ID, Status: "succeeded"}
	if record.Effect.HelperAbort != nil {
		receipt, err := s.deps.Helper.AbortGate(ctx, *record.Effect.HelperAbort)
		if err != nil {
			return api.EffectOutcome{}, err
		}
		outcome.Abort = &receipt
	} else {
		receipt, err := s.deps.Helper.Release(ctx, *record.Effect.HelperRelease)
		if err != nil {
			return api.EffectOutcome{}, err
		}
		outcome.Release = &receipt
	}
	actual, err := s.deps.CleanupNative.ReadPlanCleanupNative(ctx, scope, claim, record.Effect)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if !reflect.DeepEqual(actual, outcome) {
		return api.EffectOutcome{}, wire.Error(api.CodeIntegrity, "native cleanup reply differs from independent helper journal read-back")
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.EffectOutcome{}, err
	}
	outcome.ClaimID, outcome.ExpectedGeneration = lease.ClaimID, lease.Record.Generation
	if _, err := s.deps.Store.CompleteEffect(ctx, scope, outcome); err != nil {
		return api.EffectOutcome{}, err
	}
	return actual, nil
}

func (s *Service) cleanupWithdrawal(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim) error {
	job := claim.Request
	if job.Withdrawal == nil || job.Prepared == nil {
		return wire.Error(api.CodeContainmentUnknown, "failed-plan withdrawal has no original projection selector")
	}
	journal, record, err := s.projectionLookup(ctx, job.Withdrawal.ProjectionID)
	if err != nil {
		return err
	}
	allocation, err := s.deps.Store.(api.PlanCleanupStore).PlanCleanupAllocation(ctx, scope, claim)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(record.Authority.Request.Prepared, *job.Prepared) || record.Authority.Request.Lease != allocation {
		return wire.Error(api.CodeForbidden, "cleanup projection differs from the original helper allocation")
	}
	if record.State == "withdrawn" {
		if !journal.Fenced || !journal.Released || record.Fence == nil || !reflect.DeepEqual(*record.Fence, *job.Withdrawal) || record.Withdrawal == nil {
			return wire.Error(api.CodeIntegrity, "withdrawal retry lost its original terminal fence")
		}
		return nil
	}
	store := s.deps.Store.(api.PlanCleanupStore)
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return err
	}
	fenced, err := s.BeginCredentialWithdrawal(ctx, *job.Withdrawal)
	if err != nil {
		return err
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return err
	}
	if fenced.State != "withdrawing" || fenced.Fence == nil || !reflect.DeepEqual(*fenced.Fence, *job.Withdrawal) {
		return wire.Error(api.CodeIntegrity, "cleanup projection did not retain its exact withdrawal fence")
	}
	// The retained native abort/release performs withdrawal and calls the
	// broker's existing Finish port before collecting the helper allocation.
	return nil
}

func cleanupSlotIDs(job api.PlanCleanup) ([]api.ID, error) {
	ids := []api.ID{job.Slot.ID}
	if job.Kind != "release" && job.Injection != nil {
		ids = append([]api.ID{}, job.Injection.SlotIDs...)
	}
	if len(ids) == 0 || len(ids) > 257 || !slices.Contains(ids, job.Slot.ID) {
		return nil, wire.Error(api.CodeIntegrity, "cleanup lost its original complete slot inventory")
	}
	seen := map[api.ID]bool{}
	for _, id := range ids {
		if !wire.ID(string(id)) || seen[id] {
			return nil, wire.Error(api.CodeIntegrity, "cleanup slot inventory is invalid or duplicated")
		}
		seen[id] = true
	}
	return ids, nil
}

func (s *Service) cleanupSlots(ctx context.Context, j bstate.Journal, job api.PlanCleanup, allocation api.HelperLease, release bool) (resultErr error) {
	ids, err := cleanupSlotIDs(job)
	if err != nil {
		return err
	}
	slots := []bstate.Slot{}
	defer func() { clearProjectionSlots(slots) }()
	for _, id := range ids {
		var slot bstate.Slot
		if err := j.Read("slot", id, &slot); err != nil {
			return err
		}
		slots = append(slots, slot)
		if slot.Config != job.Cause.Config || slot.Target != job.Cause.Target || slot.ReservationID != job.ReservationID || slot.LaunchID != job.LaunchID ||
			slot.OperationID != job.Cause.CauseOperationID || slot.RequestID != job.Cause.CauseRequestID || slot.RequestedBy != job.Cause.RequestedBy ||
			slot.HelperLeaseID != allocation.ID || !wire.Digest(slot.Fingerprint) || id == job.Slot.ID && (slot.Kind != "profile" || slot.Credential != job.Slot) {
			return wire.Error(api.CodeForbidden, "cleanup broker slot differs from its immutable reservation and allocation")
		}
		if job.Kind == "withdraw" {
			if job.Withdrawal == nil || slot.ProjectionID != job.Withdrawal.ProjectionID || !slot.Released {
				return wire.Error(api.CodeContainmentUnknown, "projected cleanup requires completed original withdrawal tombstones")
			}
		} else if slot.ProjectionID != "" {
			return wire.Error(api.CodeForbidden, "unprojected cleanup cannot collect a projected slot")
		}
		if !release && (!slot.Released || len(slot.Material)+len(slot.Returned) != 0) {
			return wire.Error(api.CodeIntegrity, "cleanup broker tombstone is absent or still contains material")
		}
		if !release && (slot.Credential.Mode == "codex-file" || slot.Credential.Mode == "file_login") {
			var owner bstate.Login
			if err := j.Read("login", slot.LoginID, &owner); err != nil {
				return err
			}
			clear(owner.Material)
			if owner.SlotID == slot.ID || owner.PendingRelease == slot.ID {
				return wire.Error(api.CodeIntegrity, "cleanup canonical credential ownership is still retained")
			}
		}
	}
	if !release || job.Kind == "withdraw" {
		return nil
	}
	// Validate the complete selection before writing any tombstone. Canonical
	// ownership is freed only after the exact slot's material is durably gone.
	leases := []bstate.RefreshLease{}
	defer func() {
		for _, lease := range leases {
			resultErr = errors.Join(resultErr, lease.Close())
		}
	}()
	for _, slot := range slots {
		if slot.Credential.Mode == "codex-file" || slot.Credential.Mode == "file_login" {
			var owner bstate.Login
			if err := j.Read("login", slot.LoginID, &owner); err != nil {
				return err
			}
			clear(owner.Material)
			if owner.ID != slot.LoginID || owner.Quarantined || !slot.Released && owner.SlotID != slot.ID || owner.PendingRelease != "" && owner.PendingRelease != slot.ID || owner.ProjectionID != "" {
				return wire.Error(api.CodeConflict, "unopened cleanup has another canonical credential owner")
			}
			if len(slot.Returned) != 0 {
				return wire.Error(api.CodeContainmentUnknown, "unopened slot contains unexpected refresh material")
			}
			if !slot.Released && slot.Credential.Mode == "codex-file" {
				lease, err := j.AcquireRefreshLease(slot.LoginID)
				if err != nil {
					return err
				}
				if wire.Nil(lease) {
					return wire.Error(api.CodeContainmentUnknown, "unopened cleanup has no measured canonical refresh exclusion")
				}
				leases = append(leases, lease)
				if err := lease.Check(); err != nil {
					return err
				}
			}
		}
	}
	for _, slot := range slots {
		var owner bstate.Login
		canonical := slot.Credential.Mode == "codex-file" || slot.Credential.Mode == "file_login"
		if canonical {
			if err := j.Read("login", slot.LoginID, &owner); err != nil {
				return err
			}
			defer clear(owner.Material)
			if slot.Released {
				if owner.SlotID == slot.ID || owner.PendingRelease == slot.ID {
					if owner.SlotID != "" && owner.SlotID != slot.ID {
						return wire.Error(api.CodeConflict, "cleanup canonical pending owner changed")
					}
					owner.SlotID, owner.PendingRelease = "", ""
					if err := j.Write("login", owner.ID, owner); err != nil {
						return err
					}
				}
				continue
			}
			owner.PendingRelease = slot.ID
			if err := j.Write("login", owner.ID, owner); err != nil {
				return err
			}
		}
		if slot.Released {
			continue
		}
		clear(slot.Material)
		clear(slot.Returned)
		slot.Material, slot.Returned, slot.Released = []byte{}, []byte{}, true
		if err := j.Write("slot", slot.ID, slot); err != nil {
			return err
		}
		if canonical {
			owner.SlotID, owner.PendingRelease = "", ""
			if err := j.Write("login", owner.ID, owner); err != nil {
				return err
			}
		}
	}
	return nil
}

func cleanupBrokerAck(job api.PlanCleanup, receipt api.PlanCleanupReceipt) api.PlanCleanupBrokerReceipt {
	var nativeID, projectionID api.ID
	if receipt.Abort != nil {
		nativeID = receipt.Abort.ID
	}
	if receipt.Release != nil {
		nativeID = receipt.Release.ID
	}
	if receipt.Withdrawal != nil {
		projectionID = receipt.Withdrawal.Authority.ID
	}
	return api.PlanCleanupBrokerReceipt{CleanupID: job.ID, ReservationID: job.ReservationID, LaunchID: job.LaunchID, Kind: job.Kind,
		Slot: job.Slot, Injection: job.Injection, NativeReceiptID: nativeID, ProjectionID: projectionID, CompletedAt: receipt.CompletedAt}
}

func (s *Service) ExecutePlanCleanup(ctx context.Context, scope api.Scope, supplied api.PlanCleanupClaim) (api.PlanCleanupReceipt, error) {
	claim, err := freezeCleanup(supplied)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	store, allocation, err := s.cleanupAuthority(ctx, scope, claim)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	job := claim.Request
	var saved bstate.PlanCleanup
	err = backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("plan_cleanup", job.ID, &saved) })
	if err == nil {
		if !reflect.DeepEqual(saved.Request, job) || saved.Receipt.Allocation != allocation {
			return api.PlanCleanupReceipt{}, wire.Error(api.CodeIntegrity, "cleanup retry changed its original resource-owner journal")
		}
		if saved.Receipt.Broker.ID != "" {
			return s.ReadPlanCleanupReceipt(ctx, scope, claim)
		}
	} else if !hasCode(err, api.CodeNotFound) {
		return api.PlanCleanupReceipt{}, err
	}
	record, err := s.cleanupNativeEffect(ctx, scope, claim, allocation)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	outcome, err := s.executeCleanupNative(ctx, scope, claim, record)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	if job.Kind == "revoke_injection" {
		prior, err := store.PlanCleanupStatus(ctx, scope, cleanupStageID(job.ReservationID, "cleanup-release"))
		if err != nil {
			return api.PlanCleanupReceipt{}, err
		}
		if prior.State != "completed" || prior.Receipt == nil || !reflect.DeepEqual(prior.Receipt.Abort, outcome.Abort) || !reflect.DeepEqual(prior.Receipt.Release, outcome.Release) {
			return api.PlanCleanupReceipt{}, wire.Error(api.CodeIntegrity, "injection revocation replaced its prerequisite release")
		}
	}
	if saved.Receipt.ID == "" {
		saved = bstate.PlanCleanup{Request: job, Effect: record.Effect, Receipt: api.PlanCleanupReceipt{ID: credentialID("cleanup-owner-receipt", job.ID), CleanupID: job.ID, ReservationID: job.ReservationID,
			LaunchID: job.LaunchID, Kind: job.Kind, SlotID: job.Slot.ID, Allocation: allocation, Abort: outcome.Abort, Release: outcome.Release, CompletedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))}}
		if job.Kind == "withdraw" {
			_, withdrawn, err := s.projectionLookup(ctx, job.Withdrawal.ProjectionID)
			if err != nil {
				return api.PlanCleanupReceipt{}, err
			}
			saved.Receipt.Withdrawal = &withdrawn
		}
		if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("plan_cleanup", job.ID, saved) }); err != nil {
			return api.PlanCleanupReceipt{}, err
		}
	} else if !reflect.DeepEqual(saved.Effect, record.Effect) || !reflect.DeepEqual(saved.Receipt.Abort, outcome.Abort) || !reflect.DeepEqual(saved.Receipt.Release, outcome.Release) {
		return api.PlanCleanupReceipt{}, wire.Error(api.CodeIntegrity, "cleanup native replay changed its retained measurement")
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error {
		if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
			return err
		}
		if err := s.cleanupSlots(ctx, j, job, allocation, true); err != nil {
			return err
		}
		return s.cleanupSlots(ctx, j, job, allocation, false)
	}); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	ack := cleanupBrokerAck(job, saved.Receipt)
	raw, err := json.Marshal(ack)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	sum := sha256.Sum256(raw)
	digest := api.Digest(hex.EncodeToString(sum[:]))
	cause := job.Cause
	cause.Kind, cause.ID, cause.Actor = api.InternalObjectRetain, credentialID("cleanup-broker-ack", job.ID), s.deps.ServiceScope.Actor
	ref, err := s.deps.Store.RetainObject(ctx, s.deps.ServiceScope, api.RetainObjectRequest{Intent: cause,
		Object: api.ObjectWrite{ObjectKey: credentialID("cleanup-broker-ack", job.ID), Class: "manifest", Bytes: raw, SHA256: digest, Origin: "service",
			ACL: api.ObjectACL{Config: job.Cause.Config, Owner: s.deps.ServiceScope.Actor, LifeID: job.Cause.Target.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	saved.Receipt.Broker = ref
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("plan_cleanup", job.ID, saved) }); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	return s.ReadPlanCleanupReceipt(ctx, scope, claim)
}

func (s *Service) ReadPlanCleanupReceipt(ctx context.Context, scope api.Scope, supplied api.PlanCleanupClaim) (api.PlanCleanupReceipt, error) {
	claim, err := freezeCleanup(supplied)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	store, allocation, err := s.cleanupAuthority(ctx, scope, claim)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	var saved bstate.PlanCleanup
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error {
		if err := j.Read("plan_cleanup", claim.Request.ID, &saved); err != nil {
			return err
		}
		if !reflect.DeepEqual(saved.Request, claim.Request) || saved.Receipt.Allocation != allocation || saved.Receipt.Broker.ID == "" {
			return wire.Error(api.CodeIntegrity, "cleanup has no exact completed resource-owner journal")
		}
		return s.cleanupSlots(ctx, j, claim.Request, allocation, false)
	}); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	actual, err := s.deps.CleanupNative.ReadPlanCleanupNative(ctx, scope, claim, saved.Effect)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	if !reflect.DeepEqual(actual.Abort, saved.Receipt.Abort) || !reflect.DeepEqual(actual.Release, saved.Receipt.Release) {
		return api.PlanCleanupReceipt{}, wire.Error(api.CodeIntegrity, "cleanup receipt changed its original helper journal")
	}
	if saved.Receipt.Withdrawal != nil {
		journal, current, err := s.projectionLookup(ctx, saved.Receipt.Withdrawal.Authority.ID)
		if err != nil {
			return api.PlanCleanupReceipt{}, err
		}
		if !journal.Fenced || !journal.Released || current.State != "withdrawn" || !reflect.DeepEqual(current, *saved.Receipt.Withdrawal) {
			return api.PlanCleanupReceipt{}, wire.Error(api.CodeIntegrity, "cleanup read-back lost the completed original withdrawal")
		}
	}
	raw, err := s.protectedObject(ctx, saved.Receipt.Broker, claim.Request.Cause.CauseOperationID, claim.Request.Cause.Target.LifeID)
	if err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	var ack api.PlanCleanupBrokerReceipt
	if err := json.Unmarshal(raw, &ack); err != nil || !reflect.DeepEqual(ack, cleanupBrokerAck(claim.Request, saved.Receipt)) {
		return api.PlanCleanupReceipt{}, wire.Error(api.CodeIntegrity, "cleanup broker acknowledgement differs from independent journal read-back")
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.PlanCleanupReceipt{}, err
	}
	return saved.Receipt, nil
}
