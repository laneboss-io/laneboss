package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type launchInput struct {
	request      api.Request
	task         api.BlobRef
	message      *api.BlobRef
	budget       api.Budget
	role         api.RoleContext
	driver       api.Driver
	profile      api.ID
	model        string
	effort       string
	mail         []api.ID
	previous     *api.LaunchBindingRequest
	previousPlan *api.LaunchPlan
	slot         *api.CredentialSlot
	turn         api.ID
}

type planExecution struct {
	service *Service
	scope   api.Scope
	lease   api.EffectLease
	record  api.LaunchPlanRecord
	input   launchInput
}

func launchObjectID(reservation api.ID, stage string) api.ID {
	return api.ID(digestOfBytes([]byte("launch\x00" + string(reservation) + "\x00" + stage)))
}

func digestOfBytes(data []byte) api.Digest {
	// Keep production hashing separate from dependency fixtures.
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func (execution *planExecution) checkClaim(ctx context.Context) error {
	s, scope, lease := execution.service, execution.scope, execution.lease
	if scope.Actor.Kind != "service" || !validID(scope.Actor.ID) || scope.Request.Method != "" ||
		!validID(lease.Record.Effect.ID) || !validID(lease.ClaimID) {
		return problem(api.CodeForbidden, "launch planning requires the installed service claim",
			"Use the service outbox's current original PlanLaunch effect.")
	}
	current, err := s.deps.Store.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return failure(err)
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, string(current.ClaimExpiresAt))
	if effectRecord(current) != nil || !api.EffectLeaseClaimed(lease) || current.State != api.EffectClaimed || current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID ||
		lease.Record.State != current.State || current.Outcome != nil || lease.Record.Outcome != nil ||
		current.Generation != lease.Record.Generation || current.ClaimExpiresAt != lease.ExpiresAt ||
		lease.Record.ClaimID != lease.ClaimID || lease.Record.ClaimantID != current.ClaimantID || lease.Record.ClaimExpiresAt != lease.ExpiresAt ||
		parseErr != nil || !s.deps.Clock.Now().Before(expires) || !reflect.DeepEqual(current.Effect, lease.Record.Effect) {
		return problem(api.CodeConflict, "launch planning claim is stale or foreign",
			"Reconcile and claim the same durable effect; do not start a replacement.")
	}
	effect := current.Effect
	// Context retains the original service author. ClaimantID, ClaimID,
	// generation, expiry and exact durable effect equality above authenticate
	// this attempt; the author must not be rewritten for each fresh claimant.
	if effect.PlanLaunch == nil || effect.Context == nil || effect.Context.Kind != api.InternalLaunchPlan ||
		effect.Context.Actor.Kind != "service" || !validID(effect.Context.Actor.ID) ||
		effect.Context.Config != scope.Config || effect.Context.EffectID != effect.ID ||
		effect.Context.CauseOperationID != effect.OperationID {
		return integrity("planning effect has no exact launch cause")
	}
	if execution.record.Reservation.ID != "" {
		r := execution.record.Reservation
		cause := effect.Context
		if effect.PlanLaunch.ReservationID != r.ID || effect.OperationID != r.OperationID ||
			cause.Target != r.Target || cause.CauseRequestID != r.RequestID || cause.RequestedBy != r.RequestedBy ||
			cause.CancellationEpoch != r.CancellationEpoch || r.Config != scope.Config ||
			r.Loop != nil && (cause.LogicalTurnID != r.Loop.LogicalTurnID || effect.ID != r.Loop.PlanEffectID) {
			return integrity("planning claim selects a foreign reservation")
		}
	}
	return nil
}

func (execution *planExecution) cause(kind api.InternalKind, stage string) api.InternalIntent {
	r := execution.record.Reservation
	return api.InternalIntent{ID: launchObjectID(r.ID, "cause-"+stage), Kind: kind, Config: r.Config,
		Actor: execution.lease.Record.Effect.Context.Actor, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID,
		CauseRequestID: r.RequestID, EffectID: execution.lease.Record.Effect.ID,
		Target: r.Target, LogicalTurnID: execution.input.turn, CancellationEpoch: r.CancellationEpoch}
}

// writeCause authenticates this attempt; immutable stage DTOs keep cause's
// original author so reclaiming an effect does not change their bytes.
func (execution *planExecution) writeCause(kind api.InternalKind, stage string) api.InternalIntent {
	cause := execution.cause(kind, stage)
	cause.Actor = execution.scope.Actor
	cause.ID = launchObjectID(execution.record.Reservation.ID, "attempt-"+string(execution.lease.ClaimID)+"-"+stage)
	return cause
}

func (execution *planExecution) currentPolicy(ctx context.Context) error {
	if execution.record.Phase != "opened" {
		if err := execution.starter(ctx); err != nil {
			return err
		}
	}
	policy, err := execution.service.deps.Store.Policy(ctx, execution.scope)
	if err != nil {
		return failure(err)
	}
	if execution.scope.PolicyGeneration != policy.Generation {
		return problem(api.CodeConflict, "launch control scope is stale", "Reauthenticate current control rights before planning or reconciling the retained launch.")
	}
	if execution.record.Phase == "opened" {
		generation, err := api.PolicyGenerationFor(api.PolicyExactReplay, policy.Generation, execution.record.Reservation.PolicyGeneration)
		if err != nil {
			return failure(err)
		}
		retained, err := execution.service.deps.Store.PolicyAt(ctx, execution.scope, generation)
		if err != nil {
			return failure(err)
		}
		if retained.Generation != generation {
			return integrity("opened launch policy history changed its generation")
		}
		return nil
	}
	if execution.record.Inputs != nil {
		return failure(api.ValidateLaunchPolicyCurrent(execution.record.Reservation, execution.record.Inputs.Grants, policy))
	}
	generation, err := api.PolicyGenerationFor(api.PolicyNewLaunch, policy.Generation, 0)
	if err != nil {
		return failure(err)
	}
	if generation != execution.record.Reservation.PolicyGeneration {
		return problem(api.CodeConflict, "reserved launch policy is no longer current",
			"Retain the reservation and resolve the changed policy before release.")
	}
	return nil
}

func (execution *planExecution) retain(ctx context.Context, stage, class string, value any) (api.BlobRef, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return api.BlobRef{}, integrity("cannot encode retained launch input")
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return api.BlobRef{}, failure(err)
	}
	return execution.retainBytes(ctx, stage, class, canonical)
}

func (execution *planExecution) retainBytes(ctx context.Context, stage, class string, data []byte) (api.BlobRef, error) {
	if err := execution.checkClaim(ctx); err != nil {
		return api.BlobRef{}, err
	}
	if err := execution.currentPolicy(ctx); err != nil {
		return api.BlobRef{}, err
	}
	r := execution.record.Reservation
	cause := execution.writeCause(api.InternalLaunchPlan, stage)
	// Object ownership belongs to the immutable planning author, while the
	// store independently checks this attempt's current execution claimant.
	owner := execution.lease.Record.Effect.Context.Actor
	ref, err := execution.service.deps.Store.RetainObject(ctx, execution.scope, api.RetainObjectRequest{
		Intent: cause, Object: api.ObjectWrite{ObjectKey: launchObjectID(r.ID, stage), Class: class,
			Bytes: append([]byte{}, data...), SHA256: digestOfBytes(data), Origin: "service",
			ACL: api.ObjectACL{Config: r.Config, Owner: owner, LifeID: r.Target.LifeID,
				Audience: "owner", Generation: 1}}})
	if err != nil {
		return api.BlobRef{}, failure(err)
	}
	if !validBlob(ref) || ref.ID != launchObjectID(r.ID, stage) || ref.Class != class || ref.Bytes != int64(len(data)) || ref.SHA256 != digestOfBytes(data) {
		return api.BlobRef{}, integrity("retained launch bytes differ from their object receipt")
	}
	read, err := execution.service.readBlob(ctx, execution.scope, ref)
	if err != nil {
		return api.BlobRef{}, err
	}
	if !bytes.Equal(read, data) {
		return api.BlobRef{}, integrity("launch object failed exact read-back")
	}
	return ref, nil
}

func (execution *planExecution) event(kind api.EventKind, value any) (api.Event, error) {
	r := execution.record.Reservation
	lane := api.Lane{LifeID: r.Target.LifeID, Run: r.Target.Run, RootLifeID: r.RootLifeID,
		ParentLifeID: r.ParentLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq,
		LogicalTurnID: execution.input.turn}
	scope := execution.scope
	// The envelope carries the durable requester; the actor remains the real
	// authenticated service executing this internal effect.
	event, err := execution.service.event(scope, lane, kind, value, scope.Actor)
	if err != nil {
		return api.Event{}, err
	}
	event.OperationID, event.RequestID, event.RequestedBy = r.OperationID, r.RequestID, r.RequestedBy
	return event, nil
}

func (execution *planExecution) transact(ctx context.Context, writes api.StateWrites, effects []api.Effect,
	events []api.Event, compares []api.Compare) error {
	if err := execution.checkClaim(ctx); err != nil {
		return err
	}
	if err := execution.currentPolicy(ctx); err != nil {
		return err
	}
	r := execution.record.Reservation
	// One reservation performs several distinct writes. Give each exact
	// transition its own stable intent identity; the store's replay digest
	// must continue to reject different content under the same intent ID.
	content, err := json.Marshal(struct {
		Writes  api.StateWrites
		Effects []api.Effect
		Events  []api.Event
		Compare []api.Compare
	}{writes, effects, events, compares})
	if err != nil {
		return integrity("cannot encode launch transition identity")
	}
	cause := execution.writeCause(api.InternalLaunchPlan, "write-"+string(digestOfBytes(content)))
	_, err = execution.service.deps.Store.Transact(ctx, api.Transaction{Scope: execution.scope,
		Internal: &cause, Writes: writes, Effects: effects, Events: events, Compare: compares,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}})
	api.ObserveHelperReason(ctx, err, api.HelperReason(err))
	return failure(err)
}

func (execution *planExecution) save(ctx context.Context, next api.LaunchPlanRecord, events ...api.Event) error {
	if execution.record.Generation >= api.Generation(maxInteger) {
		return integrity("launch plan revision exhausted")
	}
	next.Generation = execution.record.Generation + 1
	if err := api.ValidateLaunchPlanRecord(next); err != nil {
		return failure(err)
	}
	if err := execution.transact(ctx, api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}}, nil, events,
		[]api.Compare{{Kind: api.CompareLaunchPlan, ID: next.Reservation.ID, Generation: execution.record.Generation}}); err != nil {
		return err
	}
	retained, err := execution.service.deps.Store.LaunchPlan(ctx, execution.scope, next.Reservation.ID)
	if err != nil {
		return failure(err)
	}
	if !reflect.DeepEqual(retained, next) {
		return integrity("launch plan write did not retain its exact revision")
	}
	execution.record = retained
	return nil
}

func notFound(err error) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed != nil && typed.Code == api.CodeNotFound
}
