package api

import (
	"context"
	"time"
)

// LaunchClaim selects one authenticated planning attempt. It is an in-process
// selector, never authority: every consumer reloads Effect before using it.
type LaunchClaim struct {
	ReservationID ID
	EffectID      ID
	ClaimID       ID
	ClaimantID    ID
	Generation    Generation
}

func PlanningClaim(reservation ID, lease EffectLease) LaunchClaim {
	return LaunchClaim{ReservationID: reservation, EffectID: lease.Record.Effect.ID,
		ClaimID: lease.ClaimID, ClaimantID: lease.Record.ClaimantID, Generation: lease.Record.Generation}
}

// StablePlanningPin retains identity, never attempt ownership. A new claimant
// of this same effect must authenticate a new live selector at the next call.
func StablePlanningPin(reservation, effect ID) LaunchClaim {
	return LaunchClaim{ReservationID: reservation, EffectID: effect}
}

// ReloadPlanningClaim is for an installed continuation holding a retained
// stable pin. Callers receiving an explicit selector must verify that selector
// unchanged; they must not replace a stale supplied claim with this result.
func ReloadPlanningClaim(ctx context.Context, store StateStore, scope Scope, reservation, effect ID, now time.Time) (LaunchClaim, error) {
	current, err := store.Effect(ctx, scope, effect)
	if err != nil {
		return LaunchClaim{}, err
	}
	claim := PlanningClaim(reservation, EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt})
	if err := CheckPlanningClaim(current, claim, scope.Config, now); err != nil {
		return LaunchClaim{}, err
	}
	return claim, nil
}

// CheckPlanningClaim checks a freshly reloaded durable record, never a record
// supplied with the selector. The immutable author may differ from claimant.
func CheckPlanningClaim(current EffectRecord, claim LaunchClaim, config string, now time.Time) error {
	e := current.Effect
	expires, err := time.Parse(time.RFC3339Nano, string(current.ClaimExpiresAt))
	if !launchID(claim.ReservationID) || !launchID(claim.EffectID) || !launchID(claim.ClaimID) || !launchID(claim.ClaimantID) ||
		!launchGeneration(claim.Generation) || current.State != EffectClaimed || current.Outcome != nil ||
		current.ClaimID != claim.ClaimID || current.ClaimantID != claim.ClaimantID || current.Generation != claim.Generation ||
		err != nil || !now.Before(expires) || e.ID != claim.EffectID || e.PlanLaunch == nil ||
		e.PlanLaunch.ReservationID != claim.ReservationID || e.Context == nil || e.Context.Kind != InternalLaunchPlan ||
		e.Context.Config != config || e.Context.Actor.Kind != "service" || !launchID(e.Context.Actor.ID) ||
		e.Context.EffectID != e.ID || e.Context.CauseOperationID != e.OperationID {
		return &Error{Code: CodeConflict, Owner: "lb-v2-lifecycle", Message: "launch planning claim is stale or foreign"}
	}
	return nil
}

type LaunchProfileRequest struct {
	Claim         LaunchClaim
	HelperLeaseID ID
	Target        LifeRef
	Grant         ProfileGrant
}

type LaunchInjectionRequest struct {
	Claim         LaunchClaim
	HelperLeaseID ID
	Target        LifeRef
	Grants        []SecretGrant
}

type LaunchCredentialBroker interface {
	AcquireLaunch(context.Context, LaunchProfileRequest) (CredentialSlot, error)
	InjectLaunch(context.Context, LaunchInjectionRequest) (Injection, error)
}
