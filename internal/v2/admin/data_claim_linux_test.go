//go:build linux

package admin

import (
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaunchAllocationStableAuthor(t *testing.T) {
	parent, job, _ := dataTestReg(t)
	original := parent.Request
	live := original
	live.Cause.Actor.ID = "current-allocation-executor"
	authority := launchAuthority{Record: api.LaunchPlanRecord{Reservation: job.Reg.Reservation, Inputs: &job.Reg.Inputs},
		Claim: api.EffectRecord{Effect: api.Effect{HelperAllocate: &original}}, Policy: parent.LaunchAllocations[0].Policy}
	registration := launchAllocationForAuthority(authority, live)
	if !reflect.DeepEqual(registration.Request, original) || live.Cause.Actor == original.Cause.Actor {
		t.Fatal("helper allocation journal replaced the immutable author with its live claimant")
	}
	parent.Request, parent.LaunchAllocations[0] = registration.Request, registration
	if err := validateDataJob(parent, job, testBinding()); err != nil {
		t.Fatal("original data parent no longer matches the authenticated allocation", err)
	}
}

// Store/reconciler tests exercise actual reclaim. This constructor test uses
// the native journal fixture to isolate admission metadata from stable identity.
func TestDataRegistrationAttemptMetadata(t *testing.T) {
	allocation, job, _ := dataTestReg(t)
	r := job.Reg
	cause := allocation.Request.Cause
	cause.Kind, cause.EffectID = api.InternalLaunchPlan, r.ParentEffect
	parent := api.EffectRecord{Effect: api.Effect{ID: r.ParentEffect, OperationID: r.Reservation.OperationID, Context: &cause,
		PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.Reservation.ID}},
		State: api.EffectClaimed, Generation: 2, ClaimID: "plan-claim-before", ClaimantID: "plan-executor-before", ClaimExpiresAt: r.ClaimExpires}
	stage := api.LaunchDataStage{ID: r.Request.StageID, Reservation: r.Reservation, Inputs: r.Inputs, Grants: r.Grants,
		AgentLeaseID: r.Request.AgentLeaseID, WorkerLaunchID: r.LaunchID, ParentEffectID: r.ParentEffect, Worker: r.Worker, Plan: r.Plan,
		ParentClaim: api.StablePlanningPin(r.Reservation.ID, r.ParentEffect),
		Claim:       api.EffectLease{Record: api.EffectRecord{Effect: parent.Effect}}}
	before, err := dataRegistration(r.Request, stage, parent)
	if err != nil || before.ClaimID != parent.ClaimID || before.ParentActor != cause.Actor {
		t.Fatal("reserved data preparation treated its stable pin as a live lease", err)
	}
	parent.Generation++
	parent.ClaimID, parent.ClaimantID = "plan-claim-after", "plan-executor-after"
	parent.ClaimExpiresAt = api.Timestamp(time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339Nano))
	claim := api.PlanningClaim(r.Reservation.ID, api.EffectLease{Record: parent, ClaimID: parent.ClaimID, ExpiresAt: parent.ClaimExpiresAt})
	if err := api.CheckPlanningClaim(parent, claim, r.Reservation.Config, time.Now()); err != nil {
		t.Fatal(err)
	}
	after, err := dataRegistration(r.Request, stage, parent)
	if err != nil || after.ClaimID != parent.ClaimID || after.ClaimGeneration != parent.Generation ||
		after.ParentActor != before.ParentActor || after.ClaimExpires != stage.Worker.ExpiresAt || !sameDataReg(before, after) {
		t.Fatal("reclaimed preparation changed stable journal identity or retained the old attempt", err)
	}
	parent.Effect.ID = "foreign-planning-effect"
	if _, err := dataRegistration(r.Request, stage, parent); err == nil {
		t.Fatal("another effect could supply preparation ownership")
	}
}
