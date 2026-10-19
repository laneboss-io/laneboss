package secrets

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func newContinuationCase(t *testing.T) (*launchCase, api.ProfileGrant) {
	c, selected, _, _ := continuationModeCase(t, "helper", false)
	return c, selected
}

func continuationModeCase(t *testing.T, mode string, alias bool) (*launchCase, api.ProfileGrant, api.CredentialSlot, api.ProcessObservation) {
	t.Helper()
	c := newLaunchCaseWithAlternate(t, mode)
	c.registeredCapture = true
	login := api.ID("canonical-login-b")
	if alias {
		login = c.profile.LoginID
		c.profile.Generation++
		observation := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: "service-case", ProfileID: c.profile.ID, LoginID: c.profile.LoginID, Generation: c.profile.Generation, Driver: c.profile.Driver, Provider: c.profile.Provider,
			Available: true, CheckedAt: api.Timestamp(c.clock.now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(c.clock.now.Add(10 * time.Millisecond).Format(time.RFC3339Nano))}
		c.profile.Evidence = c.store.putObject(t, "short-profile-evidence", "credential_evidence", observation, "short-observation-operation")
		if err := c.service.InstallProfile(context.Background(), c.profile); err != nil {
			t.Fatal("cannot install short-lived original room evidence")
		}
	}
	selected, _ := c.installProfileAlias(t, login)
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot acquire the original continuation profile")
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal("cannot prepare the original continuation injection")
	}
	observation := c.bind(t, slot, injection)
	request := api.ProfileEligibilityRequest{Target: c.target, GrantSetID: c.store.grants.ID, FromGrantID: c.grant.ID, ToGrantID: selected.ID, Driver: c.grant.Driver, Model: c.store.lane.Model, Session: c.store.lane.Session, HistoryID: c.store.lane.Session.HistoryID}
	eligibility, err := c.service.Eligibility(context.Background(), request)
	if err != nil || !eligibility.Compatible {
		t.Fatal("cannot establish real protected continuation eligibility")
	}
	room, err := c.service.Room(context.Background(), selected)
	if err != nil || !room.Available {
		t.Fatal("cannot establish protected continuation room")
	}
	observation = c.finish(t, observation)
	stageContinuation(t, c, selected, eligibility, room)
	return c, selected, slot, observation
}

func stageContinuation(t *testing.T, c *launchCase, selected api.ProfileGrant, eligibility api.ProfileEligibility, room api.Room) {
	t.Helper()
	var err error
	prior := c.plan(t)
	c.store.priorPlanID, c.store.priorLaunchID = prior.Reservation.ID, prior.Reservation.LaunchID
	if err := c.store.save("prior-plan.json", prior); err != nil {
		t.Fatal("cannot retain previous continuation plan")
	}
	var binding api.LaunchBindingRequest
	if err := c.store.read("binding.json", &binding); err != nil {
		t.Fatal("cannot read previous continuation binding")
	}
	if err := c.store.save("prior-binding.json", binding); err != nil {
		t.Fatal("cannot retain previous continuation binding")
	}
	swap := api.ProfileSwap{ProfileGrantID: selected.ID, EligibilityID: eligibility.ID, ExpectedGeneration: 1, CancellationEpoch: 1, FromProfileID: c.grant.ProfileID, ToProfileID: selected.ProfileID, CausingRun: 1, ContinuationRun: 2, LogicalTurnID: "logical-turn", Room: room, OperationID: "continue-operation"}
	input := api.ContinuationRequest{IntentID: "continuation-a", Swap: swap}
	intent := api.ContinuationIntent{ID: input.IntentID, Target: c.target, LogicalTurnID: swap.LogicalTurnID, ExpectedGeneration: swap.ExpectedGeneration, CancellationEpoch: swap.CancellationEpoch, Generation: 1, Status: "claimed", Swap: swap, Eligibility: eligibility, OperationID: swap.OperationID}
	if err := c.store.save("continuation.json", intent); err != nil {
		t.Fatal("cannot retain current continuation claim")
	}
	r := prior.Reservation
	r.ID, r.LaunchID, r.SpecID, r.Mode, r.PreviousLaunchID = "continue-reservation", "continue-launch", "continue-spec", "continue", prior.Reservation.LaunchID
	r.Authority = api.LaunchAuthority{Kind: "starter", ID: r.PreviousLaunchID}
	r.Target.Run, r.Generation, r.BaseGeneration, r.OperationID, r.RequestID = 2, 2, 1, swap.OperationID, "continue-request"
	r.OriginalRequest = c.store.putObject(t, "continue-input", "launch_request", input, r.OperationID)
	r.RequestSHA256, err = valueDigest(input)
	if err != nil {
		t.Fatal("cannot hash exact original continuation input")
	}
	inputs := *prior.Inputs
	inputs.Sources.ReservationID = r.ID
	c.store.planID, c.target = r.ID, r.Target
	record := api.LaunchPlanRecord{Reservation: r, Generation: 2, Phase: "sourced", Inputs: &inputs}
	c.setPlan(t, record)
	var effect api.EffectRecord
	if err := c.store.read("effect.json", &effect); err != nil {
		t.Fatal("cannot read continuation planning claim")
	}
	effect.Effect.OperationID, effect.Effect.PlanLaunch.ReservationID = r.OperationID, r.ID
	effect.Effect.Context.Target, effect.Effect.Context.CauseOperationID, effect.Effect.Context.CauseRequestID = r.Target, r.OperationID, r.RequestID
	if err := c.store.save("effect.json", effect); err != nil {
		t.Fatal("cannot retain continuation planning claim")
	}
	var storage api.LaunchStorage
	if err := c.store.read("storage.json", &storage); err != nil {
		t.Fatal("cannot read retained continuation storage")
	}
	storage.ReservationID, storage.Target, storage.LeaseID = r.ID, r.Target, "continue-helper"
	if err := c.store.save("storage.json", storage); err != nil {
		t.Fatal("cannot retain continuation allocation")
	}
	lease := api.HelperLease{ID: storage.LeaseID, UID: 12001, GID: 12001, ContainmentID: "continue-containment", EndpointGeneration: 2}
	payload, err := json.Marshal(lease)
	if err != nil {
		t.Fatal("cannot encode continuation allocation receipt")
	}
	c.store.events = append(c.store.events, api.Event{Schema: api.SchemaVersion, ID: "continue-allocation", Seq: 3, Kind: "helper.allocated", Config: r.Config, Actor: effect.Effect.Context.Actor,
		RequestedBy: r.RequestedBy, RequestID: r.RequestID, OperationID: r.OperationID, LifeID: r.Target.LifeID, Run: r.Target.Run, Payload: payload})
}

func TestContinuationCredentialSelection(t *testing.T) {
	c, selected := newContinuationCase(t)
	slot, err := c.acquire(context.Background(), c.target, selected)
	if err != nil || slot.ProfileGrantID != selected.ID || slot.ProfileID != selected.ProfileID {
		t.Fatal("continuation did not acquire its exact current eligible replacement profile")
	}
	if c.store.lane.Run != 1 {
		t.Fatal("credential continuation manufactured the next ready run")
	}
	_, err = c.acquire(context.Background(), c.target, c.grant)
	stageCode(t, err, api.CodeForbidden)
}

func TestContinuationCredentialGuards(t *testing.T) {
	for _, fault := range []string{"epoch", "claim", "selection", "eligibility", "binding", "dependency"} {
		t.Run(fault, func(t *testing.T) {
			c, selected := newContinuationCase(t)
			var intent api.ContinuationIntent
			if err := c.store.read("continuation.json", &intent); err != nil {
				t.Fatal("cannot read continuation control")
			}
			code := api.CodeConflict
			switch fault {
			case "epoch":
				intent.CancellationEpoch++
			case "claim":
				intent.Status = "cancelled"
			case "selection":
				intent.Swap.ProfileGrantID = c.grant.ID
			case "eligibility":
				intent.Eligibility.Compatible = false
			case "binding":
				c.store.fail["binding"] = &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-service", Message: "fixture previous binding is absent"}
				code = api.CodeNotFound
			case "dependency":
				c.store.fail["continuation"] = api.NotImplemented("lb-v2-service", "store.ContinuationIntent")
				code = api.CodeNotImplemented
			}
			if err := c.store.save("continuation.json", intent); err != nil {
				t.Fatal("cannot retain continuation control")
			}
			_, err := c.acquire(context.Background(), c.target, selected)
			stageCode(t, err, code)
		})
	}
}
