package secrets

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Continue is an internal typed call. Its protected original input is the
// existing ContinuationRequest, not an invented public lane.continue method.
// The service/store must retain these exact input bytes and their JCS digest.
func (s *Service) continuationOriginal(ctx context.Context, launch *credentialLaunch, data []byte) error {
	r := launch.record.Reservation
	var input api.ContinuationRequest
	if err := api.DecodeObject(data, &input); err != nil {
		return err
	}
	digest, err := valueDigest(input)
	if err != nil {
		return err
	}
	if digest != r.RequestSHA256 || !wire.ID(string(input.IntentID)) {
		return wire.Error(api.CodeIntegrity, "credential continuation differs from its retained original input")
	}
	intent, err := s.deps.Store.ContinuationIntent(ctx, s.deps.ServiceScope, input.IntentID)
	if err != nil {
		return err
	}
	swap := input.Swap
	if intent.ID != input.IntentID || intent.OperationID != r.OperationID || intent.Status != "claimed" || intent.Generation == 0 || intent.Target.LifeID != r.Target.LifeID || intent.Target.Run+1 != r.Target.Run ||
		intent.ExpectedGeneration != r.BaseGeneration || intent.CancellationEpoch != r.CancellationEpoch || !reflect.DeepEqual(intent.Swap, swap) ||
		swap.ExpectedGeneration != intent.ExpectedGeneration || swap.CancellationEpoch != intent.CancellationEpoch || swap.CausingRun != intent.Target.Run || swap.ContinuationRun != r.Target.Run ||
		swap.LogicalTurnID != intent.LogicalTurnID || !wire.ID(string(swap.LogicalTurnID)) || swap.OperationID != r.OperationID || swap.EligibilityID != intent.Eligibility.ID ||
		!intent.Eligibility.Compatible || !future(intent.Eligibility.ExpiresAt, s.deps.Clock.Now()) || intent.Eligibility.Request.Target != intent.Target || intent.Eligibility.Request.ToGrantID != swap.ProfileGrantID {
		return wire.Error(api.CodeConflict, "credential continuation differs from its current durable claim and eligibility")
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, r.PreviousLaunchID)
	if err != nil {
		return err
	}
	if binding.Recovery == nil {
		return wire.Error(api.CodeIntegrity, "credential continuation lost its retained private history binding")
	}
	prior, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, binding.Recovery.PlanID)
	if err != nil {
		return err
	}
	if err := api.ValidateLaunchPlanRecord(prior); err != nil {
		return err
	}
	if prior.Plan == nil {
		return wire.Error(api.CodeIntegrity, "credential continuation lost its previous launch plan")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *prior.Plan); err != nil {
		return err
	}
	if prior.Plan.Capture.Status != "registered" || binding.Record.Actor.Level != r.Level || binding.Record.Actor.Role != r.Role || prior.Plan.Reservation.Driver != r.Driver {
		return wire.Error(api.CodeForbidden, "credential continuation changed its capture role or driver pins")
	}
	if binding.Record.ID != r.PreviousLaunchID || binding.Record.Target != intent.Target || prior.Plan.Runner.Session != intent.Eligibility.Request.Session {
		return wire.Error(api.CodeForbidden, "credential continuation differs from its bound private session")
	}
	var selected api.ProfileGrant
	for _, grant := range launch.record.Inputs.Grants.Profiles {
		if grant.ID == swap.ProfileGrantID && grant.ProfileID == swap.ToProfileID {
			selected = grant
			break
		}
	}
	if selected.ID == "" {
		return wire.Error(api.CodeForbidden, "credential continuation profile is not in its exact resolved grants")
	}
	fresh, err := s.continuationRoom(ctx, intent, selected)
	if err != nil {
		return err
	}
	profile, err := s.loadProfile(ctx, selected)
	if err != nil {
		return err
	}
	if profile.Usage != nil {
		room, err := s.committedRoom(ctx, fresh.Evidence, intent.Target, selected)
		if err != nil {
			return err
		}
		launch.room = &room
	}
	lane, err := s.deps.Store.Lane(ctx, s.deps.ServiceScope, intent.Target)
	if err != nil {
		return err
	}
	if lane.Session != fresh.Request.Session || lane.Model != fresh.Request.Model || lane.ProfileGrantID != fresh.Request.FromGrantID || swap.FromProfileID != prior.Plan.Runner.Slot.ProfileID {
		return wire.Error(api.CodeConflict, "credential continuation changed its source profile model or history")
	}
	launch.profile, launch.model = selected.ID, lane.Model
	launch.continuation = &intent
	return nil
}
