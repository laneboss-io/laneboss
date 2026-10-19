package watchdog

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) liveTurn(ctx context.Context, lane api.Lane, target api.LifeRef) error {
	return s.liveTurnAtPolicy(ctx, lane, target, lane.PolicyGeneration)
}

// Current authorization and retained turn policy are separate read facts. A
// fresh selection can verify the old turn snapshot before advancing the life.
func (s *Service) liveTurnAtPolicy(ctx context.Context, lane api.Lane, target api.LifeRef, authority api.Generation) error {
	turn, err := s.deps.Store.Turn(ctx, s.readScope(), target, lane.LogicalTurnID)
	if err != nil {
		return err
	}
	if turn.Target != target || turn.LogicalTurnID != lane.LogicalTurnID ||
		turn.Task != lane.Task || turn.PolicyGeneration == 0 || turn.PolicyGeneration > authority || turn.Generation == 0 {
		return problem(api.CodeIntegrity, "quota continuation has no matching retained turn and task")
	}
	if turn.Status != "running" {
		return problem(api.CodeConflict, "quota continuation requires a running logical turn")
	}
	if turn.PolicyGeneration != authority {
		generation, err := api.PolicyGenerationFor(api.PolicyRetainedSelection, authority, turn.PolicyGeneration)
		if err != nil {
			return err
		}
		scope := s.readScope()
		scope.LaunchID, scope.PolicyGeneration = lane.LaunchID, authority
		policy, err := s.deps.Store.PolicyAt(ctx, scope, generation)
		if err != nil {
			return err
		}
		if policy.Generation != generation || !validDigest.MatchString(string(policy.SHA256)) || policy.Context.Level != lane.Level || policy.Context.Role != lane.Role {
			return problem(api.CodeIntegrity, "logical turn lost its immutable approved policy snapshot")
		}
	}
	return nil
}

func (s *Service) policyForLane(ctx context.Context, lane api.Lane) (api.EffectivePolicy, error) {
	scope := s.readScope()
	// The trusted launch is the read target; the actor remains watchdog.
	scope.LaunchID, scope.PolicyGeneration = lane.LaunchID, lane.PolicyGeneration
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.EffectivePolicy{}, err
	}
	if policy.Generation < lane.PolicyGeneration || policy.Generation == 0 || !validDigest.MatchString(string(policy.SHA256)) ||
		policy.Context.Level != lane.Level || policy.Context.Role != lane.Role {
		return api.EffectivePolicy{}, problem(api.CodeConflict, "effective profile policy differs from the current life")
	}
	return policy, nil
}

// Current policy is resolved only for fresh work. Historical launch/grant and
// turn snapshots remain immutable; the protected store advances the life fence.
func (s *Service) freshPolicy(ctx context.Context, lane api.Lane, expected api.EffectivePolicy) (api.Lane, error) {
	policy, err := s.policyForLane(ctx, lane)
	if err != nil {
		return api.Lane{}, err
	}
	if !reflect.DeepEqual(policy, expected) {
		return api.Lane{}, problem(api.CodeConflict, "approved policy changed after limit validation")
	}
	generation, err := api.PolicyGenerationFor(api.PolicyNewLaunch, policy.Generation, lane.PolicyGeneration)
	if err != nil {
		return api.Lane{}, err
	}
	if generation == lane.PolicyGeneration {
		return lane, nil
	}
	request := api.PolicyAdvanceRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run},
		ExpectedLaneGeneration: lane.Generation, FromGeneration: lane.PolicyGeneration, ToGeneration: generation,
		CancellationEpoch: lane.CancellationEpoch}
	scope := s.readScope()
	scope.LaunchID, scope.PolicyGeneration = lane.LaunchID, generation
	receipt, err := s.deps.Store.RefreshLanePolicy(ctx, scope, request)
	if err != nil {
		return api.Lane{}, err
	}
	if err := api.ValidatePolicyAdvance(lane, request, policy, receipt); err != nil {
		return api.Lane{}, err
	}
	current, err := s.currentLane(ctx, request.Target)
	if err != nil {
		return api.Lane{}, err
	}
	if !reflect.DeepEqual(current, receipt.Lane) {
		return api.Lane{}, problem(api.CodeConflict, "life changed after current-policy refresh")
	}
	return current, nil
}

func excluded(policy api.EffectivePolicy, profile api.ID) bool {
	for _, id := range policy.ProfileExclusions {
		if id == profile {
			return true
		}
	}
	return false
}

func (s *Service) pendingGrant(ctx context.Context, lane api.Lane, intent api.ContinuationIntent) (api.ProfileGrant, error) {
	var destination api.ProfileGrant
	if err := s.liveTurn(ctx, lane, intent.Target); err != nil {
		return destination, err
	}
	launch, err := s.deps.Store.Launch(ctx, lane.LaunchID)
	if err != nil {
		return destination, err
	}
	if launch.ID != lane.LaunchID || launch.Config != s.deps.Config || launch.Target != intent.Target || launch.Revoked ||
		launch.GrantSetID != lane.GrantSetID || launch.PolicyGeneration > lane.PolicyGeneration {
		return destination, problem(api.CodeIntegrity, "pending continuation lost its bound launch")
	}
	if _, err := s.launchContext(ctx, lane, launch); err != nil {
		return destination, err
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return destination, err
	}
	checked, err := s.deps.Grants.Revalidate(ctx, grants)
	if err != nil {
		return destination, err
	}
	if !reflect.DeepEqual(checked, grants) {
		return destination, problem(api.CodeConflict, "effective grants changed before continuation")
	}
	policy, err := s.policyForLane(ctx, lane)
	if err != nil {
		return destination, err
	}
	if policy.Generation != lane.PolicyGeneration {
		return destination, problem(api.CodeConflict, "policy changed during pending recovery")
	}
	current, err := s.currentLane(ctx, intent.Target)
	if err != nil {
		return destination, err
	}
	if !reflect.DeepEqual(current, lane) {
		return destination, problem(api.CodeConflict, "life changed during pending recovery")
	}
	now := s.deps.Clock.Now()
	if err := currentGrants(grants, lane, launch, now); err != nil {
		return destination, err
	}
	active, err := activeProfile(grants, lane, intent.Swap.Limit, now)
	if err != nil {
		return destination, err
	}
	for _, grant := range grants.Profiles {
		if grant.ID == intent.Swap.ProfileGrantID {
			destination = grant
		}
	}
	if destination.ID == "" || destination.ProfileID != intent.Swap.ToProfileID ||
		destination.Driver != active.Driver || destination.Provider != active.Provider ||
		(destination.Paid && (!active.Paid || lane.BudgetRemaining.SpendMicros <= 0)) || excluded(policy, destination.ProfileID) {
		return api.ProfileGrant{}, problem(api.CodeForbidden, "pending destination is no longer an eligible delegated profile")
	}
	if err := profileLive(destination, now); err != nil {
		return api.ProfileGrant{}, err
	}
	return destination, nil
}

// Control events are service-origin records even when their actor is a human
// or a supervising lane. Run zero applies to the whole life.
func controlError(events []api.Event, target api.LifeRef, turn api.ID) error {
	var launchSeq api.Sequence
	for _, event := range events {
		if event.Run == target.Run && outsideEvent(event, "service", "worker", "scheduler", "watchdog") &&
			(event.Kind == "lane.started" || event.Kind == "lane.resumed") && (launchSeq == 0 || event.Seq < launchSeq) {
			launchSeq = event.Seq
		}
	}
	for _, event := range events {
		if event.Origin != "service" {
			continue
		}
		// helper_open/mail_deliver can announce this run's own turn after its
		// launch. Only a different later turn on this or a newer run (or the
		// whole life) supersedes it; a profile continuation retains its turn.
		if event.Kind == "lane.turn" && launchSeq != 0 && event.Seq > launchSeq &&
			(event.Run == 0 || event.Run >= target.Run) && event.LogicalTurnID != "" && event.LogicalTurnID != turn {
			return problem(api.CodeCancelled, "a later logical turn superseded this run")
		}
		if event.Run != 0 && event.Run != target.Run {
			continue
		}
		switch event.Kind {
		case "capture.refused":
			var capture api.CaptureBinding
			if err := decodePayload(event.Payload, &capture); err != nil {
				return err
			}
			if err := api.ValidateCaptureBinding(capture); err != nil {
				return err
			}
			if capture.Status != "refused" || capture.Target != target || capture.Config != event.Config {
				return problem(api.CodeIntegrity, "capture refusal differs from its run")
			}
			return capture.Refusal
		case "watchdog.cancelled":
			return problem(api.CodeCancelled, "watchdog intent was cancelled")
		case "lane.stopping", "lane.cleaned", "grants.revoked", "lane.lost":
			return problem(api.CodeCancelled, "manual control or revocation cancelled this run")
		case "lane.state":
			var state api.StateEvent
			if err := decodePayload(event.Payload, &state); err != nil {
				return err
			}
			switch state.To {
			case "stopping", "abandoned", "merged", "accepted":
				return problem(api.CodeCancelled, "terminal state cancelled continuation")
			}
		}
	}
	return nil
}

func blobClass(class string) bool {
	switch class {
	case "task", "prompt", "report", "artifact", "capture", "transcript", "policy", "manifest", "judge_request", "judge_raw", "archive", "record", "usage_window", "usage_raw":
		return true
	}
	return false
}
