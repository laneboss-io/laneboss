package templates

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.LaunchTemplateRenderer = (*Service)(nil)

// LaunchBriefing is an internal reservation port. Public BriefRender retains
// its self-scope and prepared-frame rules; a service actor is not a human.
func (s *Service) LaunchBriefing(ctx context.Context, scope api.Scope, request api.LaunchPromptRequest) (api.Briefing, error) {
	if s.deps.Clock == nil {
		return api.Briefing{}, problem(api.CodePrerequisite, "launch rendering requires the installed clock",
			"Bind the service clock before checking a planning claim.")
	}
	current, err := s.deps.Store.Effect(ctx, scope, request.Lease.Record.Effect.ID)
	if err != nil {
		return api.Briefing{}, err
	}
	if scope.Actor.Kind != "service" || scope.Actor.ID != request.Lease.Record.ClaimantID {
		return api.Briefing{}, integrity("launch briefing requires its actual service claimant")
	}
	if err := api.CheckPlanningClaim(current, api.PlanningClaim(request.ReservationID, request.Lease), scope.Config, s.deps.Clock.Now()); err != nil {
		return api.Briefing{}, err
	}
	reader, ok := s.deps.Store.(api.LaunchBriefingReader)
	if !ok || reader == nil {
		return api.Briefing{}, api.NotImplemented("lb-v2-service", "protected launch briefing input")
	}
	input, err := reader.LaunchBriefingInput(ctx, scope, request)
	if err != nil {
		return api.Briefing{}, err
	}
	r := request.Lease.Record.Effect.Context
	if input.Mode != "lane" || input.Lane == nil || input.Task == nil || input.GrantSet == nil || r == nil ||
		input.Lane.LifeID != r.Target.LifeID || input.Lane.Run != r.Target.Run || input.Lane.Task != *input.Task ||
		input.Lane.GrantSetID != input.GrantSet.ID || input.Lane.Level != input.Policy.Context.Level || input.Lane.Role != input.Policy.Context.Role {
		return api.Briefing{}, integrity("protected launch briefing input differs from its retained cause")
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, scope, request.ReservationID)
	if err != nil {
		return api.Briefing{}, err
	}
	preparation := &renderPreparation{reservation: plan.Reservation, grants: input.GrantSet}
	if err := preparation.checkInput(input); err != nil {
		return api.Briefing{}, err
	}
	return s.renderBriefing(ctx, scope, input.Policy.Context, input, preparation)
}
