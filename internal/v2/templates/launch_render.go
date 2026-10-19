package templates

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type renderPreparation struct {
	reservation api.LaunchReservation
	grants      *api.GrantSet
}

func checkRenderEnvelope(scope api.Scope) error {
	frame := scope.Request
	if frame.Protocol != api.Protocol || frame.Schema != api.SchemaVersion || frame.Config != scope.Config ||
		!safeID.MatchString(string(frame.RequestID)) || !safeID.MatchString(string(frame.IdempotencyKey)) ||
		!safeDigest.MatchString(string(frame.RequestSHA256)) {
		return integrity("lifecycle render omits its prepared causal request")
	}
	digest, err := api.RequestDigest(frame)
	if err != nil || digest != frame.RequestSHA256 {
		return integrity("lifecycle render causal request differs from its exact intent")
	}
	return nil
}

// Service planning carries an explicit selector; listing outbox work cannot
// identify an attempt whose claim is currently held by the planner.
func (s *Service) renderPreflight(ctx context.Context, scope api.Scope, request api.TemplateRequest) (*renderPreparation, error) {
	if scope.Actor.Kind != "service" {
		return nil, nil
	}
	if lifecycleRender(scope.Request.Method) {
		if err := checkRenderEnvelope(scope); err != nil {
			return nil, err
		}
	} else if scope.Request.Method != "" {
		_, _, err := s.renderCause(ctx, scope, nil)
		return nil, err
	} else if scope.Request.Proof != nil {
		return nil, problem(api.CodeForbidden, "internal planning cannot carry a public human proof",
			"Use the current service-owned planning claim.")
	}
	claim := request.Claim
	if claim == (api.LaunchClaim{}) {
		if scope.Request.Method != "" {
			// Public prepared-frame rendering retains its existing authorization.
			return nil, nil
		}
		return nil, problem(api.CodeForbidden, "service rendering requires an explicit planning claim",
			"Use the authentic reservation and current claimed effect.")
	}
	if s.deps.Clock == nil {
		return nil, problem(api.CodePrerequisite, "launch rendering requires the installed clock",
			"Bind the service clock before checking a planning claim.")
	}
	current, err := s.deps.Store.Effect(ctx, scope, claim.EffectID)
	if err != nil {
		return nil, err
	}
	if claim.ClaimantID != scope.Actor.ID {
		return nil, integrity("briefing planning claimant differs from its service scope")
	}
	if current.Effect.Context == nil {
		return nil, integrity("briefing planning effect omitted its retained cause")
	}
	record, err := s.deps.Store.LaunchPlan(ctx, scope, claim.ReservationID)
	if err != nil {
		return nil, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return nil, err
	}
	r, cause := record.Reservation, current.Effect.Context
	if r.ID != claim.ReservationID || r.Config != scope.Config || r.GrantSetID != request.GrantSetID ||
		r.Level != request.Context.Level || r.Role != request.Context.Role || (scope.LaunchID != "" && scope.LaunchID != r.LaunchID) ||
		current.Effect.OperationID != r.OperationID || cause.CauseOperationID != r.OperationID ||
		cause.CauseRequestID != r.RequestID || cause.RequestedBy != r.RequestedBy ||
		cause.Target != r.Target || cause.CancellationEpoch != r.CancellationEpoch {
		return nil, integrity("briefing launch reservation differs from its current causal effect")
	}
	if err := api.CheckPlanningClaim(current, claim, scope.Config, s.deps.Clock.Now()); err != nil {
		return nil, err
	}
	if r.Mode != "continue" && r.RequestedBy.Kind != "human" && r.RequestedBy.Kind != "lane" {
		return nil, integrity("public planning reservation has no authentic requester")
	}
	if record.Phase != "reserved" && record.Phase != "sourced" {
		return nil, problem(api.CodeConflict, "briefing launch plan is past prompt preparation",
			"Reconcile the retained plan before rendering.")
	}
	if scope.Request.Method != "" && (scope.Request.Method != api.Method("lane."+r.Mode) ||
		r.RequestID != scope.Request.RequestID || r.RequestSHA256 != scope.Request.RequestSHA256) {
		return nil, integrity("briefing launch reservation differs from its original public request")
	}
	selected := &renderPreparation{reservation: r}
	if record.Inputs != nil {
		grants := record.Inputs.Grants
		selected.grants = &grants
	}
	return selected, nil
}

func (p *renderPreparation) checkInput(input api.BriefingInput) error {
	r := p.reservation
	lane := input.Lane
	if lane == nil || input.GrantSet == nil || lane.LifeID != r.Target.LifeID || lane.Run != r.Target.Run ||
		lane.Generation != r.Generation || lane.GrantSetID != r.GrantSetID || lane.CancellationEpoch != r.CancellationEpoch ||
		lane.ParentLifeID != r.ParentLifeID || lane.RootLifeID != r.RootLifeID || !reflect.DeepEqual(lane.StarterChain, r.StarterChain) ||
		lane.StarterEventSeq != r.StarterEventSeq || lane.Session.Driver != r.Driver ||
		r.PolicyGeneration != input.Policy.Generation || p.grants != nil && !reflect.DeepEqual(*input.GrantSet, *p.grants) {
		return integrity("briefing input differs from the reserved launch life and grants")
	}
	return nil
}
