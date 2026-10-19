package api

import "context"

// These are in-process reservation selectors, never public actor overrides.
type LaunchPromptRequest struct {
	ReservationID ID
	Lease         EffectLease
}

type LaunchPromptInput struct {
	Reservation LaunchReservation
	Lane        Lane
	Turn        TurnSnapshot
	Grants      GrantSet
	Policy      EffectivePolicy
}

type LaunchBriefingReader interface {
	LaunchBriefingInput(context.Context, Scope, LaunchPromptRequest) (BriefingInput, error)
}

type LaunchTemplateRenderer interface {
	LaunchBriefing(context.Context, Scope, LaunchPromptRequest) (Briefing, error)
}

type LaunchGuidanceRequest struct {
	Prompt    LaunchPromptRequest
	AttemptID ID
	Deadline  Timestamp
}

type LaunchGuidanceInput struct {
	Prompt     LaunchPromptInput
	Claim      GuidanceReservation
	Candidates []DecisionCandidate
}

type LaunchGuidanceStore interface {
	ReserveLaunchGuidance(context.Context, Scope, LaunchGuidanceRequest) (LaunchGuidanceInput, error)
}

type LaunchGuidanceSelector interface {
	LaunchGuidance(context.Context, Scope, LaunchPromptRequest) (Guidance, error)
}

// An installed judge must explicitly support the protected preparing life;
// public own-life judge ports cannot be invoked by relabelling its requester.
type LaunchGuidanceJudge interface {
	EvaluateLaunchGuidance(context.Context, Scope, LaunchPromptRequest, JudgeRequest) (JudgeReply, error)
}
