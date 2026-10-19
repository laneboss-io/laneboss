package guidance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.LaunchGuidanceSelector = (*Service)(nil)

// LaunchGuidance selects the original launch turn without impersonating its
// human requester or invoking the public self-access handler as a service.
func (s *Service) LaunchGuidance(ctx context.Context, scope api.Scope, request api.LaunchPromptRequest) (api.Guidance, error) {
	entered := s.deps.Clock.Now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	backend, ok := s.deps.Store.(api.LaunchGuidanceStore)
	if !ok || missing(backend) {
		return api.Guidance{}, api.NotImplemented("lb-v2-service", "protected launch guidance reservation")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return api.Guidance{}, err
	}
	input, err := backend.ReserveLaunchGuidance(ctx, scope, api.LaunchGuidanceRequest{Prompt: request,
		AttemptID: api.ID(hex.EncodeToString(nonce[:])), Deadline: api.Timestamp(entered.Add(5 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		return api.Guidance{}, err
	}
	r, p := input.Claim, input.Prompt
	if err := api.ValidateGuidanceReservation(r); err != nil {
		return api.Guidance{}, err
	}
	if r.LaunchReservationID != request.ReservationID || r.LaunchEffectID != request.Lease.Record.Effect.ID ||
		r.OwnerOperationID != p.Reservation.OperationID || r.OwnerRequestID != p.Reservation.RequestID || r.RequestedBy != p.Reservation.RequestedBy ||
		r.Target != p.Reservation.Target || r.Task != p.Lane.Task || r.LogicalTurnID != p.Turn.LogicalTurnID || r.PolicyGeneration != p.Policy.Generation {
		return api.Guidance{}, integrity("launch guidance changed its protected requester, turn or task")
	}
	query := api.GuidanceRequest{Target: r.Target, LogicalTurnID: r.LogicalTurnID, Task: r.Task}
	if !r.Acquired {
		if r.Status != "completed" {
			r, err = s.deps.Store.AwaitGuidance(ctx, scope, api.GuidanceAwaitRequest{ReservationID: r.ID, Deadline: r.Deadline})
			if err != nil {
				return api.Guidance{}, err
			}
		}
		result, err := validateCompletedSelection(r, query, p.Policy.Generation)
		if err != nil {
			return api.Guidance{}, err
		}
		return *result, nil
	}
	if input.Candidates == nil || len(input.Candidates) > 12800 || !claimBindings(input.Candidates, r.BindingItems) {
		return api.Guidance{}, integrity("launch guidance omitted its complete candidate snapshot")
	}
	reminders := 0
	for _, candidate := range input.Candidates {
		if !validAuthority(candidate) {
			return api.Guidance{}, integrity("launch guidance candidate lost its canonical authority")
		}
		if !candidate.Binding {
			reminders++
		}
		if candidate.Authority.Kind == "human" {
			stored, err := s.deps.Store.Decision(ctx, scope, candidate.ID)
			if err != nil {
				return api.Guidance{}, err
			}
			if stored.Candidate.Source != candidate.Source || stored.Candidate.Authority != candidate.Authority || stored.RecordID != candidate.ID {
				return api.Guidance{}, integrity("launch guidance candidate differs from its canonical decision")
			}
		} else {
			stored, err := s.deps.Store.Source(ctx, scope, candidate.Source)
			if err != nil {
				return api.Guidance{}, err
			}
			if stored.Source != candidate.Source || stored.Content.SHA256 != candidate.Source.SHA256 {
				return api.Guidance{}, integrity("launch guidance source differs from approved content")
			}
		}
	}
	task, err := s.taskBytes(ctx, scope, r.Task)
	if err != nil {
		return api.Guidance{}, err
	}
	asOf, err := time.Parse(time.RFC3339Nano, string(r.ReservedAt))
	if err != nil {
		return api.Guidance{}, err
	}
	var result api.Guidance
	if reminders == 0 {
		// Empty is established from the complete retained corpus, not from a
		// failed judge or a budget guess. No provider call is needed.
		result, err = rankWithCutoff(asOf, p.Policy.GuidanceHalfLifeSeconds, p.Policy.GuidanceMinRelevance, input.Candidates, api.JudgeReply{})
		if err != nil {
			return api.Guidance{}, err
		}
	} else if r.MaxCostMicros == 0 {
		result = api.Guidance{Status: "unavailable", AsOf: r.ReservedAt, Items: append([]api.GuidanceItem{}, r.BindingItems...),
			JudgmentIDs: []api.ID{}, Notice: "The retained launch has no judgment budget; binding context is retained without a model request."}
	} else {
		judgeRequest := api.JudgeRequest{ID: r.OwnerAttemptID, Purpose: "guidance", Rules: []api.JudgeRule{}, Decisions: input.Candidates,
			Task: task, Config: p.Policy.Judge, MaxCostMicros: r.MaxCostMicros,
			Context: api.JudgeContext{Config: scope.Config, Target: r.Target, LogicalTurnID: r.LogicalTurnID, Role: p.Policy.Context,
				PolicyGeneration: r.PolicyGeneration, GrantSetID: p.Grants.ID, GrantsSHA256: p.Grants.SHA256, CWD: p.Lane.Workspace.LogicalCWD}}
		if evaluator, ok := s.deps.Judge.(api.LaunchGuidanceJudge); ok && !missing(evaluator) {
			reply, err := evaluator.EvaluateLaunchGuidance(ctx, scope, request, judgeRequest)
			if err != nil {
				return api.Guidance{}, err
			}
			result, err = rankWithCutoff(asOf, p.Policy.GuidanceHalfLifeSeconds, p.Policy.GuidanceMinRelevance, input.Candidates, reply)
			if err != nil {
				return api.Guidance{}, err
			}
		} else {
			result = api.Guidance{Status: "unavailable", AsOf: r.ReservedAt, Items: append([]api.GuidanceItem{}, r.BindingItems...), JudgmentIDs: []api.ID{},
				Notice: "Historical guidance is unavailable because the installed judge has no reservation-bound launch port; binding context is retained."}
		}
	}
	return s.completeClaim(ctx, scope, query, p.Turn, r, result, api.InternalGuidanceComplete)
}
