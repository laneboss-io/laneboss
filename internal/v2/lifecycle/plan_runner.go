package lifecycle

import (
	"context"
	"reflect"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

type launchPrompt struct {
	Schema         string           `json:"schema"`
	Task           string           `json:"task"`
	Briefing       string           `json:"briefing"`
	Guidance       []launchGuidance `json:"guidance"`
	GuidanceID     api.ID           `json:"guidance_id"`
	GuidanceStatus string           `json:"guidance_status"`
	GuidanceNotice string           `json:"guidance_notice"`
	Message        string           `json:"message"`
	Mail           []launchMail     `json:"mail"`
}

type launchMail struct {
	Mail    api.Mail `json:"mail"`
	Content string   `json:"content"`
}

type launchGuidance struct {
	Selection api.GuidanceItem `json:"selection"`
	Content   string           `json:"content"`
}

func (execution *planExecution) prompt(ctx context.Context, inputs api.LaunchInputs) (api.BlobRef, error) {
	s, r, input := execution.service, execution.record.Reservation, execution.input
	if r.Mode == "continue" {
		if input.previous == nil || input.previous.Recovery == nil || input.previous.Recovery.Handoff.Spec.Runner == nil {
			return api.BlobRef{}, integrity("continuation lost its original prompt binding")
		}
		turn, err := s.deps.Store.Turn(ctx, execution.scope, input.previous.Record.Target, input.turn)
		if err != nil {
			return api.BlobRef{}, failure(err)
		}
		if turn.Target != input.previous.Record.Target || turn.LogicalTurnID != input.turn || turn.Task != input.task ||
			turn.Prompt == nil || *turn.Prompt != input.previous.Recovery.Handoff.Spec.Runner.Prompt {
			return api.BlobRef{}, integrity("continuation changed its retained logical-turn prompt")
		}
		policy, err := s.deps.Store.Policy(ctx, execution.scope)
		if err != nil {
			return api.BlobRef{}, failure(err)
		}
		generation, err := api.PolicyGenerationFor(api.PolicyRetainedSelection, policy.Generation, turn.PolicyGeneration)
		if err != nil {
			return api.BlobRef{}, failure(err)
		}
		retained, err := s.deps.Store.PolicyAt(ctx, execution.scope, generation)
		if err != nil {
			return api.BlobRef{}, failure(err)
		}
		if retained.Generation != generation {
			return api.BlobRef{}, integrity("retained turn policy history returned a foreign generation")
		}
		if _, err := s.readBlob(ctx, execution.scope, *turn.Prompt); err != nil {
			return api.BlobRef{}, err
		}
		return *turn.Prompt, nil
	}
	mail := []launchMail{}
	if len(input.mail) > 0 {
		if absent(s.deps.Delivery) {
			return api.BlobRef{}, api.NotImplemented("lb-v2-messaging", "MailDelivery.BeginDelivery")
		}
		// The messaging owner rechecks sender/relationship/current grants and
		// claims this exact ordered batch. Preparation never acknowledges mail.
		batch, err := s.deps.Delivery.BeginDelivery(ctx, execution.scope, api.DeliveryTurnRequest{
			Lease: execution.lease, Target: r.Target, LogicalTurnID: input.turn, MailIDs: input.mail,
			ExpectedGeneration: r.Generation, CancellationEpoch: r.CancellationEpoch})
		if err != nil {
			return api.BlobRef{}, failure(err)
		}
		if batch.Target != r.Target || batch.LogicalTurnID != input.turn || len(batch.Mail) != len(input.mail) {
			return api.BlobRef{}, integrity("reserved turn has no exact ordered mail claim")
		}
		if batch.Intent.Kind != api.InternalMailDeliver || !validID(batch.Intent.ID) || !validGeneration(batch.Generation) ||
			batch.Intent.Config != r.Config || batch.Intent.Target != r.Target || batch.Intent.LogicalTurnID != input.turn ||
			batch.Intent.Actor != execution.scope.Actor || batch.Intent.RequestedBy != r.RequestedBy ||
			batch.Intent.CauseOperationID != r.OperationID || batch.Intent.CauseRequestID != r.RequestID ||
			batch.Intent.CancellationEpoch != r.CancellationEpoch || batch.Intent.EffectID != execution.lease.Record.Effect.ID {
			return api.BlobRef{}, integrity("turn delivery claim changed its authentic requester or operation")
		}
		for i, item := range batch.Mail {
			if item.ID != input.mail[i] || item.RecipientLifeID != r.Target.LifeID || item.LogicalTurnID != input.turn ||
				item.QueuedSeq == 0 || !validID(item.Sender.ID) || !validBlob(item.Content) {
				return api.BlobRef{}, integrity("turn mail changed its order, sender or causal sequence")
			}
			content, err := s.readBlob(ctx, execution.scope, item.Content)
			if err != nil {
				return api.BlobRef{}, err
			}
			if !utf8.Valid(content) {
				return api.BlobRef{}, invalid("turn mail is not valid UTF-8 text")
			}
			mail = append(mail, launchMail{Mail: item, Content: string(content)})
		}
	}
	if absent(s.deps.Templates) {
		return api.BlobRef{}, api.NotImplemented("lb-v2-templates", "Templates.BriefRender")
	}
	briefing, err := launchStage(ctx, execution, "briefing", api.TemplateRequest{
		Context: input.role, Task: input.task, GrantSetID: inputs.Grants.ID, Claim: api.PlanningClaim(r.ID, execution.lease)}, func() (api.Briefing, error) {
		if renderer, ok := s.deps.Templates.(api.LaunchTemplateRenderer); ok && !absent(renderer) {
			return renderer.LaunchBriefing(ctx, execution.scope, api.LaunchPromptRequest{ReservationID: r.ID, Lease: execution.lease})
		}
		return s.deps.Templates.BriefRender(ctx, execution.scope, api.TemplateRequest{
			Context: input.role, Task: input.task, GrantSetID: inputs.Grants.ID, Claim: api.PlanningClaim(r.ID, execution.lease)})
	})
	if err != nil {
		return api.BlobRef{}, err
	}
	if briefing.PolicyGeneration != r.PolicyGeneration || !validBlob(briefing.Markdown) ||
		!validID(briefing.Template.ID) || !validGeneration(briefing.Template.Generation) {
		return api.BlobRef{}, integrity("briefing differs from the reserved role or policy")
	}
	if absent(s.deps.Guidance) {
		return api.BlobRef{}, api.NotImplemented("lb-v2-guidance", "Guidance.Select")
	}
	guidanceRequest := api.GuidanceRequest{Target: r.Target, LogicalTurnID: input.turn, Task: input.task}
	guidance, err := launchStage(ctx, execution, "guidance", guidanceRequest, func() (api.Guidance, error) {
		if selector, ok := s.deps.Guidance.(api.LaunchGuidanceSelector); ok && !absent(selector) {
			return selector.LaunchGuidance(ctx, execution.scope, api.LaunchPromptRequest{ReservationID: r.ID, Lease: execution.lease})
		}
		return s.deps.Guidance.GuidanceSelect(ctx, execution.scope, guidanceRequest)
	})
	if err != nil {
		return api.BlobRef{}, err
	}
	if guidance.Target != r.Target || guidance.LogicalTurnID != input.turn || guidance.Task != input.task ||
		guidance.PolicyGeneration != r.PolicyGeneration ||
		guidance.Status != "scored" && guidance.Status != "empty" && guidance.Status != "unavailable" {
		return api.BlobRef{}, integrity("guidance differs from the reserved logical turn")
	}
	task, err := s.readBlob(ctx, execution.scope, input.task)
	if err != nil {
		return api.BlobRef{}, err
	}
	rules, err := s.readBlob(ctx, execution.scope, briefing.Markdown)
	if err != nil {
		return api.BlobRef{}, err
	}
	if !utf8.Valid(task) || !utf8.Valid(rules) {
		return api.BlobRef{}, invalid("launch prompt inputs must be complete UTF-8 text")
	}
	prompt := launchPrompt{Schema: "laneboss.launch-prompt.v2", Task: string(task), Briefing: string(rules),
		Guidance: []launchGuidance{}, GuidanceID: guidance.ID, GuidanceStatus: guidance.Status, GuidanceNotice: guidance.Notice, Mail: mail}
	for _, item := range guidance.Items {
		source, err := s.deps.Store.Source(ctx, execution.scope, item.Source)
		if err != nil {
			return api.BlobRef{}, failure(err)
		}
		if source.Source != item.Source || source.Content.SHA256 != item.Source.SHA256 {
			return api.BlobRef{}, integrity("guidance source bytes changed after selection")
		}
		content, err := s.readBlob(ctx, execution.scope, source.Content)
		if err != nil {
			return api.BlobRef{}, err
		}
		if !utf8.Valid(content) {
			return api.BlobRef{}, integrity("guidance source is not valid text")
		}
		prompt.Guidance = append(prompt.Guidance, launchGuidance{Selection: item, Content: string(content)})
	}
	if input.message != nil {
		message, err := s.readBlob(ctx, execution.scope, *input.message)
		if err != nil {
			return api.BlobRef{}, err
		}
		if !utf8.Valid(message) {
			return api.BlobRef{}, invalid("continuation input is not valid text")
		}
		prompt.Message = string(message)
	}
	return execution.retain(ctx, "prompt", "prompt", prompt)
}

func (execution *planExecution) runnerPlan(ctx context.Context, inputs api.LaunchInputs, data api.LaunchData) (_ api.RunnerPlan, _ api.Injection, resultErr error) {
	check := "plan_profile"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	s, r, input := execution.service, execution.record.Reservation, execution.input
	var selected *api.ProfileGrant
	var resolved *api.ProfileGrant
	selectedID := input.profile
	if r.Mode == "start" || r.Mode == "adopt" {
		if resolver, ok := s.deps.Grants.(interface {
			ResolveProfile(context.Context, api.Scope, api.GrantResolveRequest) (api.ProfileGrant, error)
		}); ok && !absent(resolver) {
			profile, err := resolver.ResolveProfile(ctx, execution.scope, api.GrantResolveRequest{ReservationID: r.ID})
			if err != nil {
				return api.RunnerPlan{}, api.Injection{}, failure(err)
			}
			resolvedCopy := profile
			resolved = &resolvedCopy
			selectedID = profile.ID
			resolved = &profile
		}
	}
	for i := range inputs.Grants.Profiles {
		profile := &inputs.Grants.Profiles[i]
		if profile.ID == selectedID && profile.Driver == input.driver {
			if resolved != nil && *profile != *resolved {
				continue
			}
			if selected != nil {
				return api.RunnerPlan{}, api.Injection{}, integrity("launch profile selection is ambiguous")
			}
			selected = profile
		}
	}
	if selected == nil {
		return api.RunnerPlan{}, api.Injection{}, problem(api.CodeForbidden, "launch profile is not delegated", "Select an enrolled delegated profile for the original driver.")
	}
	if resolved != nil && *selected != *resolved {
		return api.RunnerPlan{}, api.Injection{}, problem(api.CodeConflict, "resolved launch profile differs from its retained grant member", "Revalidate the original reserved grant set before acquiring credentials.")
	}
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(selected.ExpiresAt))
	if expiryErr != nil || !s.deps.Clock.Now().Before(expires) || selected.Paid && input.budget.SpendMicros <= 0 {
		return api.RunnerPlan{}, api.Injection{}, problem(api.CodeForbidden, "launch profile is expired or outside spend authority", "Retain the current task budget and delegation.")
	}
	if absent(s.deps.Credentials) {
		return api.RunnerPlan{}, api.Injection{}, api.NotImplemented("lb-v2-secrets", "CredentialBroker.Acquire")
	}
	check = "plan_session"
	session, err := execution.runnerSession(ctx, inputs, data)
	if err != nil {
		return api.RunnerPlan{}, api.Injection{}, err
	}
	check = "plan_prompt"
	prompt, err := execution.prompt(ctx, inputs)
	if err != nil {
		return api.RunnerPlan{}, api.Injection{}, err
	}
	check = "plan_credential_slot"
	slot, err := launchStage(ctx, execution, "credential-slot", *selected, func() (api.CredentialSlot, error) {
		// A watchdog handoff already owns this slot. Retain it for cleanup
		// under this reservation without invoking another acquisition.
		if input.slot != nil {
			return *input.slot, nil
		}
		if broker, ok := s.deps.Credentials.(api.LaunchCredentialBroker); ok && !absent(broker) {
			return broker.AcquireLaunch(ctx, api.LaunchProfileRequest{Claim: api.PlanningClaim(r.ID, execution.lease), Target: r.Target, HelperLeaseID: data.LeaseID, Grant: *selected})
		}
		return s.deps.Credentials.Acquire(ctx, r.Target, *selected)
	})
	if err != nil {
		return api.RunnerPlan{}, api.Injection{}, err
	}
	slotEnd, slotErr := time.Parse(time.RFC3339Nano, string(slot.ExpiresAt))
	if !validID(slot.ID) || !validID(slot.LeaseID) || slot.ProfileGrantID != selected.ID || slot.ProfileID != selected.ProfileID ||
		slotErr != nil || !s.deps.Clock.Now().Before(slotEnd) {
		return api.RunnerPlan{}, api.Injection{}, integrity("credential slot differs from the exact delegated profile")
	}
	if r.Mode == "continue" && input.slot == nil {
		keeper, ok := s.deps.Store.(interface {
			KeepContinueSlot(context.Context, api.Scope, api.LaunchPlanRequest, api.CredentialSlot) (api.ContinuationIntent, error)
		})
		if !ok || absent(keeper) {
			return api.RunnerPlan{}, api.Injection{}, api.NotImplemented("lb-v2-store", "KeepContinueSlot")
		}
		kept, err := keeper.KeepContinueSlot(api.WithEffectLease(ctx, execution.lease), execution.scope, api.LaunchPlanRequest{Lease: execution.lease}, slot)
		if err != nil {
			return api.RunnerPlan{}, api.Injection{}, failure(err)
		}
		if kept.Status != "claimed" || kept.OperationID != r.OperationID || kept.Slot == nil || *kept.Slot != slot {
			return api.RunnerPlan{}, api.Injection{}, integrity("continuation did not retain its actual acquired slot")
		}
		execution.input.slot = kept.Slot
	}
	check = "plan_injection"
	injection, err := launchStage(ctx, execution, "injection", inputs.Grants.Secrets, func() (api.Injection, error) {
		if broker, ok := s.deps.Credentials.(api.LaunchCredentialBroker); ok && !absent(broker) {
			return broker.InjectLaunch(ctx, api.LaunchInjectionRequest{Claim: api.PlanningClaim(r.ID, execution.lease), Target: r.Target, HelperLeaseID: data.LeaseID, Grants: inputs.Grants.Secrets})
		}
		return s.deps.Credentials.Inject(ctx, r.Target, inputs.Grants.Secrets)
	})
	if err != nil {
		return api.RunnerPlan{}, api.Injection{}, err
	}
	if injection.Target != r.Target {
		return api.RunnerPlan{}, api.Injection{}, integrity("task injection belongs to another launch")
	}
	matched := false
	for _, id := range injection.SlotIDs {
		matched = matched || id == slot.ID
	}
	if !matched {
		return api.RunnerPlan{}, api.Injection{}, integrity("injection omitted the retained credential slot")
	}
	request := api.RunnerRequest{Target: r.Target, LogicalTurnID: input.turn, Session: session, Prompt: prompt,
		Home: data.Home.Home, Slot: slot, Executable: inputs.Sources.Runtime.Executable,
		Model: input.model, Effort: input.effort, Budget: input.budget}
	runner, err := s.runner(input.driver)
	if err != nil {
		return api.RunnerPlan{}, api.Injection{}, err
	}
	check = "plan_runner_call"
	plan, err := launchStage(ctx, execution, "runner", request, func() (api.RunnerPlan, error) {
		switch r.Mode {
		case "start":
			return runner.Start(ctx, request)
		case "turn":
			return runner.Turn(ctx, request)
		default:
			return runner.Resume(ctx, request)
		}
	})
	if err != nil {
		return api.RunnerPlan{}, api.Injection{}, err
	}
	if plan.Executable != request.Executable || plan.Driver != input.driver || plan.Home != request.Home || plan.Slot != slot ||
		plan.Prompt != prompt || plan.CWD != "/work/main" || plan.Session.HomeID != request.Home.ID ||
		plan.Session.HistoryID != request.Home.HistoryID || plan.Session.Driver != input.driver ||
		plan.Session.ID != session.ID || plan.Session.LogicalCWD != session.LogicalCWD ||
		(input.driver == api.DriverClaudock || input.previous != nil || r.Mode == "adopt") && !reflect.DeepEqual(plan.Session, session) {
		return api.RunnerPlan{}, api.Injection{}, integrity("runner selected an unpinned executable or private session")
	}
	return plan, injection, nil
}
