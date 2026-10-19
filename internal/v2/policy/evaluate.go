package policy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

type evaluationInput struct {
	Schema            string                    `json:"schema"`
	StartedAt         api.Timestamp             `json:"started_at"`
	Request           api.PolicyEvaluateRequest `json:"request"`
	WireParams        []byte                    `json:"wire_params"`
	Context           api.JudgeContext          `json:"context"`
	Policy            api.EffectivePolicy       `json:"policy"`
	OrgSnapshot       api.OrgSnapshotRef        `json:"org_snapshot"`
	Turn              api.TurnSnapshot          `json:"turn"`
	RuleSetSHA256     api.Digest                `json:"rule_set_sha256"`
	ContextSHA256     api.Digest                `json:"context_sha256"`
	SkipContextSHA256 api.Digest                `json:"skip_context_sha256"`
	CostLimitMicros   int64                     `json:"cost_limit_micros"`
	DeadlineMS        int64                     `json:"deadline_ms"`
	Batches           []batchObservation        `json:"batches"`
}

type batchObservation struct {
	Request    api.JudgeRequest  `json:"request"`
	Fit        *api.TokenFit     `json:"fit,omitempty"`
	Reply      *api.JudgeReply   `json:"reply,omitempty"`
	Nonfinite  map[api.ID]string `json:"nonfinite,omitempty"`
	UsageKnown bool              `json:"usage_known"`
	Error      string            `json:"error,omitempty"`
}

func newID(prefix string) (api.ID, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", &api.Error{Code: api.CodeUnavailable, Message: "policy receipt entropy unavailable",
			Instead: "Repair the service entropy source before retrying."}
	}
	return api.ID(prefix + "-" + hex.EncodeToString(bytes[:])), nil
}

func validateCommand(command api.CommandData) error {
	if !textOK(command.Tool, 256) || command.Command == nil || command.Argv == nil || command.DeclaredPaths == nil ||
		!textOK(command.CWD, maxTextBytes) || !path.IsAbs(command.CWD) ||
		len(command.Command) > api.MaxFrameBytes || !validDigest(command.RawSHA256) || digestBytes(command.Command) != command.RawSHA256 {
		return invalid("invalid command data or raw byte digest")
	}
	total := len(command.Command) + len(command.CWD) + len(command.Tool)
	for _, arguments := range [][]string{command.Argv, command.DeclaredPaths} {
		if len(arguments) > api.MaxFrameBytes {
			return invalid("command argument count exceeds bound")
		}
		for _, value := range arguments {
			if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return invalid("invalid command argument bytes")
			}
			total += len(value) + 3
		}
	}
	if total > api.MaxFrameBytes {
		return invalid("command data exceeds byte bound")
	}
	return nil
}

// ValidateCommandInput checks all locally available command data before a CLI
// adapter resolves a missing target through the service.
func ValidateCommandInput(command api.CommandData) error {
	if err := validateCommand(command); err != nil {
		var typed *api.Error
		if errors.As(err, &typed) {
			copy := *typed
			copy.Owner = "lb-v2-policy"
			return &copy
		}
		return err
	}
	return nil
}

// ValidateEvaluateSelection permits missing fields only for the ergonomic
// adapter's local preflight. Supplied fields always receive the same checks.
func ValidateEvaluateSelection(target api.LifeRef, turn api.ID, allowMissing bool) error {
	if (!allowMissing && (target.LifeID == "" || target.Run == 0 || turn == "")) ||
		(target.LifeID != "" && !validID(target.LifeID)) || target.Run > 1<<53-1 || (turn != "" && !validID(turn)) {
		return inputInvalid("current target run and logical turn are required")
	}
	return nil
}

// ValidateEvaluateInput is shared by the service and the CLI's method-owned
// local validator. It validates data, never caller authority or membership.
func ValidateEvaluateInput(request api.PolicyEvaluateRequest) error {
	if err := ValidateCommandInput(request.Command); err != nil {
		return err
	}
	return ValidateEvaluateSelection(request.Target, request.LogicalTurnID, false)
}

func (s *Service) evaluationContext(ctx context.Context, scope api.Scope, request api.PolicyEvaluateRequest, policy api.EffectivePolicy) (api.JudgeContext, api.Lane, api.GrantSet, error) {
	var empty api.JudgeContext
	if scope.Actor.Kind == "lane" && request.Target.LifeID != scope.Actor.LifeID {
		return empty, api.Lane{}, api.GrantSet{}, forbiddenTarget()
	}
	lane, err := s.deps.Store.Lane(ctx, scope, request.Target)
	if err != nil {
		return empty, lane, api.GrantSet{}, err
	}
	if lane.LifeID != request.Target.LifeID || lane.Run != request.Target.Run || lane.Cleaned ||
		lane.LogicalTurnID != request.LogicalTurnID || lane.Level != policy.Context.Level || lane.Role != policy.Context.Role {
		return empty, lane, api.GrantSet{}, conflict("evaluation life, run or logical turn changed")
	}
	launchID := scope.LaunchID
	if scope.Actor.Kind == "human" {
		launchID = lane.LaunchID
	}
	launch, err := s.deps.Store.Launch(ctx, launchID)
	if err != nil {
		return empty, lane, api.GrantSet{}, err
	}
	if launch.Revoked || launch.ID != launchID || launch.Config != scope.Config || launch.Target != request.Target ||
		launch.GrantSetID != lane.GrantSetID || launch.Actor.Kind != "lane" || launch.Actor.LifeID != lane.LifeID ||
		launch.PolicyGeneration == 0 || launch.PolicyGeneration > policy.Generation ||
		launch.Actor.Level != lane.Level || launch.Actor.Role != lane.Role ||
		(scope.Actor.Kind == "lane" && (launch.Actor != scope.Actor || launch.EndpointGeneration != scope.EndpointGeneration)) {
		return empty, lane, api.GrantSet{}, forbiddenTarget()
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return empty, lane, grants, err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if err != nil || grants.ID != lane.GrantSetID || grants.LifeID != lane.LifeID || grants.Revoked ||
		grants.PolicyGeneration == 0 || grants.PolicyGeneration > policy.Generation ||
		!validDigest(grants.SHA256) || !s.deps.Clock.Now().Before(expires) {
		return empty, lane, grants, forbiddenTarget()
	}
	return api.JudgeContext{
		Config: scope.Config, Target: request.Target, Role: policy.Context,
		LogicalTurnID: request.LogicalTurnID, GrantSetID: grants.ID,
		GrantsSHA256: grants.SHA256, PolicyGeneration: policy.Generation, CWD: request.Command.CWD,
	}, lane, grants, nil
}

// ContextDigest deliberately performs no shell normalization. Exact bytes,
// quoted argv, tool and declared paths remain data; no expansions are executed.
// The service-owned grant/endpoint/life generations prevent semantic cache reuse
// from standing in for fresh authorization.
func ContextDigest(scope api.Scope, request api.PolicyEvaluateRequest, context api.JudgeContext, laneGeneration, grantGeneration api.Generation, turn api.TurnSnapshot) (api.Digest, error) {
	return digest(struct {
		Version            string                    `json:"version"`
		Actor              api.Actor                 `json:"actor"`
		LaunchID           api.ID                    `json:"launch_id"`
		EndpointGeneration api.Generation            `json:"endpoint_generation"`
		LaneGeneration     api.Generation            `json:"lane_generation"`
		GrantGeneration    api.Generation            `json:"grant_generation"`
		TurnGeneration     api.Generation            `json:"turn_generation"`
		Task               api.BlobRef               `json:"task"`
		Prompt             *api.BlobRef              `json:"prompt,omitempty"`
		Context            api.JudgeContext          `json:"context"`
		Request            api.PolicyEvaluateRequest `json:"request"`
	}{"raw-v2", scope.Actor, scope.LaunchID, scope.EndpointGeneration, laneGeneration, grantGeneration,
		turn.Generation, turn.Task, turn.Prompt, context, request})
}

func (s *Service) PolicyEvaluate(ctx context.Context, scope api.Scope, request api.PolicyEvaluateRequest) (api.PolicyDecision, error) {
	var empty api.PolicyDecision
	started := s.deps.Clock.Now()
	wallStarted := time.Now()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.deps.CommandDeadlineMS)*time.Millisecond)
	defer cancel()
	if err := authenticated(scope); err != nil {
		return empty, err
	}
	if scope.Actor.Kind == "human" {
		verified, err := api.WithReadAuthority(ctx, scope)
		if err != nil {
			return empty, err
		}
		scope = verified
	}
	receipt, err := s.mutation(ctx, scope, request)
	if err != nil {
		return empty, err
	}
	if receipt.Reply != nil {
		return s.replayPolicy(ctx, scope, receipt)
	}
	if err := ValidateEvaluateInput(request); err != nil {
		return empty, err
	}
	policy, snapshot, err := s.getPolicy(ctx, scope, api.PolicyGetRequest{LifeID: request.Target.LifeID}, nil)
	if err != nil {
		return empty, err
	}
	deadlineMS := min(s.deps.CommandDeadlineMS, policy.Judge.CommandDeadlineMS)
	ctx, cancelSnapshot := context.WithDeadline(ctx, wallStarted.Add(time.Duration(deadlineMS)*time.Millisecond))
	defer cancelSnapshot()
	judgeContext, lane, grants, err := s.evaluationContext(ctx, scope, request, policy)
	if err != nil {
		return empty, err
	}
	turn, err := s.deps.Store.Turn(ctx, scope, request.Target, request.LogicalTurnID)
	if err != nil {
		return empty, err
	}
	if turn.Target != request.Target || turn.LogicalTurnID != request.LogicalTurnID || turn.Generation == 0 ||
		turn.Task != lane.Task || !validID(turn.Task.ID) || !validDigest(turn.Task.SHA256) || turn.Task.Bytes <= 0 {
		return empty, conflict("evaluation turn differs from its retained task snapshot")
	}
	limit := s.deps.MaxCostMicros
	if lane.BudgetRemaining.SpendMicros < limit {
		limit = lane.BudgetRemaining.SpendMicros
	}
	if limit < 0 {
		return empty, integrity("negative remaining inference budget")
	}
	// An unfunded request still produces the ordinary protected unscored audit.
	// The judge loop records the zero cap and never starts inference for it.
	// A human preview reads current policy without changing the target's life CAS.
	if scope.Actor.Kind == "lane" {
		lane, err = s.advanceLanePolicy(ctx, scope, lane, policy)
		if err != nil {
			return empty, err
		}
	}
	ruleHash, err := RuleSetDigest(policy)
	if err != nil {
		return empty, err
	}
	contextHash, err := ContextDigest(scope, request, judgeContext, lane.Generation, grants.Generation, turn)
	if err != nil {
		return empty, err
	}
	skipContextHash, err := SkipContextDigest(scope.Config, request.Command, policy)
	if err != nil {
		return empty, err
	}
	cacheKey, err := digest([]api.Digest{policy.SHA256, ruleHash, contextHash})
	if err != nil {
		return empty, err
	}
	id, err := newID("policy")
	if err != nil {
		return empty, err
	}
	input := evaluationInput{
		Schema: "laneboss.policy-input.v2", Request: request,
		StartedAt:  api.Timestamp(started.UTC().Format(time.RFC3339Nano)),
		WireParams: append([]byte{}, scope.Request.Params...), Context: judgeContext,
		Policy: policy, OrgSnapshot: snapshot.OrgSnapshotRef, Turn: turn, RuleSetSHA256: ruleHash, ContextSHA256: contextHash,
		SkipContextSHA256: skipContextHash,
		CostLimitMicros:   limit, DeadlineMS: deadlineMS, Batches: []batchObservation{},
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return empty, integrity("policy input cannot be encoded")
	}
	intent, err := retentionIntent(scope, request.Target, request.LogicalTurnID, receipt.Operation.ID)
	if err != nil {
		return empty, err
	}
	inputs := append(append([]api.BlobRef{}, snapshot.Inputs...), turn.Task)
	inputRef, err := s.put(ctx, scope, intent, "judge_request", inputBytes, inputs)
	if err != nil {
		return empty, err
	}
	decision := api.PolicyDecision{
		ID: id, Result: "allow", Rules: []api.RuleDecision{},
		PolicyGeneration: policy.Generation, Input: inputRef,
	}
	complete := false
	// Source/authorization and input-retention wait count against cache age.
	// Reusing the arrival time would revive a receipt that expired while waiting.
	lookupTime := s.deps.Clock.Now()
	if skip, proof := s.eligibleSkip(policy, ruleHash, skipContextHash, contextHash, lookupTime); skip != "" {
		decision.SkipID = skip
		if proof.ID != "" {
			decision.CacheOf = proof.ID
			decision.Rules = copyDecisions(proof.Rules)
			for i := range decision.Rules {
				decision.Rules[i].Reason = "approved exact-context skip; " + decision.Rules[i].Reason
			}
		}
	} else if cached, hit := s.cached(cacheKey, lookupTime); hit {
		decision.Rules = copyDecisions(cached.Rules)
		decision.Result, decision.CacheOf = cached.Result, cached.ID
	} else {
		deadline := wallStarted.Add(time.Duration(policy.Judge.CommandDeadlineMS) * time.Millisecond)
		if ceiling, _ := ctx.Deadline(); deadline.After(ceiling) {
			deadline = ceiling
		}
		// Leave time inside the total bound for the final protected receipt.
		reserve := min(100*time.Millisecond, time.Duration(deadlineMS)*time.Millisecond/10)
		judgeCtx, stopJudge := context.WithDeadline(ctx, deadline.Add(-reserve))
		decision.Rules, input.Batches, complete, err = s.judge(judgeCtx, scope, input, limit)
		stopJudge()
		if err != nil {
			return empty, err
		}
		decision.Result = aggregate(decision.Rules)
		inputBytes, err = json.Marshal(input)
		if err != nil {
			return empty, integrity("judge observations cannot be encoded")
		}
		intent, writeErr := retentionIntent(scope, request.Target, request.LogicalTurnID, receipt.Operation.ID)
		if writeErr != nil {
			return empty, writeErr
		}
		finalInput, writeErr := s.put(ctx, scope, intent, "judge_request", inputBytes, inputs)
		if writeErr != nil {
			// An absent protected outcome object is not a successful audit. There
			// is no frozen spool port, so report this dependency failure honestly.
			return empty, writeErr
		}
		decision.Input = finalInput
	}
	decision.LatencyMS = elapsedMS(started, s.deps.Clock.Now())
	decision, err = s.audit(ctx, scope, snapshot.OrgSnapshotRef, lane, grants, receipt.Operation.ID, started, decision)
	if err != nil {
		return empty, err
	}
	if complete && decision.AuditComplete && decision.ID == id {
		s.remember(cacheKey, decision, policy.Judge.CacheTTLMS)
		if decision.Result == "allow" {
			proofKey, err := positiveKey(ruleHash, contextHash)
			if err != nil {
				return empty, err
			}
			s.remember(proofKey, decision, policy.Judge.CacheTTLMS)
		}
	}
	return decision, nil
}

func positiveKey(ruleHash, contextHash api.Digest) (api.Digest, error) {
	return digest(struct {
		Version string     `json:"version"`
		Rules   api.Digest `json:"rules"`
		Context api.Digest `json:"context"`
	}{"positive-proof-v1", ruleHash, contextHash})
}

func (s *Service) eligibleSkip(policy api.EffectivePolicy, ruleHash, skipContextHash, contextHash api.Digest, now time.Time) (api.ID, api.PolicyDecision) {
	for _, rule := range policy.Rules {
		if rule.Band == "refuse" && rule.Critical {
			// With no judgment, an applicable critical entry is unresolved.
			return "", api.PolicyDecision{}
		}
	}
	for _, skip := range policy.Skip {
		if skip.RuleSetSHA256 == ruleHash && skip.ContextSHA256 == skipContextHash {
			if len(policy.Rules) == 0 {
				return skip.ID, api.PolicyDecision{}
			}
			key, err := positiveKey(ruleHash, contextHash)
			if err != nil {
				return "", api.PolicyDecision{}
			}
			proof, found := s.cached(key, now)
			if found && proof.AuditComplete && proof.Result == "allow" && len(proof.Rules) == len(policy.Rules) {
				for _, decision := range proof.Rules {
					if decision.Result != "allow" || decision.Probability == nil {
						return "", api.PolicyDecision{}
					}
				}
				return skip.ID, proof
			}
		}
	}
	return "", api.PolicyDecision{}
}

func (s *Service) judge(ctx context.Context, scope api.Scope, input evaluationInput, remaining int64) ([]api.RuleDecision, []batchObservation, bool, error) {
	rules := input.Policy.Rules
	decisions, observations := []api.RuleDecision{}, []batchObservation{}
	complete := true
	blockedBudget := ""
	if len(rules) > 0 && s.deps.Judge == nil {
		return nil, nil, false, api.NotImplemented("lb-v2-judge", "policy judge dependency")
	}
	judgeConfig, err := api.ResolveJudgeConfig(input.Policy.Judge)
	if err != nil {
		return nil, nil, false, err
	}
	for offset := 0; offset < len(rules); {
		end := min(offset+input.Policy.Judge.MaxQuestions, len(rules))
		batch := rules[offset:end]
		id, err := newID("judge")
		if err != nil {
			return nil, nil, false, err
		}
		request := api.JudgeRequest{
			ID: id, Purpose: "blacklist", Rules: []api.JudgeRule{},
			Command: &input.Request.Command, Decisions: []api.DecisionCandidate{},
			Context: input.Context, Task: []byte{}, Config: judgeConfig,
			DeadlineMS: input.Policy.Judge.CommandDeadlineMS, MaxCostMicros: remaining,
		}
		if deadline, bounded := ctx.Deadline(); bounded {
			request.DeadlineMS = max(0, time.Until(deadline).Milliseconds())
		}
		for _, rule := range batch {
			request.Rules = append(request.Rules, api.JudgeRule{
				ID: rule.ID, Text: rule.Text, SourceSHA256: rule.Source.SHA256,
				CriteriaVersion: "blacklist-v1-" + string(rule.Thresholds.CalibrationID),
			})
		}
		request.Config, err = api.ResolveJudgeForScope(scope, request, input.Policy)
		if err != nil {
			return nil, nil, false, err
		}
		observation := batchObservation{Request: request}
		reason := ""
		if remaining <= 0 {
			reason = "budget_exhausted"
			if blockedBudget != "" {
				reason = blockedBudget
			}
		} else if ctx.Err() != nil {
			reason = "deadline_exceeded"
		} else if !utf8.Valid(input.Request.Command.Command) {
			reason = "command_not_utf8"
		} else {
			fit, fitErr := s.deps.Judge.FitForScope(ctx, scope, request)
			if isStub(fitErr) {
				return nil, nil, false, fitErr
			}
			if scopedJudgeRefusal(fitErr) {
				return nil, nil, false, fitErr
			}
			observation.Fit = &fit
			if fitErr != nil {
				reason = errorReason(fitErr)
				if fit == (api.TokenFit{}) {
					observation.Fit = nil
				}
			} else if !fit.Proved || fit.InputBytes <= 0 || fit.InputBytes > request.Config.MaxBytes ||
				fit.InputTokens <= 0 || fit.InputTokens > request.Config.ContextTokens ||
				fit.ContextTokens != request.Config.ContextTokens || fit.TokenizerSHA256 != request.Config.TokenizerSHA256 {
				reason = "token_fit_unproved"
			} else if ctx.Err() != nil {
				reason = errorReason(ctx.Err())
			} else {
				reply, evalErr := s.deps.Judge.EvaluateForScope(ctx, scope, request)
				if isStub(evalErr) {
					return nil, nil, false, evalErr
				}
				if scopedJudgeRefusal(evalErr) {
					return nil, nil, false, evalErr
				}
				observation.Reply = &reply
				if evalErr != nil {
					reason = errorReason(evalErr)
					if reply.ID == "" && reply.Raw == nil {
						observation.Reply = nil
					}
				} else if ctx.Err() != nil {
					reason = errorReason(ctx.Err())
				} else {
					reason = invalidReply(request, fit, reply)
				}
				if reason == "" {
					observation.UsageKnown = true
					remaining -= reply.CostMicros
				} else {
					// A failed/partial call may have consumed its reservation. Do
					// not infer zero spend and issue another batch against that cap.
					remaining = 0
					blockedBudget = "budget_reservation_unknown"
				}
			}
		}
		if reason != "" {
			complete = false
			observation.Error = reason
			for _, rule := range batch {
				decisions = append(decisions, unscored(rule, reason))
			}
		} else {
			answers := map[api.ID]api.Judgment{}
			for _, answer := range observation.Reply.Results {
				answers[answer.QuestionID] = answer
			}
			for _, rule := range batch {
				decisions = append(decisions, scored(rule, answers[rule.ID], observation.Reply.ID))
			}
		}
		if observation.Reply != nil {
			// Nonfinite Go values cannot be serialized as JSON numbers. Keep the
			// rejection explicit and retain their exact symbolic values separately;
			// the provider's protected Raw object remains the original wire evidence.
			reply := *observation.Reply
			reply.Results = append([]api.Judgment{}, reply.Results...)
			for i, answer := range reply.Results {
				if answer.Probability != nil && (math.IsNaN(*answer.Probability) || math.IsInf(*answer.Probability, 0)) {
					if observation.Nonfinite == nil {
						observation.Nonfinite = map[api.ID]string{}
					}
					observation.Nonfinite[answer.QuestionID] = strconv.FormatFloat(*answer.Probability, 'g', -1, 64)
					reply.Results[i].Probability = nil
					reply.Results[i].Status = "unscored"
				}
			}
			observation.Reply = &reply
		}
		observations = append(observations, observation)
		offset = end
	}
	return decisions, observations, complete, nil
}

func invalidReply(request api.JudgeRequest, fit api.TokenFit, reply api.JudgeReply) string {
	if !validID(reply.ID) || reply.Status != "scored" || len(reply.Results) != len(request.Rules) ||
		reply.SelectedModel != request.Config.Model || reply.DeploymentSHA256 != request.Config.DeploymentSHA256 ||
		!textOK(reply.ReportedModel, 256) || reply.InputBytes != fit.InputBytes || reply.InputTokens != fit.InputTokens ||
		reply.LatencyMS < 0 || reply.CostMicros < 0 || reply.CostMicros > request.MaxCostMicros {
		return "unscored_or_invalid_reply"
	}
	questions := map[api.ID]bool{}
	for _, rule := range request.Rules {
		questions[rule.ID] = true
	}
	for _, answer := range reply.Results {
		if !questions[answer.QuestionID] || answer.Status != "scored" || answer.Probability == nil ||
			!finiteProbability(*answer.Probability) || !textOK(answer.Reason, maxTextBytes) {
			return "invalid_probability_mapping"
		}
		delete(questions, answer.QuestionID)
	}
	if len(questions) != 0 {
		return "incomplete_probability_mapping"
	}
	return ""
}

func baseDecision(rule api.Rule, result, reason string) api.RuleDecision {
	return api.RuleDecision{RuleID: rule.ID, Result: result, Critical: rule.Critical,
		Thresholds: rule.Thresholds, Reason: reason, Instead: rule.Instead}
}

func unscored(rule api.Rule, reason string) api.RuleDecision {
	result := "allow"
	if rule.Critical && rule.Band == "refuse" {
		result = "refuse"
	}
	return baseDecision(rule, result, "unscored: "+reason)
}

func scored(rule api.Rule, answer api.Judgment, judgmentID api.ID) api.RuleDecision {
	probability := *answer.Probability
	result := "allow"
	if probability >= rule.Thresholds.Match && rule.Band == "refuse" {
		result = "refuse"
	} else if probability >= DefaultWarnThreshold || probability >= rule.Thresholds.Match {
		result = "warn"
	}
	// Provider explanations can quote secret-bearing command data. Keep the
	// original explanation in the protected input object, and put only the
	// policy classification and actual numeric score in the event/projection.
	reason := "no scored blacklist match"
	if result == "refuse" {
		reason = "scored blacklist match"
	} else if result == "warn" {
		reason = "scored membership warning"
	}
	if probability >= rule.Thresholds.UncertainLow && probability <= rule.Thresholds.UncertainHigh {
		reason = "uncertain scored probability; " + reason
	}
	decision := baseDecision(rule, result, reason)
	decision.Probability, decision.JudgmentID = &probability, judgmentID
	return decision
}

func aggregate(decisions []api.RuleDecision) string {
	result := "allow"
	for _, decision := range decisions {
		if decision.Result == "refuse" {
			return "refuse"
		}
		if decision.Result == "warn" {
			result = "warn"
		}
	}
	return result
}

func isStub(err error) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed.Code == api.CodeNotImplemented
}

func scopedJudgeRefusal(err error) bool {
	var typed *api.Error
	if !errors.As(err, &typed) {
		return false
	}
	switch typed.Code {
	case api.CodeInvalid, api.CodeNotFound:
		// Invalid requests and missing approved providers are integration failures,
		// not provider outages. Preserve the judge's exact typed recovery route.
		return true
	case api.CodeUnauthenticated, api.CodeForbidden, api.CodeConflict, api.CodeIntegrity, api.CodeVersion, api.CodePrerequisite:
		// These report a rejected scope/policy/provider selection. They are not
		// inference outages from which an ordinary unscored allow is derived.
		return true
	}
	return false
}

func errorReason(err error) string {
	var typed *api.Error
	if errors.As(err, &typed) {
		switch typed.Code {
		case api.CodeInvalid, api.CodeUnauthenticated, api.CodeForbidden, api.CodeNotFound,
			api.CodeConflict, api.CodeIdempotencyConflict, api.CodeVersion,
			api.CodeUnavailable, api.CodePrerequisite, api.CodeUnsupported, api.CodeIntegrity,
			api.CodeBudget, api.CodeUnscored, api.CodeCursorExpired, api.CodeContainmentUnknown,
			api.CodeCancelled, api.CodeDeadline:
			return string(typed.Code)
		default:
			return "judge_unavailable"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "judge_unavailable"
}

func elapsedMS(start, end time.Time) int64 {
	if end.Before(start) {
		return 0
	}
	return end.Sub(start).Milliseconds()
}

func copyDecisions(source []api.RuleDecision) []api.RuleDecision {
	result := append([]api.RuleDecision{}, source...)
	for i := range result {
		if result[i].Probability != nil {
			value := *result[i].Probability
			result[i].Probability = &value
		}
	}
	return result
}

func (s *Service) cached(key api.Digest, now time.Time) (api.PolicyDecision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.cache[key]
	if !found || now.Before(entry.created) || !now.Before(entry.expires) {
		delete(s.cache, key)
		return api.PolicyDecision{}, false
	}
	return entry.decision, true
}

func (s *Service) remember(key api.Digest, decision api.PolicyDecision, ttlMS int64) {
	if ttlMS == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.deps.Clock.Now()
	for key, entry := range s.cache {
		if !now.Before(entry.expires) || now.Before(entry.created) {
			delete(s.cache, key)
		}
	}
	// Bound process memory; eviction only causes a fresh judgment.
	if len(s.cache) >= 1024 {
		for candidate := range s.cache {
			delete(s.cache, candidate)
			break
		}
	}
	decision.Rules = copyDecisions(decision.Rules)
	s.cache[key] = cacheEntry{decision: decision, created: now, expires: now.Add(time.Duration(ttlMS) * time.Millisecond)}
}
