// Scoped draft.4 consumers. Audit writes are available; provider dispatch still
// requires an authenticated, once-only egress reservation/worker claim.
package judge

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

var _ api.ScopedJudge = (*Service)(nil)

func (s *Service) FitForScope(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.TokenFit, error) {
	started := time.Now()
	ctx, cancel, err := scopedDeadline(ctx, request)
	if err != nil {
		return api.TokenFit{}, err
	}
	defer cancel()
	resolved, err := s.resolveRequest(ctx, scope, request)
	if err != nil {
		return api.TokenFit{}, err
	}
	ctx, finish, err := providerDeadline(ctx, resolved, started)
	if err != nil {
		return api.TokenFit{}, err
	}
	defer finish()
	// Fit performs no provider HTTP or request retention. The protected raw
	// adapter still screens the complete resolved bytes and proves its pins.
	provider, err := s.provider(resolved.Config)
	if err != nil {
		return api.TokenFit{}, err
	}
	return provider.Fit(ctx, resolved)
}

func (s *Service) EvaluateForScope(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.JudgeReply, error) {
	started := time.Now()
	ctx, cancel, err := scopedDeadline(ctx, request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	defer cancel()
	resolved, err := s.resolveRequest(ctx, scope, request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	ctx, finish, err := providerDeadline(ctx, resolved, started)
	if err != nil {
		return api.JudgeReply{}, err
	}
	defer finish()
	provider, err := s.provider(resolved.Config)
	if err != nil {
		return api.JudgeReply{}, err
	}
	worker, ok := provider.(api.JudgeWorker)
	if !ok {
		return api.JudgeReply{}, api.NotImplemented("lb-v2-judge", "judge.worker.egress-lease")
	}
	if readiness, ok := provider.(WorkerReadiness); ok {
		if err := readiness.ReadyForJudge(ctx, resolved.Config); err != nil {
			return api.JudgeReply{}, err
		}
		// Complete screening and fit precede durable egress acquisition. A
		// withheld secret-bearing request must never be retained just to give
		// an unavailable observation a mandatory request reference.
		fit, err := provider.Fit(ctx, resolved)
		if err != nil || !fit.Proved {
			reason := fit.Reason
			if err != nil {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnscored {
					return api.JudgeReply{}, err
				}
				reason = typed.Message
			}
			if reason == "" {
				reason = "complete judge fit is unproved"
			}
			return api.JudgeReply{ID: resolved.ID, Status: "unavailable", Results: []api.Judgment{}, SelectedModel: resolved.Config.Model,
				DeploymentSHA256: resolved.Config.DeploymentSHA256, UnavailableReason: reason}, nil
		}
	}
	store, ok := s.deps.Store.(api.JudgeExecutionStore)
	if !ok {
		return api.JudgeReply{}, api.NotImplemented("lb-v2-service", "judge execution store")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return api.JudgeReply{}, problem(api.CodeDeadline, "judge execution has no total deadline")
	}
	attempt, err := client.NewRequestID()
	if err != nil {
		return api.JudgeReply{}, err
	}
	execution, err := store.ReserveJudgeExecution(ctx, scope, api.JudgeExecutionRequest{Request: resolved, AttemptID: attempt, Deadline: api.Timestamp(deadline.UTC().Format(time.RFC3339Nano))})
	if err != nil {
		return api.JudgeReply{}, err
	}
	if !execution.Acquired {
		if execution.Audit != nil {
			return cloneReply(execution.Audit.Reply), nil
		}
		if recoverer, ok := s.deps.Store.(interface {
			RecoverJudgeExecution(context.Context, api.Scope, api.JudgeExecution) (api.JudgeAudit, error)
		}); ok {
			audit, err := recoverer.RecoverJudgeExecution(ctx, api.Scope{Config: scope.Config, Actor: execution.Intent.Actor,
				PolicyGeneration: resolved.Context.PolicyGeneration, Source: "worker"}, execution)
			if err != nil {
				return api.JudgeReply{}, err
			}
			return cloneReply(audit.Reply), nil
		}
		return api.JudgeReply{}, problem(api.CodeUnavailable, "judge execution is already reserved; its outcome is pending or unknown")
	}
	if execution.AttemptID != attempt {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "judge execution winner differs from its local attempt")
	}
	internal := api.Scope{Config: scope.Config, Actor: execution.Intent.Actor, PolicyGeneration: scope.PolicyGeneration, Source: "worker"}
	if err := store.ValidateJudgeExecution(ctx, internal, execution); err != nil {
		return api.JudgeReply{}, err
	}
	retain := func(ctx context.Context, class string, data []byte) (api.BlobRef, error) {
		if err := store.ValidateJudgeExecution(ctx, internal, execution); err != nil {
			return api.BlobRef{}, err
		}
		return s.deps.Store.RetainObject(ctx, internal, api.RetainObjectRequest{Intent: execution.Intent,
			Object: api.ObjectWrite{ObjectKey: api.ID(wire.Digest([]byte(string(execution.ID) + ":" + class + ":" + string(wire.Digest(data))))),
				Class: class, SHA256: wire.Digest(data), Bytes: bytes.Clone(data), Origin: "service", InputRefs: []api.BlobRef{},
				ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: execution.Intent.Target.LifeID, Audience: "owner", Participants: []api.ID{}, Generation: 1}}})
	}
	reply, fit, err := worker.EvaluateLeased(ctx, execution, retain)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if reply.Request == nil {
		return api.JudgeReply{}, problem(api.CodeUnscored, "judge execution could not retain its exact request")
	}
	audit, err := store.CompleteJudgeExecution(ctx, internal, execution, api.JudgeAudit{ID: resolved.ID, Request: *reply.Request, Reply: reply,
		Fit: fit, StartedAt: execution.ReservedAt, CompletedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))})
	if err != nil {
		return api.JudgeReply{}, err
	}
	return cloneReply(audit.Reply), nil
}

func providerDeadline(ctx context.Context, request api.JudgeRequest, started time.Time) (context.Context, context.CancelFunc, error) {
	limit := request.Config.CommandDeadlineMS
	if request.Purpose == "guidance" {
		limit = request.Config.GuidanceDeadlineMS
	}
	bounded, cancel := context.WithDeadline(ctx, started.Add(time.Duration(min(limit, request.DeadlineMS))*time.Millisecond))
	if err := bounded.Err(); err != nil {
		cancel()
		code := api.CodeCancelled
		if err == context.DeadlineExceeded {
			code = api.CodeDeadline
		}
		return nil, nil, problem(code, "scoped judge budget ended")
	}
	return bounded, cancel, nil
}

func scopedDeadline(ctx context.Context, request api.JudgeRequest) (context.Context, context.CancelFunc, error) {
	if request.DeadlineMS < 1 || request.DeadlineMS > int64((1<<63-1)/time.Millisecond) {
		return nil, nil, problem(api.CodeInvalid, "invalid scoped judge deadline")
	}
	maximum := int64(2000)
	if request.Purpose == "guidance" {
		maximum = 5000
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(min(request.DeadlineMS, maximum))*time.Millisecond)
	return bounded, cancel, nil
}

func (s *Service) resolveTask(ctx context.Context, scope api.Scope, request *api.JudgeRequest) error {
	turn, err := s.deps.Store.Turn(ctx, scope, request.Context.Target, request.Context.LogicalTurnID)
	if err != nil {
		return err
	}
	if turn.Target != request.Context.Target || turn.LogicalTurnID != request.Context.LogicalTurnID ||
		turn.PolicyGeneration == 0 || turn.PolicyGeneration > request.Context.PolicyGeneration || turn.Generation == 0 ||
		!wire.ValidID(turn.Task.ID) || !wire.ValidDigest(turn.Task.SHA256) || turn.Task.Bytes < 0 {
		return problem(api.CodeConflict, "judge turn/task snapshot differs")
	}
	if turn.Task.Bytes > api.MaxJudgeBytes {
		return problem(api.CodeUnscored, "complete task exceeds judge bound")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, turn.Task.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != turn.Task || metadata.ACL.Config != scope.Config ||
		metadata.ACL.LifeID != "" && metadata.ACL.LifeID != turn.Target.LifeID {
		return problem(api.CodeIntegrity, "judge task metadata differs")
	}
	chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: turn.Task.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		return err
	}
	if chunk.ObjectID != turn.Task.ID || chunk.Offset != 0 || int64(len(chunk.Data)) != turn.Task.Bytes ||
		wire.Digest(chunk.Data) != turn.Task.SHA256 || chunk.SHA256 != turn.Task.SHA256 {
		return problem(api.CodeIntegrity, "judge task bytes differ")
	}
	if len(request.Task) != 0 && !bytes.Equal(request.Task, chunk.Data) {
		return problem(api.CodeForbidden, "judge task claim differs")
	}
	request.Task = bytes.Clone(chunk.Data)
	return nil
}

func (s *Service) resolveQuestions(ctx context.Context, scope api.Scope, policy api.EffectivePolicy, request *api.JudgeRequest) error {
	if request.Purpose == "blacklist" {
		if len(request.Decisions) != 0 {
			return problem(api.CodeForbidden, "blacklist contains decisions")
		}
		for _, question := range request.Rules {
			found := false
			for _, rule := range policy.Rules {
				if question == (api.JudgeRule{ID: rule.ID, Text: rule.Text, SourceSHA256: rule.Source.SHA256, CriteriaVersion: wire.CriteriaVersion}) {
					found = true
					break
				}
			}
			if !found {
				return problem(api.CodeForbidden, "judge rule is not authoritative")
			}
		}
		return nil
	}
	if len(request.Rules) != 0 {
		return problem(api.CodeForbidden, "guidance contains blacklist rules")
	}
	remaining := make(map[api.ID]api.DecisionCandidate, len(request.Decisions))
	for _, decision := range request.Decisions {
		if _, duplicate := remaining[decision.ID]; duplicate {
			return problem(api.CodeInvalid, "duplicate scoped decision")
		}
		remaining[decision.ID] = decision
	}
	var snapshot api.ID
	for _, kind := range []string{"binding", "reminder"} {
		cursor := ""
		for pageNumber := 0; pageNumber < 256 && len(remaining) > 0; pageNumber++ {
			page, err := s.deps.Store.DecisionCandidates(ctx, scope, api.DecisionQuery{Target: request.Context.Target, SnapshotID: snapshot, Kind: kind, Cursor: cursor, Limit: 128})
			if err != nil {
				return err
			}
			if page.SnapshotID == "" || page.PolicyGeneration != policy.Generation || snapshot != "" && snapshot != page.SnapshotID {
				return problem(api.CodeConflict, "judge decision snapshot changed")
			}
			snapshot = page.SnapshotID
			for _, actual := range page.Candidates {
				if supplied, ok := remaining[actual.ID]; ok {
					if actual.Authority.Kind == "" || !wire.ValidID(actual.Authority.ReceiptID) || actual.Authority.SourceSeq == 0 {
						return problem(api.CodeIntegrity, "judge decision authority is absent")
					}
					if !reflect.DeepEqual(supplied, actual) {
						return problem(api.CodeForbidden, "judge decision authority differs")
					}
					delete(remaining, actual.ID)
				}
			}
			if page.Complete {
				break
			}
			if page.Cursor == "" || page.Cursor == cursor {
				return problem(api.CodeIntegrity, "judge decision cursor stalled")
			}
			cursor = page.Cursor
			if pageNumber == 255 {
				return problem(api.CodeUnscored, "judge decision scan bound reached")
			}
		}
	}
	if len(remaining) != 0 {
		return problem(api.CodeForbidden, "judge decision is not applicable")
	}
	return nil
}
