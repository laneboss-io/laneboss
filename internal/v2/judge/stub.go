// Package judge is owned by lb-v2-judge.
package judge

import (
	"context"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type Dependencies struct {
	Clef     api.Judge
	TypeSafe api.Judge
	Store    api.StateStore
	Clock    api.Clock
}

type Service struct {
	deps Dependencies
}

func New(deps Dependencies) (*Service, error) {
	if wire.Nil(deps.Store) || wire.Nil(deps.Clock) || wire.Nil(deps.Clef) {
		return nil, problem(api.CodePrerequisite, "judge dependencies are unavailable")
	}
	return &Service{deps: deps}, nil
}

// Only the resolved approved policy selects a port. An absent alternative or
// an unavailable selected provider never permits a call to the other port.
func (s *Service) provider(config api.JudgeConfig) (api.Judge, error) {
	var provider api.Judge
	switch config.Provider {
	case api.DefaultJudgeProvider:
		provider = s.deps.Clef
	case "typesafe":
		provider = s.deps.TypeSafe
	default:
		return nil, problem(api.CodeInvalid, "unknown approved judge provider")
	}
	if wire.Nil(provider) {
		return nil, problem(api.CodePrerequisite, "approved judge provider is unavailable")
	}
	return provider, nil
}

var _ api.JudgeAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if wire.Nil(registry) {
		return problem(api.CodeInvalid, "judge registry is unavailable")
	}
	if err := registry.Register("judge.ask", handler(DecodeAskInput, s.JudgeAsk)); err != nil {
		return err
	}
	return registry.Register("judge.list", handler(DecodeListInput, s.JudgeList))
}

func problem(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-judge",
		Instead: "Repair the named judge prerequisite through the supervisor."}
}

func handler[P, R any](decode func(json.RawMessage) (P, error), run func(context.Context, api.Scope, P) (R, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		params, err := decode(raw)
		if err != nil {
			return nil, err
		}
		result, err := run(ctx, scope, params)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
}

func authenticated(ctx context.Context, scope api.Scope, now time.Time) error {
	if scope.Config == "" || !wire.ValidID(scope.Actor.ID) || scope.EndpointGeneration == 0 {
		return problem(api.CodeUnauthenticated, "judge requires an authenticated scope")
	}
	if wire.Nil(scope.Connection) || wire.Nil(scope.Frame) {
		return problem(api.CodeUnauthenticated, "judge connection is unavailable")
	}
	if !wire.ValidID(scope.Connection.ID()) || wire.Nil(scope.Connection.Conn()) || wire.Nil(scope.Connection.Peer()) {
		return problem(api.CodeUnauthenticated, "judge connector lifetime is unavailable")
	}
	if err := scope.Connection.Peer().Alive(ctx); err != nil {
		return err
	}
	binding := scope.Connection.Binding()
	if binding.Config != scope.Config || binding.EndpointGeneration != scope.EndpointGeneration ||
		binding.ContractRevision != api.ContractRevision || binding.Protocol != api.Protocol || binding.APISchema != api.SchemaVersion {
		return problem(api.CodeUnauthenticated, "judge connection binding differs")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return err
	}
	if binding.Class == api.EndpointHuman {
		if scope.Actor.Kind != "human" || scope.Actor.LifeID != "" {
			return problem(api.CodeForbidden, "judge human scope differs")
		}
		authority, err := scope.Connection.ReadAuthority(ctx)
		if err != nil {
			return err
		}
		idle, idleErr := time.Parse(time.RFC3339Nano, string(authority.IdleExpiresAt))
		absolute, absoluteErr := time.Parse(time.RFC3339Nano, string(authority.ExpiresAt))
		if authority.PrincipalID != scope.Actor.ID || authority.Config != scope.Config ||
			authority.EndpointGeneration != scope.EndpointGeneration || !wire.ValidID(authority.SessionID) ||
			!wire.ValidID(authority.CredentialID) || idleErr != nil || absoluteErr != nil ||
			!now.Before(idle) || !now.Before(absolute) {
			return problem(api.CodeUnauthenticated, "judge human read authority differs")
		}
	} else if binding.Class != api.EndpointLane || binding.Target == nil ||
		binding.Target.LifeID != scope.Actor.LifeID || binding.LaunchID != scope.LaunchID {
		return problem(api.CodeForbidden, "judge launch scope differs")
	}
	if scope.Actor.LifeID == "" && scope.Actor.Kind != "human" {
		return problem(api.CodeForbidden, "judge requires a life or verified human scope")
	}
	return nil
}

func (s *Service) JudgeAsk(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.JudgeReply, error) {
	if err := ValidatePreviewInput(request); err != nil {
		return api.JudgeReply{}, err
	}
	return s.EvaluateForScope(ctx, scope, request)
}

func (s *Service) resolveRequest(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.JudgeRequest, error) {
	if ctx.Err() != nil {
		return api.JudgeRequest{}, problem(api.CodeCancelled, "judge preview cancelled")
	}
	if err := authenticated(ctx, scope, s.deps.Clock.Now()); err != nil {
		return api.JudgeRequest{}, err
	}
	if request.Purpose != "preview" && request.Purpose != "blacklist" && request.Purpose != "guidance" {
		return api.JudgeRequest{}, problem(api.CodeInvalid, "unknown scoped judge purpose")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.JudgeRequest{}, err
	}
	if policy.Generation != scope.PolicyGeneration || policy.Generation == 0 {
		return api.JudgeRequest{}, problem(api.CodeConflict, "judge policy generation changed")
	}
	// Public preview may omit all configuration/context claims. Internal
	// consumers supply the approved snapshot. ResolveJudgeForScope compares
	// both spellings after R108 defaults while preserving every approved pin.
	pinRequest := request
	if pinRequest.Config == (api.JudgeConfig{}) && request.Purpose == "preview" {
		pinRequest.Config = policy.Judge
	}
	if pinRequest.Context.PolicyGeneration == 0 && request.Purpose == "preview" {
		pinRequest.Context.PolicyGeneration = scope.PolicyGeneration
	}
	approved, err := api.ResolveJudgeForScope(scope, pinRequest, policy)
	if err != nil {
		return api.JudgeRequest{}, err
	}
	if err := wire.ValidateConfig(approved); err != nil {
		return api.JudgeRequest{}, err
	}
	target := request.Context.Target
	if scope.Actor.LifeID != "" {
		if target.LifeID != "" && target.LifeID != scope.Actor.LifeID {
			return api.JudgeRequest{}, problem(api.CodeForbidden, "judge preview cannot select another life")
		}
		target.LifeID = scope.Actor.LifeID
	}
	lane, err := s.deps.Store.Lane(ctx, scope, target)
	if err != nil {
		return api.JudgeRequest{}, err
	}
	if lane.LifeID != target.LifeID || target.Run != 0 && target.Run != lane.Run ||
		lane.PolicyGeneration == 0 || lane.PolicyGeneration > policy.Generation || lane.Generation == 0 || lane.Cleaned {
		return api.JudgeRequest{}, problem(api.CodeConflict, "judge target is stale or unavailable")
	}
	if binding := scope.Connection.Binding(); binding.Class == api.EndpointLane &&
		(binding.Target.Run != lane.Run || binding.LaunchID != lane.LaunchID) {
		return api.JudgeRequest{}, problem(api.CodeConflict, "judge bound run changed")
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return api.JudgeRequest{}, err
	}
	expiry, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if err != nil || grants.Revoked || !s.deps.Clock.Now().Before(expiry) ||
		grants.LifeID != lane.LifeID || grants.ID != lane.GrantSetID ||
		grants.PolicyGeneration == 0 || grants.PolicyGeneration > policy.Generation || grants.Generation == 0 ||
		!wire.ValidDigest(grants.SHA256) {
		return api.JudgeRequest{}, problem(api.CodeForbidden, "judge grants are unavailable or revoked")
	}
	resolved := api.JudgeContext{Config: scope.Config,
		Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run},
		Role: api.RoleContext{Level: lane.Level, Role: lane.Role,
			InstanceID: policy.Context.InstanceID}, LogicalTurnID: lane.LogicalTurnID,
		GrantSetID: grants.ID, GrantsSHA256: grants.SHA256,
		PolicyGeneration: policy.Generation, CWD: lane.Workspace.LogicalCWD}
	if policy.Context.Level != resolved.Role.Level || policy.Context.Role != resolved.Role.Role {
		return api.JudgeRequest{}, problem(api.CodeIntegrity, "judge policy scope disagrees with live role")
	}
	supplied := request.Context
	supplied.Config, supplied.Target = "", api.LifeRef{}
	if supplied != (api.JudgeContext{}) && request.Context != resolved {
		return api.JudgeRequest{}, problem(api.CodeForbidden, "judge context cannot override live scope")
	}
	if request.Context.Config != "" && request.Context.Config != scope.Config {
		return api.JudgeRequest{}, problem(api.CodeForbidden, "judge configuration binding differs")
	}
	request.Context, request.Config = resolved, approved
	if request.Purpose == "preview" {
		request.Rules = make([]api.JudgeRule, 0, len(policy.Rules))
		request.Decisions = []api.DecisionCandidate{}
		for _, rule := range policy.Rules {
			request.Rules = append(request.Rules, api.JudgeRule{ID: rule.ID, Text: rule.Text,
				SourceSHA256: rule.Source.SHA256, CriteriaVersion: wire.CriteriaVersion})
		}
	} else if err := s.resolveQuestions(ctx, scope, policy, &request); err != nil {
		return api.JudgeRequest{}, err
	}
	if err := s.resolveTask(ctx, scope, &request); err != nil {
		return api.JudgeRequest{}, err
	}
	if _, _, err := wire.Payload(request); err != nil {
		return api.JudgeRequest{}, err
	}
	return request, nil
}

func (s *Service) JudgeList(ctx context.Context, scope api.Scope, request api.Empty) (api.ConfigView, error) {
	if ctx.Err() != nil {
		return api.ConfigView{}, problem(api.CodeCancelled, "judge list cancelled")
	}
	if err := authenticated(ctx, scope, s.deps.Clock.Now()); err != nil {
		return api.ConfigView{}, err
	}
	if _, err := s.deps.Store.Policy(ctx, scope); err != nil {
		return api.ConfigView{}, err
	}
	projection, ok := s.deps.Store.(api.JudgeViewStore)
	if !ok {
		return api.ConfigView{}, api.NotImplemented("lb-v2-judge", "judge.config-projection")
	}
	return projection.JudgeView(ctx, scope)
}
