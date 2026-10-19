package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Store api.StateStore
	Judge api.ScopedJudge
	Clock api.Clock
	// ValidateSources validates the complete canonical configuration/source
	// generation. An effective blacklist alone cannot prove unrelated runner,
	// role-library, project or resource source files valid.
	ValidateSources func(context.Context, api.Scope, api.OrgValidateRequest) (api.OrgValidation, error)
	// MaxCostMicros is an org-approved inference ceiling, additionally bounded
	// by the current lane's remaining spend. Strict New requires a positive
	// approved ceiling. NewInstalled records unfunded calls as unscored audits.
	MaxCostMicros int64
	// CommandDeadlineMS bounds the initial source/store read as well as judging
	// and retention. The composition root supplies the current approved service
	// ceiling on reload. A rule snapshot may further tighten this ceiling.
	CommandDeadlineMS int64
}

type cacheEntry struct {
	decision api.PolicyDecision
	created  time.Time
	expires  time.Time
}

type Service struct {
	deps  Dependencies
	mu    sync.Mutex
	cache map[api.Digest]cacheEntry
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func New(deps Dependencies) (*Service, error) {
	if deps.Store == nil {
		return nil, api.NotImplemented("lb-v2-service", "policy store dependency")
	}
	if deps.MaxCostMicros <= 0 {
		return nil, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-integrate",
			Message: "policy inference cost ceiling is not configured",
			Instead: "Supply the positive org-approved policy inference ceiling at service assembly."}
	}
	if deps.CommandDeadlineMS == 0 {
		deps.CommandDeadlineMS = 2000
	}
	if deps.CommandDeadlineMS < 1 || deps.CommandDeadlineMS > 60000 {
		return nil, invalid("invalid policy command deadline")
	}
	if deps.Clock == nil {
		deps.Clock = wallClock{}
	}
	return &Service{deps: deps, cache: make(map[api.Digest]cacheEntry)}, nil
}

// NewInstalled enables host startup and policy reads before an approved
// inference ceiling exists. It grants no inference budget: PolicyEvaluate
// records unscored decisions without starting inference when the cap is zero.
// New retains its strict fully configured constructor contract.
func NewInstalled(deps Dependencies) (*Service, error) {
	if err := api.RequireDependencies("lb-v2-policy", deps.Store, deps.Judge, deps.Clock); err != nil {
		return nil, err
	}
	if deps.MaxCostMicros < 0 {
		return nil, invalid("negative installed inference ceiling")
	}
	if deps.CommandDeadlineMS == 0 {
		deps.CommandDeadlineMS = 2000
	}
	if deps.CommandDeadlineMS < 1 || deps.CommandDeadlineMS > 60000 {
		return nil, invalid("invalid policy command deadline")
	}
	return &Service{deps: deps, cache: make(map[api.Digest]cacheEntry)}, nil
}

var _ api.PolicyAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func authenticated(scope api.Scope) error {
	if !validID(api.ID(scope.Config)) || !validID(scope.Actor.ID) || scope.EndpointGeneration == 0 {
		return &api.Error{Code: api.CodeUnauthenticated, Message: "authenticated configuration scope required",
			Instead: "Use the installed bound CLI through its authenticated endpoint."}
	}
	switch scope.Actor.Kind {
	case "lane":
		if !validID(scope.Actor.LifeID) || !validID(scope.LaunchID) ||
			!validRole(api.RoleContext{Level: scope.Actor.Level, Role: scope.Actor.Role}) {
			return &api.Error{Code: api.CodeUnauthenticated, Message: "incomplete live lane scope",
				Instead: "Use the service-created launch and its original binding."}
		}
	case "human":
		// The service authenticator verifies the human session before the module
		// is entered. An Actor in an RPC body is never accepted here.
	default:
		return &api.Error{Code: api.CodeForbidden, Message: "policy projection requires a lane or verified human",
			Instead: "Read policy through an authenticated lane or human session."}
	}
	return nil
}

func forbiddenTarget() error {
	return &api.Error{Code: api.CodeForbidden, Message: "policy target differs from the authenticated life",
		Instead: "Use that life's own hook, or the verified human policy view."}
}

func conflict(message string) error {
	return &api.Error{Code: api.CodeConflict, Message: message,
		Instead: "Refresh the current life and policy through the existing binding."}
}

func (s *Service) PolicyGet(ctx context.Context, scope api.Scope, request api.PolicyGetRequest) (api.EffectivePolicy, error) {
	if err := ValidateGetInput(request); err != nil {
		return api.EffectivePolicy{}, err
	}
	scope, err := readScope(ctx, scope)
	if err != nil {
		return api.EffectivePolicy{}, err
	}
	policy, _, err := s.getPolicy(ctx, scope, request, nil)
	return policy, err
}

func readScope(ctx context.Context, scope api.Scope) (api.Scope, error) {
	if err := authenticated(scope); err != nil {
		return api.Scope{}, err
	}
	if scope.Actor.Kind == "human" {
		return api.WithReadAuthority(ctx, scope)
	}
	return scope, nil
}

func (s *Service) getPolicy(ctx context.Context, scope api.Scope, request api.PolicyGetRequest, role *api.RoleContext) (api.EffectivePolicy, sourceSnapshot, error) {
	var empty api.EffectivePolicy
	var noSnapshot sourceSnapshot
	if err := authenticated(scope); err != nil {
		return empty, noSnapshot, err
	}
	if err := ValidateGetInput(request); err != nil {
		return empty, noSnapshot, err
	}
	if scope.Actor.Kind == "lane" && request.LifeID != "" && request.LifeID != scope.Actor.LifeID {
		return empty, noSnapshot, forbiddenTarget()
	}
	var policy api.EffectivePolicy
	var err error
	if scope.Actor.Kind == "human" && (request.LifeID != "" || role != nil) || scope.Actor.Kind == "lane" && role != nil && role.InstanceID == scope.Actor.ID {
		// BriefingInput resolves the target without rewriting the authenticated
		// human principal or borrowing a lane's connection authority.
		var input api.BriefingInput
		lookup := api.BriefingInputRequest{LifeID: request.LifeID}
		if role != nil {
			lookup.Context = *role
		}
		input, err = s.deps.Store.BriefingInput(ctx, scope, lookup)
		if err == nil && request.LifeID != "" && (input.Lane == nil || input.Lane.LifeID != request.LifeID ||
			input.Policy.Context.Level != input.Lane.Level || input.Policy.Context.Role != input.Lane.Role) {
			err = integrity("target policy does not describe the resolved life")
		}
		policy = input.Policy
	} else {
		policy, err = s.deps.Store.Policy(ctx, scope)
	}
	if err != nil {
		return empty, noSnapshot, err
	}
	if role != nil && policy.Context != *role {
		if scope.Actor.Kind == "lane" {
			return empty, noSnapshot, forbiddenTarget()
		}
		return empty, noSnapshot, conflict("policy context differs from the requested approved role")
	}
	if err := validatePolicy(policy); err != nil {
		return empty, noSnapshot, err
	}
	if scope.PolicyGeneration != policy.Generation {
		return empty, noSnapshot, conflict("policy generation changed")
	}
	if scope.Actor.Kind == "lane" {
		lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: scope.Actor.LifeID})
		if err != nil {
			return empty, noSnapshot, err
		}
		if lane.LifeID != scope.Actor.LifeID || lane.Level != scope.Actor.Level || lane.Role != scope.Actor.Role ||
			policy.Context.Level != lane.Level || policy.Context.Role != lane.Role {
			return empty, noSnapshot, conflict("policy role differs from current recorded life")
		}
		if err := s.laneReadAuthority(ctx, scope, lane, policy.Generation); err != nil {
			return empty, noSnapshot, err
		}
	}
	want, err := policyDigest(policy)
	if err != nil {
		return empty, noSnapshot, err
	}
	if !validDigest(policy.SHA256) || policy.SHA256 != want {
		return empty, noSnapshot, integrity("effective policy content hash mismatch")
	}
	snapshot, err := s.approvedSources(ctx, scope, policy)
	if err != nil {
		return empty, noSnapshot, err
	}
	return copyPolicy(policy), snapshot, nil
}

func (s *Service) laneReadAuthority(ctx context.Context, scope api.Scope, lane api.Lane, generation api.Generation) error {
	if lane.Cleaned {
		return forbiddenTarget()
	}
	if err := lanePolicyGeneration(lane.PolicyGeneration, generation); err != nil {
		return err
	}
	launch, err := s.deps.Store.Launch(ctx, scope.LaunchID)
	if err != nil {
		return err
	}
	if launch.Revoked || lane.LaunchID != scope.LaunchID || launch.ID != scope.LaunchID ||
		launch.Config != scope.Config || launch.Actor != scope.Actor || launch.EndpointGeneration != scope.EndpointGeneration ||
		launch.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) || launch.GrantSetID != lane.GrantSetID ||
		launch.PolicyGeneration == 0 || launch.PolicyGeneration > generation {
		return forbiddenTarget()
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if err != nil || grants.ID != lane.GrantSetID || grants.LifeID != lane.LifeID || grants.Revoked ||
		grants.Generation == 0 || grants.PolicyGeneration == 0 || grants.PolicyGeneration > generation ||
		!validDigest(grants.SHA256) || !s.deps.Clock.Now().Before(expires) {
		return forbiddenTarget()
	}
	return nil
}

// Fix 11 permits an older live projection while reads use current policy. A
// zero/future pin is still invalid; reads never advance it or rewrite issuance.
func lanePolicyGeneration(recorded, current api.Generation) error {
	if recorded == 0 || recorded > current {
		return &api.Error{Code: api.CodeConflict, Owner: "lb-v2-policy",
			Message: fmt.Sprintf("recorded life policy generation %d differs from current policy generation %d", recorded, current),
			Instead: "Reload the current approved policy and reconcile the invalid live policy projection through its protected coordinator."}
	}
	return nil
}

func copyPolicy(policy api.EffectivePolicy) api.EffectivePolicy {
	policy.Rules = append([]api.Rule{}, policy.Rules...)
	for i := range policy.Rules {
		policy.Rules[i].Scope = cloneScope(policy.Rules[i].Scope)
	}
	policy.Skip = append([]api.SkipEntry{}, policy.Skip...)
	policy.Sources = append([]api.SourceRef{}, policy.Sources...)
	policy.ProfileExclusions = append([]api.ID{}, policy.ProfileExclusions...)
	return policy
}

func (s *Service) ConfigRead(ctx context.Context, scope api.Scope, request api.ConfigReadRequest) (api.ConfigView, error) {
	var empty api.ConfigView
	if err := ValidateConfigReadInput(request); err != nil {
		return empty, err
	}
	scope, err := readScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if scope.Actor.Kind == "lane" && request.Context != nil &&
		(request.Context.Level != scope.Actor.Level || request.Context.Role != scope.Actor.Role || request.Context.InstanceID != "" && request.Context.InstanceID != scope.Actor.ID) {
		return empty, forbiddenTarget()
	}
	policy, snapshot, err := s.getPolicy(ctx, scope, api.PolicyGetRequest{}, request.Context)
	if err != nil {
		return empty, err
	}
	org, err := s.deps.Store.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: snapshot.OrgID, Generation: snapshot.Generation})
	if err != nil {
		return empty, err
	}
	if org.Ref != snapshot.OrgSnapshotRef || org.Config != scope.Config {
		return empty, conflict("configuration snapshot changed")
	}
	sources := append([]api.SourceRef{}, policy.Sources...)
	if scope.Actor.Kind == "human" {
		sources = make([]api.SourceRef, 0, len(org.Sources))
		for _, file := range org.Sources {
			sources = append(sources, file.Source)
		}
	}
	projection := api.ConfigProjection{Schema: "laneboss.config-view.v2", Config: scope.Config,
		View: request.View, Generation: snapshot.Generation, Context: &policy.Context,
		Names: []string{}, Settings: []api.SettingValue{}, Resources: []api.Resource{},
		Sources: sources, Warnings: []string{}}
	switch request.View {
	case "path":
		// Approved logical source references are safe discovery metadata. Never
		// expose the writable service state directory or a runtime socket path.
	case "list":
		// A bound client sees only its named configuration.
		projection.Names = []string{scope.Config}
	case "show", "settings", "roles", "plugins", "channels":
		canonical, err := ReadCanonical(ctx, s.deps.Store, scope, policy, org, policy.Context)
		if err != nil {
			return empty, err
		}
		if request.View == "show" || request.View == "settings" {
			projection.Settings = canonical.Settings
		}
		if request.View == "show" || request.View == "roles" {
			projection.Names = canonical.Names
		}
		for _, resource := range canonical.Resources {
			if request.View == "show" || request.View == "plugins" && resource.Kind == "plugin" || request.View == "channels" && resource.Kind == "channel" {
				projection.Resources = append(projection.Resources, resource)
			}
		}
	default:
		return empty, invalid("unknown configuration view")
	}
	data, err := json.Marshal(projection)
	if err != nil {
		return empty, integrity("configuration projection cannot be encoded")
	}
	target := api.LifeRef{}
	if scope.Actor.Kind == "lane" {
		target.LifeID = scope.Actor.LifeID
	}
	intent, err := retentionIntent(scope, target, "", "")
	if err != nil {
		return empty, err
	}
	blob, err := s.put(ctx, scope, intent, "policy", data, snapshot.Inputs)
	if err != nil {
		return empty, err
	}
	return api.ConfigView{Generation: snapshot.Generation, Sources: sources,
		Projection: blob, Warnings: []string{}}, nil
}

func (s *Service) ConfigValidate(ctx context.Context, scope api.Scope, request api.Empty) (api.OrgValidation, error) {
	scope, err := readScope(ctx, scope)
	if err != nil {
		return api.OrgValidation{}, err
	}
	_, snapshot, err := s.getPolicy(ctx, scope, api.PolicyGetRequest{}, nil)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeInvalid {
			return api.OrgValidation{Valid: false, Problems: []string{typed.Message}}, nil
		}
		return api.OrgValidation{}, err
	}
	if s.deps.ValidateSources == nil {
		return api.OrgValidation{}, api.NotImplemented("lb-v2-integrate", "complete configuration source validation")
	}
	validation, err := s.deps.ValidateSources(ctx, scope, api.OrgValidateRequest{Generation: snapshot.Generation})
	if err != nil {
		return api.OrgValidation{}, err
	}
	if validation.Problems == nil || validation.Valid != (len(validation.Problems) == 0) {
		return api.OrgValidation{}, integrity("configuration source validation is incomplete")
	}
	return validation, nil
}

// DefaultJudgeConfig selects the brief's self-hosted Clef default. The caller
// still supplies measured deployment/tokenizer pins and calibration receipts;
// this function cannot establish a provider's calibration or authenticate it.
func DefaultJudgeConfig(deployment, tokenizer api.Digest, contextTokens int) api.JudgeConfig {
	return api.JudgeConfig{
		Provider: "clef-sglang", Model: "Cloudflare/clef-flash",
		DeploymentSHA256: deployment, TokenizerSHA256: tokenizer,
		ContextTokens: contextTokens, MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12,
		CommandDeadlineMS: 2000, GuidanceDeadlineMS: 5000,
		CacheTTLMS: 30000, OutagePolicy: "critical-only",
	}
}
