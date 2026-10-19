// Package guidance is owned by lb-v2-guidance.
package guidance

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	// Optional protected inference ceiling; installation supplies its actual
	// approved value. Remaining lane spend is always an additional bound.
	MaxCostMicros int64
	Store         api.StateStore
	Judge         api.ScopedJudge
	Clock         api.Clock
}

type Service struct {
	deps Dependencies
}

func New(deps Dependencies) (*Service, error) {
	if deps.MaxCostMicros < 0 || deps.MaxCostMicros > maxInteger {
		return nil, invalid("invalid approved guidance inference ceiling")
	}
	if missing(deps.Store) || missing(deps.Judge) || missing(deps.Clock) {
		return nil, &api.Error{
			Code: api.CodePrerequisite, Owner: "lb-v2-guidance",
			Message: "guidance requires a store, judge and service clock",
			Instead: "Wire the required service dependencies before selecting guidance.",
		}
	}
	return &Service{deps: deps}, nil
}

var _ api.GuidanceAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if missing(registry) {
		return invalid("guidance requires an RPC registry")
	}
	return registry.Register("guidance.select", func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		request, err := decodeRequest(raw)
		if err != nil {
			return nil, err
		}
		result, err := s.GuidanceSelect(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	})
}

func (s *Service) GuidanceSelect(ctx context.Context, scope api.Scope, request api.GuidanceRequest) (api.Guidance, error) {
	// The single total budget starts before authority and store waits.
	entered := s.deps.Clock.Now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := validateRequest(request); err != nil {
		return api.Guidance{}, err
	}
	var err error
	scope, err = authorizeTarget(ctx, scope, request.Target)
	if err != nil {
		return api.Guidance{}, err
	}
	if err := contextError(ctx); err != nil {
		return api.Guidance{}, err
	}
	if result, found, err := s.exactReply(ctx, scope, request); found || err != nil {
		return result, err
	}
	lane, err := s.deps.Store.Lane(ctx, scope, request.Target)
	if err != nil {
		return api.Guidance{}, err
	}
	if lane.LifeID != request.Target.LifeID || lane.Run != request.Target.Run ||
		lane.LogicalTurnID != request.LogicalTurnID || lane.Cleaned {
		return api.Guidance{}, &api.Error{
			Code: api.CodeConflict, Owner: "lb-v2-guidance",
			Message: "guidance target is not the current uncleaned logical turn",
			Instead: "Read the current lane and use its authentic logical turn.",
		}
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.Guidance{}, err
	}
	turn, err := s.deps.Store.Turn(ctx, scope, request.Target, request.LogicalTurnID)
	if err != nil {
		return api.Guidance{}, err
	}
	if turn.Target.LifeID != request.Target.LifeID || turn.Target.Run == 0 || turn.Target.Run > request.Target.Run ||
		turn.LogicalTurnID != request.LogicalTurnID || turn.Task != request.Task || turn.Generation == 0 {
		return api.Guidance{}, &api.Error{Code: api.CodeConflict, Owner: "lb-v2-guidance",
			Message: "guidance task does not match the authoritative logical turn",
			Instead: "Use the exact retained task and turn; a visible alternative task is not a replacement."}
	}
	if policy.Generation == 0 || scope.PolicyGeneration != 0 && policy.Generation != scope.PolicyGeneration {
		return api.Guidance{}, integrity("current policy differs from the authorization scope")
	}
	reservation, found, err := s.lookupClaim(ctx, scope, request)
	if err != nil {
		return api.Guidance{}, err
	}
	if found {
		return s.observeClaim(ctx, scope, request, lane, turn, policy, reservation)
	}
	return s.selectFresh(ctx, scope, request, lane, turn, policy, entered)
}

func missing(value any) bool {
	if value == nil {
		return true
	}
	switch reflect.ValueOf(value).Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	}
	return false
}

func contextError(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	code := api.CodeCancelled
	if ctx.Err() == context.DeadlineExceeded {
		code = api.CodeDeadline
	}
	return &api.Error{
		Code: code, Owner: "lb-v2-guidance", Message: "guidance selection interrupted",
		Instead: "Inspect the retained turn receipt before retrying the same request.",
	}
}
