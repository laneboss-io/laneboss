package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only a fresh operation reaches this coordinator. Exact receipt replay is
// resolved first, so refreshing the live projection cannot rewrite its cause.
func (s *Service) refreshLaunchPolicy(ctx context.Context, scope api.Scope, lane api.Lane) (api.Lane, error) {
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.Lane{}, failure(err)
	}
	generation, err := api.PolicyGenerationFor(api.PolicyNewLaunch, policy.Generation, 0)
	if err != nil {
		return api.Lane{}, failure(err)
	}
	if scope.PolicyGeneration != generation {
		return api.Lane{}, problem(api.CodeConflict, "authenticated policy context is stale", "Reload current authorization before taking a fresh launch fence.")
	}
	if lane.PolicyGeneration == generation {
		return lane, nil
	}
	request := api.PolicyAdvanceRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, ExpectedLaneGeneration: lane.Generation,
		FromGeneration: lane.PolicyGeneration, ToGeneration: generation, CancellationEpoch: lane.CancellationEpoch}
	receipt, err := s.deps.Store.RefreshLanePolicy(ctx, scope, request)
	if err != nil {
		return api.Lane{}, failure(err)
	}
	if err := api.ValidatePolicyAdvance(lane, request, policy, receipt); err != nil {
		return api.Lane{}, failure(err)
	}
	retained, err := s.deps.Store.Lane(ctx, scope, request.Target)
	if err != nil {
		return api.Lane{}, failure(err)
	}
	if !reflect.DeepEqual(retained, receipt.Lane) {
		return api.Lane{}, integrity("lane policy refresh was not retained exactly")
	}
	return retained, nil
}

func (s *Service) receiptPolicy(ctx context.Context, scope api.Scope, receipt api.MutationReceipt) error {
	current, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return failure(err)
	}
	generation, err := api.PolicyGenerationForReplay(scope, current, receipt)
	if err != nil {
		return failure(err)
	}
	retained, err := s.deps.Store.PolicyAt(ctx, scope, generation)
	if err != nil {
		return failure(err)
	}
	if retained.Generation != generation {
		return integrity("receipt policy history returned a foreign generation")
	}
	return nil
}
