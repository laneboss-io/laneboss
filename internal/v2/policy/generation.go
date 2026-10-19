package policy

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// The dispatcher/LookupReceipt have already checked current authentication,
// revocation and visibility. Scope carries that current authorization generation;
// replay does not re-run fresh source/turn/command preflight or refresh the lane.
func (s *Service) replayPolicy(ctx context.Context, scope api.Scope, receipt api.MutationReceipt) (api.PolicyDecision, error) {
	current := api.EffectivePolicy{Generation: scope.PolicyGeneration}
	generation, err := api.PolicyGenerationForReplay(scope, current, receipt)
	if err != nil {
		return api.PolicyDecision{}, err
	}
	historical, err := s.deps.Store.PolicyAt(ctx, scope, generation)
	if err != nil {
		return api.PolicyDecision{}, err
	}
	if err := validatePolicy(historical); err != nil {
		return api.PolicyDecision{}, err
	}
	hash, err := policyDigest(historical)
	if err != nil || historical.Generation != generation || historical.SHA256 != hash {
		return api.PolicyDecision{}, integrity("policy replay lacks its approved immutable snapshot")
	}
	decision, err := decisionReply(receipt.Reply)
	if err != nil {
		return api.PolicyDecision{}, err
	}
	if decision.PolicyGeneration != generation {
		return api.PolicyDecision{}, integrity("policy replay decision differs from its retained generation")
	}
	return decision, nil
}

// This port is called only after receipt lookup proves fresh work and the
// current target/turn/grants have been checked. The store owns the atomic write,
// cancellation fence and lane.policy event; policy validates its narrow receipt.
func (s *Service) advanceLanePolicy(ctx context.Context, scope api.Scope, lane api.Lane, policy api.EffectivePolicy) (api.Lane, error) {
	generation, err := api.PolicyGenerationFor(api.PolicyNewEvaluation, policy.Generation, lane.PolicyGeneration)
	if err != nil {
		return api.Lane{}, err
	}
	if generation != scope.PolicyGeneration || generation != policy.Generation {
		return api.Lane{}, conflict("fresh evaluation requires the current approved policy")
	}
	if err := lanePolicyGeneration(lane.PolicyGeneration, generation); err != nil {
		return api.Lane{}, err
	}
	if lane.PolicyGeneration == generation {
		return lane, nil
	}
	request := api.PolicyAdvanceRequest{
		Target:                 api.LifeRef{LifeID: lane.LifeID, Run: lane.Run},
		ExpectedLaneGeneration: lane.Generation,
		FromGeneration:         lane.PolicyGeneration, ToGeneration: generation, CancellationEpoch: lane.CancellationEpoch,
	}
	receipt, err := s.deps.Store.RefreshLanePolicy(ctx, scope, request)
	if err != nil {
		return api.Lane{}, err
	}
	if err := api.ValidatePolicyAdvance(lane, request, policy, receipt); err != nil {
		return api.Lane{}, err
	}
	return receipt.Lane, nil
}
