package api

import "context"

// This private read always selects the approved head, regardless of the
// authenticated scope's historical policy generation. The store implements it
// against the same locked snapshot used by its prepare/open transaction.
type CurrentPolicySource interface {
	CurrentApprovedPolicy(context.Context, Scope) (EffectivePolicy, error)
}

type launchPolicyFence struct {
	config     string
	generation Generation
	kind       InternalKind
	effectID   ID
}

// BindCurrentLaunchPolicy is called by the single store writer immediately
// before validation/commit, with its locked CurrentPolicySource. A service DTO
// cannot fill the private fence or use Scope.PolicyGeneration as a substitute.
// Helper-open authorization precedes actual OpenGate; completion is too late.
func BindCurrentLaunchPolicy(ctx context.Context, source CurrentPolicySource, tx Transaction) (Transaction, error) {
	if tx.Internal == nil || tx.Internal.Kind != InternalHelperPrepare && tx.Internal.Kind != InternalHelperOpen {
		return tx, nil
	}
	if source == nil {
		return tx, NotImplemented("lb-v2-service", "current launch policy source")
	}
	current, err := source.CurrentApprovedPolicy(ctx, tx.Scope)
	if err != nil {
		return tx, err
	}
	if !launchGeneration(current.Generation) {
		return tx, &Error{Code: CodeUnavailable, Owner: "lb-v2-service", Message: "current approved launch policy is unavailable", Instead: "Keep the gate closed and reconcile the original launch."}
	}
	tx.launchPolicy = &launchPolicyFence{config: tx.Scope.Config, generation: current.Generation, kind: tx.Internal.Kind, effectID: tx.Internal.EffectID}
	return tx, nil
}

func validLaunchPolicyFence(tx Transaction) bool {
	if tx.Internal == nil || tx.Internal.Kind != InternalHelperPrepare && tx.Internal.Kind != InternalHelperOpen {
		return true
	}
	needed := len(tx.Writes.LaunchPlans) != 0 || len(tx.Writes.Lanes) != 0
	for _, binding := range tx.Writes.IdentityBindings {
		needed = needed || binding.Record.Kind != "worker"
	}
	for _, event := range tx.Events {
		needed = needed || event.Kind == "lane.started" || event.Kind == "lane.resumed" || event.Kind == "lane.turn"
	}
	// Existing validPreparedPlanBindings owns the prepare missing-plan gate.
	// Workers have their existing separate lease and no agent reservation.
	if !needed || tx.Internal.Kind == InternalHelperPrepare && len(tx.Writes.LaunchPlans) == 0 {
		return true
	}
	if tx.launchPolicy == nil {
		return false
	}
	if tx.launchPolicy.config != tx.Scope.Config || !launchGeneration(tx.launchPolicy.generation) ||
		tx.launchPolicy.kind != tx.Internal.Kind || tx.launchPolicy.effectID != tx.Internal.EffectID {
		return false
	}
	matched := false
	for _, record := range tx.Writes.LaunchPlans {
		if record.Reservation.PolicyGeneration != tx.launchPolicy.generation {
			return false
		}
		matched = matched || record.Reservation.Target == tx.Internal.Target
	}
	return matched
}
