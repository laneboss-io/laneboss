package grants

import (
	"context"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
)

func delegationState(state string) error {
	switch state {
	case "preparing", "running", "stopping", "verifying", "idle", "profile_wait":
		return nil
	case "lost", "accepted", "merged", "abandoned":
		return refused("ended ancestors cannot issue new delegations; only sealed prior child scope can continue")
	default:
		return integrity("delegating lane has an unknown lifecycle state")
	}
}

func (s *Service) postExitDelegation(ctx context.Context, scope api.Scope, parent, child api.ID) error {
	reader, ok := s.deps.Store.(interface {
		VerifyDelegationLease(context.Context, api.Scope, api.ID, api.ID) (api.Digest, error)
	})
	if !ok {
		return &api.Error{Code: api.CodePrerequisite, Message: "sealed delegation lease reader is missing", Owner: "lb-v2-grants"}
	}
	seal, err := reader.VerifyDelegationLease(ctx, scope, parent, child)
	if err != nil {
		return err
	}
	if len(seal) != 64 {
		return integrity("delegation lease has no immutable authority seal")
	}
	return nil
}

// All selectors and pins below come from the retained reservation and current
// store records. A public resume/turn body supplies no starter authority.
func (s *Service) retainedStarter(ctx context.Context, state *lstate.State, target api.Lane) error {
	r := state.Record.Reservation
	if r.Authority.Kind != "starter" || r.RequestedBy.LifeID == target.LifeID ||
		!slices.Contains(target.StarterChain, r.RequestedBy.LifeID) {
		return refused("retained requester is not a strict authentic ancestor")
	}
	ancestor, err := s.deps.Store.Lane(ctx, state.Scope, api.LifeRef{LifeID: r.RequestedBy.LifeID})
	if err != nil {
		return err
	}
	if ancestor.Cleaned || ancestor.LifeID != r.RequestedBy.LifeID || ancestor.Level <= target.Level ||
		ancestor.Level != r.RequestedBy.Level || ancestor.Role != r.RequestedBy.Role || ancestor.RootLifeID != target.RootLifeID {
		return refused("retained requester differs from its current ancestor lane")
	}
	switch ancestor.State {
	case "accepted", "merged", "abandoned":
		if target.ParentLifeID != ancestor.LifeID {
			return refused("post-exit authority requires the direct sealed delegation edge")
		}
		if err := s.postExitDelegation(ctx, state.Scope, ancestor.LifeID, target.GrantSetID); err != nil {
			return err
		}
	default:
		if err := delegationState(ancestor.State); err != nil {
			return err
		}
	}
	starter, err := s.deps.Store.Launch(ctx, r.Authority.ID)
	if err != nil {
		return err
	}
	if starter.ID != r.Authority.ID || starter.ID != ancestor.LaunchID || starter.Kind != "agent" || starter.Revoked ||
		starter.Config != r.Config || starter.Actor != r.RequestedBy || starter.Target != (api.LifeRef{LifeID: ancestor.LifeID, Run: ancestor.Run}) ||
		starter.GrantSetID != ancestor.GrantSetID || starter.PolicyGeneration != r.PolicyGeneration || ancestor.PolicyGeneration != r.PolicyGeneration {
		return refused("retained starter authority differs from its current authentic launch")
	}
	return nil
}
