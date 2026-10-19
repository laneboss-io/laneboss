package grants

import (
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (s *Service) Revalidate(ctx context.Context, input api.GrantSet) (result api.GrantSet, resultErr error) {
	return s.revalidateScope(ctx, s.internalScope(), input, func(ctx context.Context, current api.GrantSet) (api.GrantSet, error) {
		return s.currentAfterRead(ctx, current)
	})
}

func (s *Service) revalidateScope(ctx context.Context, caller api.Scope, input api.GrantSet,
	after func(context.Context, api.GrantSet) (api.GrantSet, error)) (result api.GrantSet, resultErr error) {
	ctx = verificationContext(ctx)
	var zero api.GrantSet
	if !manifest.ValidID(input.ID) {
		return zero, manifest.Invalid("effective grants need a service-issued identity")
	}
	if err := ctx.Err(); err != nil {
		return zero, cancelled(err)
	}
	scope, view, err := s.freshAuthority(ctx, caller)
	if err != nil {
		return zero, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	current, err := s.deps.Store.Grants(ctx, input.ID)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(current, input) {
		return zero, conflict("effective grants changed since the request was prepared")
	}
	if err := s.chain(ctx, scope, current, map[api.ID]bool{}, 0); err != nil {
		return zero, err
	}
	if err := s.checkSources(ctx, scope, current); err != nil {
		return zero, err
	}
	return after(ctx, current)
}

// Source reads may yield to a revocation, policy update or generation change.
// Recheck stored authority after the reads, before handing it to a worker.
// This remains an out-of-transaction check: release still needs the shared CAS
// and launch permit protocol described in INTEGRATION.md.
func (s *Service) currentAfterRead(ctx context.Context, before api.GrantSet) (result api.GrantSet, resultErr error) {
	return s.currentAfterScope(ctx, s.internalScope(), before)
}

func (s *Service) currentAfterScope(ctx context.Context, caller api.Scope, before api.GrantSet) (result api.GrantSet, resultErr error) {
	scope, view, err := s.freshAuthority(ctx, caller)
	if err != nil {
		return api.GrantSet{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	current, err := s.deps.Store.Grants(ctx, before.ID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if !reflect.DeepEqual(current, before) {
		return api.GrantSet{}, conflict("effective grants changed during source verification")
	}
	if err := s.chain(ctx, scope, current, map[api.ID]bool{}, 0); err != nil {
		return api.GrantSet{}, err
	}
	return current, nil
}

func (s *Service) chain(ctx context.Context, scope api.Scope, current api.GrantSet, seen map[api.ID]bool, depth int) error {
	if err := ctx.Err(); err != nil {
		return cancelled(err)
	}
	if depth > 3 || seen[current.LifeID] {
		return integrity("grant starter chain has a cycle or invalid depth")
	}
	seen[current.LifeID] = true
	if err := manifest.Set(current, s.deps.Clock.Now()); err != nil {
		return err
	}
	sealed := current
	if err := seal(&sealed); err != nil {
		return err
	}
	if sealed.SHA256 != current.SHA256 {
		return integrity("effective grant digest does not match its exact contents")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: current.LifeID})
	if err != nil {
		return err
	}
	if lane.LifeID != current.LifeID || lane.GrantSetID != current.ID || lane.ParentLifeID != current.ParentLifeID ||
		lane.Level < 3 || lane.Level > 6 || lane.Cleaned {
		return integrity("grant life and authoritative lane do not match")
	}
	switch lane.State {
	case "preparing", "running", "stopping", "verifying", "idle", "profile_wait",
		"lost", "accepted", "merged", "abandoned":
	default:
		return integrity("grant life has an unknown lifecycle state")
	}
	policy, err := s.lanePolicy(ctx, scope, lane)
	if err != nil {
		return err
	}
	if policy.Generation == 0 || policy.Generation != current.PolicyGeneration || lane.PolicyGeneration != policy.Generation {
		return conflict("grant policy generation is no longer current")
	}
	if current.ParentLifeID == "" {
		if len(lane.StarterChain) != 0 || lane.RootLifeID != lane.LifeID {
			return integrity("root grant has an inconsistent starter chain")
		}
		return nil
	}
	parentLane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: current.ParentLifeID})
	if err != nil {
		return err
	}
	if parentLane.LifeID != current.ParentLifeID || parentLane.Level <= lane.Level || parentLane.Level > 6 ||
		len(lane.StarterChain) != len(parentLane.StarterChain)+1 ||
		lane.StarterChain[len(lane.StarterChain)-1] != parentLane.LifeID ||
		!reflect.DeepEqual(lane.StarterChain[:len(lane.StarterChain)-1], parentLane.StarterChain) ||
		lane.RootLifeID != parentLane.RootLifeID {
		return integrity("grant ancestry differs from the authentic strict-lower starter chain")
	}
	switch parentLane.State {
	case "preparing", "running", "stopping", "verifying", "idle", "profile_wait":
	case "lost":
		return refused("lost ancestor has no measured post-exit delegation authority")
	case "accepted", "merged", "abandoned":
		if err := s.postExitDelegation(ctx, scope, parentLane.LifeID, current.ID); err != nil {
			return err
		}
	default:
		return integrity("ancestor has an unknown lifecycle state")
	}
	parent, err := s.deps.Store.Grants(ctx, parentLane.GrantSetID)
	if err != nil {
		return err
	}
	if parent.LifeID != parentLane.LifeID {
		return integrity("ancestor grants refer to another life")
	}
	if err := s.chain(ctx, scope, parent, seen, depth+1); err != nil {
		return err
	}
	return checkChild(parent, current, s.deps.Clock.Now())
}

func (s *Service) Materialize(ctx context.Context, input api.GrantSet) (api.Materialization, error) {
	current, err := s.Revalidate(ctx, input)
	if err != nil {
		return api.Materialization{}, err
	}
	result, err := s.deps.Worker.Materialize(ctx, current)
	if err != nil {
		return api.Materialization{}, err
	}
	if result.GrantSetID != current.ID || len(result.Objects) != len(current.Data) {
		return api.Materialization{}, integrity("worker materialization does not cover the exact grant set")
	}
	if err := manifest.Blob(result.Manifest); err != nil {
		return api.Materialization{}, integrity("worker returned an invalid materialization manifest")
	}
	if result.Manifest.Class != "manifest" {
		return api.Materialization{}, integrity("materialization receipt is not a manifest")
	}
	seen, destinations := map[api.ID]bool{}, map[string]bool{}
	for _, object := range result.Objects {
		if _, found := findData(current.Data, object.GrantID); !found || seen[object.GrantID] ||
			object.SourceIdentity == "" || object.DestinationIdentity == "" || destinations[object.DestinationIdentity] ||
			!manifest.ValidDigest(object.SnapshotSHA256) || !manifest.ValidID(object.WorkspaceID) {
			return api.Materialization{}, integrity("worker omitted or aliased a materialized object identity")
		}
		seen[object.GrantID], destinations[object.DestinationIdentity] = true, true
	}
	if _, err := s.Revalidate(ctx, current); err != nil {
		return api.Materialization{}, err
	}
	return result, nil
}
