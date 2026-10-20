package lifecycle

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

// RestoreControl is a private single-writer capability. It checks the original
// reservation, current parent authority and exact proof before filesystem work,
// and retains a typed reply only after the independent worktree is complete.
type RestoreControl interface {
	RestoreArchive(context.Context, api.Scope, api.RestoreRequest) (api.RestoreReceipt, error)
}

func (s *Service) LaneRestore(ctx context.Context, scope api.Scope, request api.RestoreRequest) (result api.RestoreReceipt, resultErr error) {
	if err := s.authorize(ctx, scope, "lane.restore", request); err != nil {
		return api.RestoreReceipt{}, err
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.RestoreReceipt{}, err
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.RestoreReceipt{}, err
	}
	if result, found, err := replayReply[api.RestoreReceipt](s, ctx, scope); found || err != nil {
		return result, err
	}
	if lane.Generation != request.ExpectedGeneration || lane.Run != request.Target.Run {
		return api.RestoreReceipt{}, problem(api.CodeConflict, "restore_generation_changed", "Read the current life and retain its run and generation.")
	}
	// Bulk reads and native staging must not hold the life mutex. The store
	// rechecks this exact generation, cancellation epoch and authority at publish.
	unlock()
	locked = false
	control, ok := s.deps.Store.(RestoreControl)
	if !ok {
		return api.RestoreReceipt{}, api.NotImplemented("lb-v2-service", "authorized archive restore writer")
	}
	// Keep the existing bounded per-request object cache while streaming large
	// files. Every range still passes the original caller's live object ACLs.
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return api.RestoreReceipt{}, failure(err)
	}
	defer func() {
		release(&resultErr)
		if resultErr != nil {
			resultErr = failure(resultErr)
		}
	}()
	result, err = control.RestoreArchive(ctx, scope, request)
	return result, failure(err)
}
