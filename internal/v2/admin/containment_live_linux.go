//go:build linux

package admin

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/pollgate"
)

func (s *Service) liveContainment(ctx context.Context, id api.ID, query containmentQuery) (containmentTicket, error) {
	ticket, _, err := s.liveProof(ctx, id, query)
	return ticket, err
}

func (s *Service) liveProof(ctx context.Context, id api.ID, query containmentQuery) (containmentTicket, func() error, error) {
	// A memo fence cancels its private read context, not the request that
	// owns this IPC. Drain that reply before retrying the fenced proof;
	// genuine request cancellation and its original deadline still apply.
	return s.containmentProof(ctx, id, query, nil, func(_ context.Context, query containmentQuery) (containmentTicket, time.Time, error) {
		var ticket containmentTicket
		var observed int64
		err := s.call(ctx, "containment_live", query, &ticket, &observed)
		if err != nil {
			return ticket, time.Time{}, err
		}
		until, err := containmentExpiry(observed)
		return ticket, until, err
	})
}

func (s *Service) cachedContainment(ctx context.Context, id api.ID, query containmentQuery,
	refresh func(context.Context, containmentQuery) (containmentTicket, error)) (containmentTicket, error) {
	ticket, _, err := s.containmentProof(ctx, id, query, refresh)
	return ticket, err
}

func (s *Service) containmentProof(ctx context.Context, id api.ID, query containmentQuery,
	refresh func(context.Context, containmentQuery) (containmentTicket, error),
	timed ...func(context.Context, containmentQuery) (containmentTicket, time.Time, error)) (containmentTicket, func() error, error) {
	s.registryMu.Lock()
	entry := s.containments[id]
	if entry == nil || entry.Binding.Revoked || entry.Ticket.Lease.ID != query.LeaseID || !query.Opened {
		s.registryMu.Unlock()
		return containmentTicket{}, nil, failure(api.CodeUnauthenticated, "peer containment is absent or revoked")
	}
	ticket := entry.Ticket
	s.registryMu.Unlock()
	for attempt := range 3 {
		var current containmentTicket
		var proof pollgate.Proof
		var err error
		if len(timed) == 1 {
			current, proof, err = entry.memo.EvalTimed(ctx, ticket, func(ctx context.Context) (containmentTicket, time.Time, error) {
				return timed[0](ctx, query)
			})
		} else {
			current, proof, err = entry.memo.Eval(ctx, ticket, func(ctx context.Context) (containmentTicket, error) {
				return refresh(ctx, query)
			})
		}
		s.registryMu.Lock()
		if s.containments[id] != entry || entry.Binding.Revoked || entry.Ticket != ticket || err == nil && current != ticket {
			err = failure(api.CodeUnauthenticated, "containment changed during helper resolution")
		}
		s.registryMu.Unlock()
		// Discard the fenced/aged observation and obtain a new one for this
		// request. A changed registry or actual helper refusal never retries.
		if attempt < 2 && len(timed) == 1 && ctx.Err() == nil &&
			(errors.Is(err, pollgate.ErrChanged) || errors.Is(err, pollgate.ErrExpired)) {
			continue
		}
		if err != nil {
			if errors.Is(err, pollgate.ErrChanged) {
				err = failure(api.CodeUnauthenticated, "containment changed during helper resolution")
			} else if errors.Is(err, pollgate.ErrExpired) {
				err = failure(api.CodeUnavailable, "containment helper observation expired during resolution")
			} else if ctx.Err() != nil {
				err = contextError(ctx)
			}
			return containmentTicket{}, nil, err
		}
		return current, func() error { return entry.memo.Check(proof) }, nil
	}
	return containmentTicket{}, nil, failure(api.CodeUnavailable, "containment observation did not stabilize")
}
