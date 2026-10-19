package secrets

import (
	"context"
	"reflect"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// This is an in-process read capability over the broker's actual currently
// held journal. It is never serialized. Clearing waits for its native reader
// before the owning operation can release that journal.
type projectionInventory struct {
	mu        sync.Mutex
	journal   bstate.Journal
	authority api.CredentialProjectionAuthority
}

func (f *projectionFlight) retainInventory(j bstate.Journal, authority api.CredentialProjectionAuthority) func() {
	guard := &projectionInventory{journal: j, authority: authority}
	f.mu.Lock()
	f.inventory = guard
	f.mu.Unlock()
	return func() {
		guard.mu.Lock()
		guard.journal = nil
		guard.mu.Unlock()
		f.mu.Lock()
		if f.inventory == guard {
			f.inventory = nil
		}
		f.mu.Unlock()
	}
}

// CredentialSourceVersions is an outside-broker private metadata read. The
// native host authenticates its control connection; no value or descriptor is
// returned to the service. It is not registered as a public RPC method.
func (s *Service) CredentialSourceVersions(ctx context.Context, peer api.VerifiedPeer, request api.CredentialProjectionRequest, projection api.ID) ([]api.CredentialSourceVersion, error) {
	if wire.Nil(peer) {
		return nil, wire.Error(api.CodeUnauthenticated, "credential source inventory requires its native helper peer")
	}
	if err := peer.Alive(ctx); err != nil {
		return nil, err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return nil, err
	}
	if facts.HostUID != 0 || facts.HostPID <= 1 || request.Handoff.Config != s.deps.Config {
		return nil, wire.Error(api.CodeForbidden, "credential source inventory requires the installed root helper")
	}
	if err := api.ValidateCredentialProjectionRequest(request, s.deps.Clock.Now()); err != nil {
		return nil, err
	}
	targets, err := api.CredentialTargets(request, s.deps.Clock.Now())
	if err != nil {
		return nil, err
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return nil, err
	}
	var result []api.CredentialSourceVersion
	if projection != "" {
		s.projectionMu.Lock()
		flight := s.projections[projection]
		s.projectionMu.Unlock()
		if flight != nil {
			flight.mu.Lock()
			guard := flight.inventory
			flight.mu.Unlock()
			if guard != nil {
				guard.mu.Lock()
				defer guard.mu.Unlock()
				if guard.journal != nil {
					if guard.authority.ID != projection || !reflect.DeepEqual(guard.authority.Request, request) {
						return nil, wire.Error(api.CodeForbidden, "credential inventory callback selected another canonical owner")
					}
					slots, sources, err := s.projectionSlots(ctx, guard.journal, guard.authority)
					defer clearProjectionSlots(slots)
					if err != nil {
						return nil, err
					}
					if err := flight.checkRefreshLeases(); err != nil {
						return nil, err
					}
					return append([]api.CredentialSourceVersion{}, sources...), peer.Alive(ctx)
				}
			}
		}
	}
	err = backend.WithBroker(ctx, func(j bstate.Journal) error {
		slots, sources, err := s.projectionSlots(ctx, j, api.CredentialProjectionAuthority{ID: projection, Request: request, Targets: targets})
		defer clearProjectionSlots(slots)
		if err != nil {
			return err
		}
		result = append([]api.CredentialSourceVersion{}, sources...)
		return peer.Alive(ctx)
	})
	return result, err
}
