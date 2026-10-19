package secrets

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type guardCheck struct {
	ctx     context.Context
	result  chan error
	failure error
}
type projectionGuard struct {
	mu     sync.Mutex
	record api.CredentialProjectionRecord
	checks chan guardCheck
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	err    error
}

func (g *projectionGuard) Projection() api.CredentialProjectionRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	var copy api.CredentialProjectionRecord
	data, err := json.Marshal(g.record)
	if err == nil {
		if err := json.Unmarshal(data, &copy); err == nil {
			return copy
		}
	}
	return api.CredentialProjectionRecord{}
}
func (g *projectionGuard) Check(ctx context.Context) error {
	call := guardCheck{ctx: ctx, result: make(chan error, 1)}
	select {
	case <-g.done:
		return wire.Error(api.CodeForbidden, "credential gate guard is closed")
	case <-ctx.Done():
		return g.Fence(wire.Context(ctx))
	case g.checks <- call:
	}
	select {
	case err := <-call.result:
		return err
	case <-g.done:
		select {
		case err := <-call.result:
			return err
		default:
		}
		if g.err != nil {
			return g.err
		}
		return wire.Error(api.CodeForbidden, "credential gate guard ended during validation")
	case <-ctx.Done():
		return g.Fence(wire.Context(ctx))
	}
}
func (g *projectionGuard) Close() error {
	g.once.Do(func() { close(g.stop) })
	<-g.done
	return g.err
}

func (g *projectionGuard) Fence(cause error) error {
	call := guardCheck{ctx: context.Background(), result: make(chan error, 1), failure: cause}
	select {
	case <-g.done:
		if g.err != nil {
			return g.err
		}
		return cause
	case g.checks <- call:
	}
	select {
	case err := <-call.result:
		return err
	case <-g.done:
		if g.err != nil {
			return g.err
		}
		return cause
	}
}

func (s *Service) checkProjectionGate(ctx context.Context, j bstate.Journal, f *projectionFlight, request api.CredentialGateRequest) (api.CredentialProjectionRecord, error) {
	a := f.transfer.Authority
	if err := f.checkRefreshLeases(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	var journal bstate.Projection
	if err := j.Read("projection", a.ID, &journal); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if journal.Fenced || journal.Released {
		return api.CredentialProjectionRecord{}, wire.Error(api.CodeConflict, "credential gate is durably fenced")
	}
	if err := s.projectionPeer(ctx, f.peer, a); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	record, err := s.projectionRecord(ctx, a)
	if err != nil {
		return record, err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, a.Request.Handoff.Spec.LaunchID)
	if err != nil {
		return record, err
	}
	if err := api.ValidateCredentialGateRequest(record, request, binding, s.deps.Clock.Now()); err != nil {
		return record, err
	}
	claim, err := s.deps.Store.Effect(ctx, s.deps.ServiceScope, request.Open.EffectID)
	if err != nil {
		return record, err
	}
	if claim.State != api.EffectClaimed || claim.Generation == 0 || !future(claim.ClaimExpiresAt, s.deps.Clock.Now()) || claim.Effect.ID != request.Open.EffectID || claim.Effect.OperationID != request.Open.OperationID {
		return record, wire.Error(api.CodeConflict, "credential gate lost its live open claim")
	}
	if wire.Nil(s.deps.Control) {
		return record, wire.Error(api.CodePrerequisite, "credential gate requires its installed open control source")
	}
	opened, err := s.deps.Control.Open(ctx, request.Open.Prepared, request.Open.Permit)
	if err != nil {
		return record, err
	}
	if !reflect.DeepEqual(opened, request.Open) {
		return record, wire.Error(api.CodeForbidden, "credential gate changed its authorized open cause")
	}
	if err := s.projectionPolicy(ctx, a.Request); err != nil {
		return record, err
	}
	slots, sources, err := s.projectionSlots(ctx, j, a)
	defer clearProjectionSlots(slots)
	if err != nil {
		return record, err
	}
	if !reflect.DeepEqual(sources, a.Sources) {
		return record, wire.Error(api.CodeForbidden, "credential gate source inventory was replaced")
	}
	if a.Request.Handoff.Spec.Kind == "agent" {
		lane, err := s.deps.Store.Lane(ctx, s.deps.ServiceScope, a.Request.Prepared.Target)
		if err != nil {
			return record, err
		}
		if lane.Cleaned || lane.LaunchID != binding.Record.ID || lane.CancellationEpoch != a.Request.Cause.CancellationEpoch {
			return record, wire.Error(api.CodeConflict, "credential gate life was cancelled or replaced")
		}
	}
	return record, nil
}

func (s *Service) LockCredentialProjection(ctx context.Context, request api.CredentialGateRequest) (api.CredentialGateGuard, error) {
	guard, err := s.lockCredentialProjection(ctx, request, nil)
	if err != nil {
		// Converting a nil *projectionGuard directly would return a nonnil
		// interface whose Close method dereferences a nil receiver.
		return nil, err
	}
	return guard, nil
}

func (s *Service) lockCredentialProjection(ctx context.Context, request api.CredentialGateRequest, peer api.VerifiedPeer) (*projectionGuard, error) {
	f := s.flight(request.ProjectionID)
	if f.isFenced() {
		return nil, wire.Error(api.CodeConflict, "credential gate is closed for withdrawal")
	}
	if err := f.enter(ctx); err != nil {
		return nil, err
	}
	if f.peer == nil || !f.closed || f.isFenced() {
		f.leave()
		return nil, wire.Error(api.CodeConflict, "credential gate has no acknowledged live native handoff")
	}
	if peer != nil {
		if err := s.projectionPeer(ctx, peer, f.transfer.Authority); err != nil {
			f.leave()
			return nil, err
		}
	}
	backend, err := s.brokerBackend()
	if err != nil {
		f.leave()
		return nil, err
	}
	durable, ok := backend.(bstate.DurableBackend)
	if !ok {
		f.leave()
		return nil, wire.Error(api.CodePrerequisite, "credential guard requires its durable journal")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	g := &projectionGuard{checks: make(chan guardCheck), stop: make(chan struct{}), done: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		defer f.leave()
		defer cancel()
		defer close(g.done)
		g.err = durable.WithBrokerDurable(bounded, func(j bstate.Journal) error {
			fence := func(err error) error { return s.fenceProjectionLocked(j, f, request.ProjectionID, err) }
			record, err := s.checkProjectionGate(bounded, j, f, request)
			if err != nil {
				err = fence(err)
				ready <- err
				return err
			}
			g.record = record
			ready <- nil
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-g.stop:
					if bounded.Err() != nil {
						return fence(wire.Context(bounded))
					}
					return nil
				case <-bounded.Done():
					return fence(wire.Context(bounded))
				case <-ticker.C:
					if _, err := s.checkProjectionGate(bounded, j, f, request); err != nil {
						return fence(err)
					}
				case check := <-g.checks:
					if check.failure != nil {
						err := fence(check.failure)
						check.result <- err
						return err
					}
					_, err := s.checkProjectionGate(check.ctx, j, f, request)
					if err != nil {
						err = fence(err)
						check.result <- err
						return err
					}
					check.result <- nil
				}
			}
		})
		select {
		case ready <- g.err:
		default:
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			<-g.done
			return nil, err
		}
		return g, nil
	case <-bounded.Done():
		cancel()
		return nil, wire.Context(bounded)
	}
}
