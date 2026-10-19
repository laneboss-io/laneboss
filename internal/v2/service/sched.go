package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type schedulerSource struct {
	host   *Server
	native schedulerPin
	mu     sync.RWMutex
	stamp  api.InstalledScheduler
	policy api.Digest
	life   context.Context
}

func (s *Server) installScheduler(ctx context.Context) error {
	s.mu.RLock()
	ready := s.verified && s.bound && !s.closed && s.scheduler == nil
	binding := s.deps.Binding
	s.mu.RUnlock()
	if !ready {
		return serviceError(api.CodePrerequisite, "scheduler requires its installed bound host")
	}
	pin, err := pinScheduler(ctx, s)
	if err != nil {
		return err
	}
	id, err := wire.NewID()
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s", binding.Config, binding.InstallationGeneration, binding.ArtifactSHA256)))
	p := &schedulerSource{host: s, native: pin, life: ctx, stamp: api.InstalledScheduler{Config: binding.Config,
		Actor:        api.Actor{Kind: "scheduler", ID: api.ID("sched_" + hex.EncodeToString(digest[:16]))},
		CapabilityID: id, InstallationGeneration: binding.InstallationGeneration, BootID: pin.boot}}
	s.mu.Lock()
	if s.closed || !s.bound || s.scheduler != nil {
		s.mu.Unlock()
		return serviceError(api.CodeConflict, "installed scheduler host changed")
	}
	s.scheduler = p
	s.mu.Unlock()
	if err := s.refreshScheduler(ctx); err != nil {
		s.mu.Lock()
		s.scheduler = nil
		s.mu.Unlock()
		return err
	}
	return nil
}

// Refresh happens outside the writer. VerifyScheduler never calls into the
// store: the private writer independently compares its locked policy head.
func (s *Server) refreshScheduler(ctx context.Context) error {
	s.mu.RLock()
	p := s.scheduler
	s.mu.RUnlock()
	if p == nil {
		return serviceError(api.CodePrerequisite, "installed scheduler is missing")
	}
	if err := p.life.Err(); err != nil {
		return contextError(err)
	}
	if err := p.native.check(ctx, s); err != nil {
		return err
	}
	scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: s.controller}}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		var missing *api.Error
		if errors.As(err, &missing) && missing.Code == api.CodeNotFound {
			p.mu.RLock()
			idle := p.stamp.PolicyGeneration == 0
			p.mu.RUnlock()
			if idle {
				// Installation precedes initial policy publication. Keep the
				// native producer idle until a later refresh can pin policy.
				return nil
			}
		}
		return err
	}
	if policy.Generation == 0 || !wire.ValidDigest(string(policy.SHA256)) {
		return serviceError(api.CodeIntegrity, "scheduler has no current protected policy")
	}
	now := s.deps.Clock.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stamp.PolicyGeneration == policy.Generation && p.policy != "" && p.policy != policy.SHA256 {
		return serviceError(api.CodeIntegrity, "scheduler policy changed without its generation")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(p.stamp.ExpiresAt))
	if p.stamp.PolicyGeneration != policy.Generation || err != nil || !now.Add(5*time.Second).Before(expires) {
		p.stamp.CapabilityGeneration++
		p.stamp.ExpiresAt = api.Timestamp(now.Add(time.Minute).UTC().Format(time.RFC3339Nano))
		p.stamp.PolicyGeneration, p.policy = policy.Generation, policy.SHA256
	}
	return nil
}

func (p *schedulerSource) VerifyScheduler(ctx context.Context) (api.InstalledScheduler, error) {
	if p == nil || p.host == nil {
		return api.InstalledScheduler{}, serviceError(api.CodeForbidden, "scheduler has no private installed owner")
	}
	s := p.host
	if p.life == nil || p.life.Err() != nil {
		return api.InstalledScheduler{}, serviceError(api.CodeForbidden, "installed scheduler lifetime ended")
	}
	s.mu.RLock()
	active := s.scheduler == p && s.verified && s.bound && !s.closed && !s.dispatchPaused
	s.mu.RUnlock()
	if !active {
		return api.InstalledScheduler{}, serviceError(api.CodeForbidden, "installed scheduler is revoked, closed or frozen")
	}
	if err := p.native.check(ctx, s); err != nil {
		return api.InstalledScheduler{}, err
	}
	p.mu.RLock()
	stamp := p.stamp
	p.mu.RUnlock()
	if err := api.ValidateInstalledScheduler(stamp, s.deps.Clock.Now()); err != nil {
		return api.InstalledScheduler{}, err
	}
	return stamp, nil
}
