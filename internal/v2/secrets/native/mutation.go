package native

import (
	"context"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// WithMutation is a native capability, not an RPC or another state writer. It
// holds the same cross-process lock as Store/Revoke across the broker's version
// check, backend write and StateStore transaction. Metadata is authenticated;
// material never leaves the protected backend just to enumerate records.
func (s *Service) WithMutation(ctx context.Context, operation api.ID, fn func(api.SecretBackend, []api.SecretInfo) error) error {
	if fn == nil || !wire.ID(string(operation)) {
		return wire.Error(api.CodeInvalid, "protected mutation operation and callback are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, false); err != nil {
		return err
	}
	if err := s.directory.Lock(ctx); err != nil {
		return err
	}
	return s.withUnlock(func() error {
		names, err := s.directory.Names()
		if err != nil {
			return err
		}
		infos := make([]api.SecretInfo, 0, len(names))
		for _, name := range names {
			r, err := s.read(name)
			if err != nil {
				return err
			}
			plain, err := open(s.keys[r.Info.KeyID], r)
			clear(plain)
			if err != nil {
				return err
			}
			infos = append(infos, r.Info)
		}
		view := &mutationView{service: s, operation: operation, active: true}
		defer view.end()
		return fn(view, infos)
	})
}

type mutationView struct {
	service   *Service
	operation api.ID
	mu        sync.Mutex
	active    bool
}

func (v *mutationView) end() { v.mu.Lock(); defer v.mu.Unlock(); v.active = false }

func (v *mutationView) Store(ctx context.Context, info api.SecretInfo, material api.SecretMaterial) (api.SecretInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.active {
		return api.SecretInfo{}, wire.Error(api.CodeForbidden, "protected mutation scope has ended")
	}
	return v.service.storeLocked(ctx, info, material)
}
func (v *mutationView) Revoke(ctx context.Context, info api.SecretInfo) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.active {
		return wire.Error(api.CodeForbidden, "protected mutation scope has ended")
	}
	return v.service.revokeLocked(ctx, info, v.operation)
}
func (v *mutationView) Fetch(context.Context, api.SecretGrant) (api.SecretMaterial, error) {
	return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "protected mutation metadata does not grant material access")
}
