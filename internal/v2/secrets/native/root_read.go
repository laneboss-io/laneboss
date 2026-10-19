package native

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// WithRootSecrets is an internal metadata read for root issuance. One native
// lock pins both the authenticated secret inventory and any selected profiles
// through the caller's state commit. The configuration comes from the installed
// binding; no request can select a different directory or key enrollment.
func (s *Service) WithRootSecrets(ctx context.Context, config string, fn func([]api.SecretInfo, bstate.Journal) error) error {
	if config != s.deps.Config {
		return wire.Error(api.CodeForbidden, "root secret enrollment belongs to another configuration")
	}
	if fn == nil {
		return wire.Error(api.CodeInvalid, "root secret enrollment callback is required")
	}
	return s.WithBroker(ctx, func(journal bstate.Journal) error {
		names, err := s.directory.Names()
		if err != nil {
			return err
		}
		if len(names) > 4096 {
			return wire.Error(api.CodeBudget, "root secret enrollment exceeds its bounded inventory")
		}
		infos := make([]api.SecretInfo, 0, len(names))
		for _, name := range names {
			if err := wire.Context(ctx); err != nil {
				return err
			}
			r, err := s.read(name)
			if err != nil {
				return err
			}
			if r.Info.KeyID != s.deps.KeyHandle {
				return wire.Error(api.CodeForbidden, "root secret belongs to another key enrollment")
			}
			plain, err := open(s.keys[r.Info.KeyID], r)
			clear(plain)
			if err != nil {
				return err
			}
			infos = append(infos, r.Info)
		}
		if err := wire.Context(ctx); err != nil {
			return err
		}
		return fn(infos, journal)
	})
}
