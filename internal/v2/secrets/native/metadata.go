package native

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// WithMetadata is a protected read capability, not an RPC. The same native
// lock used by mutation keeps authenticated metadata and the caller's state
// snapshot consistent. It exports neither a material reader nor a writer.
// The callback must not reenter this backend.
func (s *Service) WithMetadata(ctx context.Context, fn func([]api.SecretInfo) error) error {
	if fn == nil {
		return wire.Error(api.CodeInvalid, "protected metadata callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, true); err != nil {
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
		// The public result has no pagination field. Refuse a collection that
		// cannot fit its bounded response rather than return a silent prefix.
		if len(names) > 4096 {
			return wire.Error(api.CodeBudget, "secret metadata exceeds its bounded inventory")
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
			// Metadata is GCM associated data. Authenticate inside the backend;
			// no Fetch or plaintext material leaves it for enumeration.
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
		return fn(infos)
	})
}
