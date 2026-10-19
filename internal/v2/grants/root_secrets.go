package grants

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

type rootSecretEnrollment interface {
	WithRootSecrets(context.Context, string, func([]api.SecretInfo, bstate.Journal) error) error
}

// Reuse the existing profile validator inside the already held native lock.
// Reentering the backend would deadlock; an unlocked metadata copy would race
// revocation. This borrowed capability is read-only and callback-bound.
type rootProfileRead struct {
	journal bstate.Journal
	active  bool
}

func (r *rootProfileRead) WithBroker(ctx context.Context, fn func(bstate.Journal) error) error {
	if !r.active || fn == nil || ctx.Err() != nil {
		return refused("root enrollment read is no longer active")
	}
	return fn(r)
}
func (r *rootProfileRead) Read(kind string, id api.ID, target any) error {
	if !r.active || kind != "profile" {
		return refused("root enrollment permits selected profile metadata only")
	}
	return r.journal.Read(kind, id, target)
}
func (*rootProfileRead) Write(string, api.ID, any) error {
	return refused("root enrollment cannot write credential records")
}
func (*rootProfileRead) Fetch(context.Context, api.SecretGrant) (api.SecretMaterial, error) {
	return api.SecretMaterial{}, refused("root enrollment cannot fetch secret material")
}
func (*rootProfileRead) AcquireRefreshLease(api.ID) (bstate.RefreshLease, error) {
	return nil, refused("root enrollment cannot acquire credential leases")
}

func (s *Service) issueSecretRoot(ctx context.Context, scope api.Scope, input api.RootGrantManifest, budget api.Budget, guard api.TransactionGuard) (api.GrantSet, error) {
	var result api.GrantSet
	backend, ok := s.deps.Profiles.(rootSecretEnrollment)
	if !ok || nilInterface(backend) {
		return result, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-grants",
			Message: "root secrets require the installed protected enrollment reader",
			Instead: "Bind the installed native secret backend; never infer enrollment from a handle."}
	}
	called := false
	err := backend.WithRootSecrets(ctx, scope.Config, func(infos []api.SecretInfo, journal bstate.Journal) (resultErr error) {
		if called || nilInterface(journal) {
			return integrity("root secret enrollment callback is missing or repeated")
		}
		called = true
		current, view, err := s.freshAuthority(ctx, scope)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
		if err := s.checkScope(ctx, current); err != nil {
			return err
		}
		if err := rootSecretHandles(input.Secrets, infos); err != nil {
			return err
		}
		if len(input.Profiles) == 0 {
			result, err = s.issueRootSet(ctx, current, input, budget, guard)
			return err
		}
		borrowed := &rootProfileRead{journal: journal, active: true}
		defer func() { borrowed.active = false }()
		bound := *s
		bound.deps.Profiles = borrowed
		result, err = bound.issueProfileRoot(ctx, current, input, budget, guard)
		return err
	})
	if err != nil {
		return api.GrantSet{}, err
	}
	if !called || result.ID == "" {
		return api.GrantSet{}, integrity("root secret enrollment did not produce a durable grant")
	}
	return result, nil
}

func rootSecretHandles(grants []api.SecretGrant, infos []api.SecretInfo) error {
	if len(infos) > 4096 {
		return integrity("root secret metadata exceeds its bounded inventory")
	}
	byHandle := make(map[api.ID]api.SecretInfo, len(infos))
	for _, info := range infos {
		if !manifest.ValidID(info.SourceHandle) || !manifest.ValidID(info.KeyID) {
			return integrity("root secret enrollment metadata is malformed")
		}
		if _, exists := byHandle[info.SourceHandle]; exists {
			return integrity("root secret enrollment repeats a source handle")
		}
		byHandle[info.SourceHandle] = info
	}
	for _, grant := range grants {
		info, found := byHandle[grant.SourceHandle]
		if !found || info.Revoked || info.Name != grant.Name || info.Version != grant.Version {
			return refused("root secret is unknown, revoked or differs from protected enrollment")
		}
	}
	return nil
}
