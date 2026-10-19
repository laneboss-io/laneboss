package secrets

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type metadataBackend interface {
	WithMetadata(context.Context, func([]api.SecretInfo) error) error
}

// Validate the caller against current stored authority, including a read
// session's actual revision/revocation. A live transport label alone cannot
// authorize protected enumeration. Do not reuse a caller's historical view.
func (s *Service) metadataCaller(ctx context.Context, scope api.Scope) error {
	if scope.Actor.Kind == "human" {
		if _, err := s.human(ctx, scope, "secret.list", false); err != nil {
			return err
		}
	} else if err := s.transport(ctx, scope, "secret.list", api.EndpointLane); err != nil {
		return err
	}
	scope.ReadView = nil
	view, err := s.deps.Store.BeginRead(ctx, scope)
	if err != nil {
		return err
	}
	if wire.Nil(view) {
		return wire.Error(api.CodeIntegrity, "secret metadata has no current authority snapshot")
	}
	if view.Snapshot().Config != s.deps.Config {
		closeErr := view.Close()
		if closeErr != nil {
			return closeErr
		}
		return wire.Error(api.CodeIntegrity, "secret metadata authority snapshot belongs to another configuration")
	}
	return view.Close()
}

func (s *Service) listMetadata(ctx context.Context, scope api.Scope) (api.SecretList, error) {
	var zero api.SecretList
	if err := s.metadataCaller(ctx, scope); err != nil {
		return zero, err
	}
	backend, ok := s.deps.Backend.(metadataBackend)
	if !ok || wire.Nil(backend) {
		return zero, wire.Error(api.CodePrerequisite, "secret metadata requires its protected authenticated backend reader")
	}
	var selected api.GrantSet
	if scope.Actor.Kind == "lane" {
		binding := scope.Connection.Binding()
		if binding.Target == nil || binding.Target.LifeID != scope.Actor.LifeID || binding.LaunchID != scope.LaunchID {
			return zero, wire.Error(api.CodeForbidden, "secret metadata differs from its exact installed life")
		}
		var err error
		selected, err = s.currentGrants(ctx, *binding.Target)
		if err != nil {
			return zero, err
		}
	}
	result := api.SecretList{Secrets: []api.SecretInfo{}}
	err := backend.WithMetadata(ctx, func(infos []api.SecretInfo) error {
		heads, known, err := s.heads(ctx, scope, infos)
		if err != nil {
			return err
		}
		byID := make(map[api.ID]api.SecretInfo, len(infos))
		for _, info := range infos {
			revoked, committed := known[info.SourceHandle]
			// Protected profile enrollment may own a source without a public
			// secret-import event. Such a source is not a published task-secret
			// head. A pending change to an existing public name still stops.
			_, publishedName := heads[info.Name]
			if committed && revoked != info.Revoked || !committed && publishedName {
				return wire.Error(api.CodeConflict, "secret source needs its original operation reconciliation")
			}
			if _, duplicate := byID[info.SourceHandle]; duplicate {
				return wire.Error(api.CodeIntegrity, "secret metadata repeats a source identity")
			}
			byID[info.SourceHandle] = info
		}
		if scope.Actor.Kind == "human" {
			for _, info := range heads {
				result.Secrets = append(result.Secrets, info)
			}
		} else {
			seen := map[api.ID]bool{}
			for _, grant := range selected.Secrets {
				if err := validateGrant(grant, s.deps.Clock.Now()); err != nil {
					return err
				}
				info, found := byID[grant.SourceHandle]
				if !found || info.Name != grant.Name || info.Version != grant.Version {
					return wire.Error(api.CodeIntegrity, "granted secret metadata differs from its protected source")
				}
				if !seen[info.SourceHandle] {
					result.Secrets = append(result.Secrets, info)
					seen[info.SourceHandle] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	if scope.Actor.Kind == "lane" {
		current, err := s.currentGrants(ctx, *scope.Connection.Binding().Target)
		if err != nil {
			return zero, err
		}
		if !reflect.DeepEqual(current, selected) {
			return zero, wire.Error(api.CodeConflict, "secret metadata grants changed during enumeration")
		}
	}
	if err := s.metadataCaller(ctx, scope); err != nil {
		return zero, err
	}
	sort.Slice(result.Secrets, func(i, j int) bool {
		a, b := result.Secrets[i], result.Secrets[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.SourceHandle < b.SourceHandle
	})
	raw, err := json.Marshal(result)
	if err != nil {
		return zero, err
	}
	if len(raw) > api.MaxFrameBytes {
		return zero, wire.Error(api.CodeBudget, "secret metadata exceeds its bounded response")
	}
	return result, nil
}
