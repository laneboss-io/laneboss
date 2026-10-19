package secrets

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Transport/grant decisions are explicit component facts. Native encrypted
// records and import metadata are real; the store's live-session/cause path
// is separately exercised by TestSecretMetadataRealStore.
type metadataGrantStore struct {
	*mutationState
	grantSet api.GrantSet
	lane     api.Lane
}

func (m *metadataGrantStore) BeginRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	if scope.Actor.Kind == "service" {
		return m.mutationState.BeginRead(ctx, scope)
	}
	if scope.Config != "service-case" || scope.Actor.Kind != "lane" || scope.Actor.ID != "metadata-agent" ||
		scope.Actor.LifeID != m.lane.LifeID || scope.LaunchID != "metadata-launch" {
		return nil, wire.Error(api.CodeUnauthenticated, "metadata component caller differs")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return &mutationReadView{snapshot: api.ReadSnapshot{Config: scope.Config, ID: "metadata-authority"}, events: append([]api.Event{}, m.events...)}, nil
}
func (m *metadataGrantStore) Lane(_ context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	if scope.Actor.Kind != "service" || target.LifeID != m.lane.LifeID {
		return api.Lane{}, wire.Error(api.CodeNotFound, "metadata component life differs")
	}
	return m.lane, nil
}
func (m *metadataGrantStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	if id != m.grantSet.ID {
		return api.GrantSet{}, wire.Error(api.CodeNotFound, "metadata component grants differ")
	}
	return m.grantSet, nil
}
func (m *metadataGrantStore) CurrentApprovedPolicy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	return api.EffectivePolicy{Generation: m.lane.PolicyGeneration, SHA256: digestFixture("metadata policy")}, nil
}

func metadataDelegatedCase(t *testing.T) (*Service, *metadataGrantStore, api.Scope, api.SecretInfo) {
	t.Helper()
	s, _, state, clock, _ := mutationFixture(t)
	var selected api.SecretInfo
	for _, name := range []string{"delegated", "parent-only"} {
		stage, connection := stageValue(t, s, clock, nil, name, "one", syntheticBytes(t, 67), false)
		r := api.SecretImportRequest{Name: name, Version: "one", SealedUploadID: stage.ID}
		info, err := s.SecretImport(context.Background(), mutationScope(t, clock, connection, "secret.import", r, state), r)
		if err != nil {
			t.Fatal(err)
		}
		if name == "delegated" {
			selected = info
		}
	}
	set := api.GrantSet{ID: "metadata-grants", LifeID: "metadata-child", Generation: 1, PolicyGeneration: 1, SHA256: digestFixture("metadata grants"),
		ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano)),
		Secrets:   []api.SecretGrant{{ID: "metadata-selection", Name: selected.Name, SourceHandle: selected.SourceHandle, Version: selected.Version, Delivery: "env", Target: "TASK_TOKEN", ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))}}}
	store := &metadataGrantStore{mutationState: state, grantSet: set, lane: api.Lane{LifeID: set.LifeID, Run: 1, State: "running", GrantSetID: set.ID, PolicyGeneration: 1}}
	s.deps.Store, s.deps.Grants = store, &grantsFixture{}
	scope := scopeFixture("secret.list")
	scope.Actor = api.Actor{Kind: "lane", ID: "metadata-agent", LifeID: set.LifeID, Level: 3, Role: "executor"}
	scope.LaunchID = "metadata-launch"
	binding := &scope.Connection.(*connectionFixture).binding
	binding.Class, binding.LaunchID, binding.Target = api.EndpointLane, scope.LaunchID, &api.LifeRef{LifeID: set.LifeID, Run: 1}
	return s, store, framedScope(scope), selected
}

func TestSecretMetadataDelegated(t *testing.T) {
	s, store, scope, selected := metadataDelegatedCase(t)
	before := store.grantSet
	for range 2 {
		actual, err := s.SecretList(context.Background(), scope, api.Empty{})
		if err != nil || !reflect.DeepEqual(actual.Secrets, []api.SecretInfo{selected}) {
			t.Fatal("delegated metadata exposed a parent-only source or lost exact selection", err)
		}
		if !reflect.DeepEqual(store.grantSet, before) {
			t.Fatal("metadata read changed the grant set")
		}
	}
}

func TestSecretMetadataDelegatedFences(t *testing.T) {
	for _, fault := range []string{"foreign-actor", "foreign-life", "stale-run", "revoked", "expired", "foreign-source", "missing-resolver", "missing-reader"} {
		t.Run(fault, func(t *testing.T) {
			s, store, scope, _ := metadataDelegatedCase(t)
			want := api.CodeForbidden
			switch fault {
			case "foreign-actor":
				scope.Actor.ID = "other"
				want = api.CodeUnauthenticated
			case "foreign-life":
				scope.Actor.LifeID = "other"
			case "stale-run":
				scope.Connection.(*connectionFixture).binding.Target.Run++
				want = api.CodeConflict
			case "revoked":
				store.grantSet.Revoked = true
			case "expired":
				store.grantSet.Secrets[0].ExpiresAt = "2000-01-01T00:00:00Z"
			case "foreign-source":
				store.grantSet.Secrets[0].SourceHandle = "foreign"
				want = api.CodeIntegrity
			case "missing-resolver":
				s.deps.Grants = nil
				want = api.CodePrerequisite
			case "missing-reader":
				s.deps.Backend = &backendFixture{}
				want = api.CodePrerequisite
			}
			actual, err := s.SecretList(context.Background(), scope, api.Empty{})
			stageCode(t, err, want)
			if len(actual.Secrets) != 0 {
				t.Fatal("refused delegated metadata returned source names")
			}
		})
	}
}
