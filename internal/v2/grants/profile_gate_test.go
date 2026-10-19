package grants

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type profileChannelStore struct {
	api.StateStore
	onRead func()
}

func (s *profileChannelStore) Channel(ctx context.Context, scope api.Scope, id api.ID) (api.EnrolledChannel, error) {
	channel, err := s.StateStore.Channel(ctx, scope, id)
	s.onRead()
	return channel, err
}

func TestProfileRelease(t *testing.T) {
	for _, source := range []string{"data", "channel"} {
		for _, change := range []string{"valid", "policy", "excluded", "scope"} {
			t.Run(source+"-"+change, func(t *testing.T) {
				f, backend, request, input := rootProfileCase(t)
				if source == "channel" {
					input.Data = []api.DataGrant{}
					input.Channels = []api.ChannelGrant{{ChannelID: "root-channel", ExpiresAt: "2030-01-01T01:00:00Z"}}
					f.store.channels = map[api.ID]api.EnrolledChannel{"root-channel": {ID: "root-channel", Config: f.scope.Config, Generation: 1, ExpiresAt: "2030-01-01T02:00:00Z"}}
					request = saveProfileInput(t, f, request, input)
				}
				scope := humanScope(t, f, "grants.root", request)
				rootProfileCommit(t, f, backend, scope)
				observed := false
				onRead := func() {
					observed = true
					switch change {
					case "policy":
						f.store.policy.Generation++
					case "excluded":
						f.store.policy.ProfileExclusions = []api.ID{input.Profiles[0].ProfileID}
					case "scope":
						scope.Connection.(*humanConnection).peer.alive = false
					}
				}
				if source == "data" {
					f.store.onBlobObject = input.Data[0].SourceObjectID
					f.store.onBlob = onRead
				} else {
					f.service.deps.Store = &profileChannelStore{StateStore: f.store, onRead: onRead}
				}
				if change == "valid" {
					commit := f.store.onTransaction
					f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
						if len(f.store.views) < 3 || tx.Scope.ReadView != f.store.views[len(f.store.views)-1] {
							t.Fatal("root profile release reused authority snapshot")
						}
						return commit(tx)
					}
				}
				result, err := f.service.GrantsRoot(context.Background(), scope, request)
				if !observed {
					t.Fatal("root profile release control did not reach its source read")
				}
				if change == "valid" {
					if err != nil || len(result.Profiles) != len(input.Profiles) || f.store.transactions != 1 {
						t.Fatal("current root profile release did not commit", err)
					}
					return
				}
				code := api.CodeForbidden
				if change == "policy" {
					code = api.CodeConflict
				}
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != code || result.ID != "" || f.store.transactions != 0 {
					t.Fatal("root profile release accepted changed "+change, err)
				}
			})
		}
	}
}
