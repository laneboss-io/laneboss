package grants

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *fixtureStore) RootGrantEvent(_ context.Context, scope api.Scope, id api.ID) (api.Event, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("root issuance read lost its configuration")
	}
	for _, event := range s.events {
		if event.Kind != "grants.issued" || event.LifeID != s.sets[id].LifeID {
			continue
		}
		var issued api.GrantEvent
		if err := api.DecodeObject(event.Payload, &issued); err != nil {
			return api.Event{}, err
		}
		if issued.GrantSet.ID == id {
			return clone(s.t, event), nil
		}
	}
	return api.Event{}, &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-service", Message: "selected root issuance is absent"}
}

func TestHumanRootTemplateRead(t *testing.T) {
	for _, name := range []string{"valid", "connection", "class", "principal", "config", "endpoint", "expired", "idle", "ended", "absent", "lane", "digest", "other-principal", "issuance-absent"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := rootFixture(t, f)
			issuer := humanScope(t, f, "grants.root", request)
			f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
				if err := api.ValidateTransactionShape(tx); err != nil {
					t.Fatal("invalid root read fixture transaction", err)
				}
				for _, set := range tx.Writes.Grants {
					f.store.sets[set.ID] = clone(t, set)
				}
				for _, event := range tx.Events {
					event.Seq = api.Sequence(len(f.store.events) + 1)
					f.store.events = append(f.store.events, clone(t, event))
				}
				id, err := freshID()
				if err != nil {
					t.Fatal(err)
				}
				return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: id, Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
			}
			root, err := f.service.GrantsRoot(context.Background(), issuer, request)
			if err != nil {
				t.Fatal("root read fixture issuance failed", err)
			}
			if _, exists := f.store.lanes[root.LifeID]; exists || root.ParentLifeID != "" {
				t.Fatal("root read fixture unexpectedly has a lane or parent")
			}
			get := api.GrantGetRequest{GrantSetID: root.ID}
			scope := humanScope(t, f, "grants.get", get)
			scope.Request.Proof, scope.Frame = nil, nil // Reads use the live read session.
			if actual, err := f.service.GrantsGet(context.Background(), scope, get); err != nil || !reflect.DeepEqual(actual, root) {
				t.Fatal("human cannot read its issued root template", err)
			}
			if name == "valid" {
				return
			}
			code := api.CodeForbidden
			switch name {
			case "connection":
				scope.Connection = nil
			case "class":
				scope.Connection.(*humanConnection).binding.Class = api.EndpointLane
			case "principal":
				scope.Connection.(*humanConnection).authority.PrincipalID = "other"
			case "config":
				scope.Connection.(*humanConnection).authority.Config = "other"
			case "endpoint":
				scope.Connection.(*humanConnection).authority.EndpointGeneration++
			case "expired":
				scope.Connection.(*humanConnection).authority.ExpiresAt = "2029-01-01T00:00:00Z"
			case "idle":
				scope.Connection.(*humanConnection).authority.IdleExpiresAt = "2029-01-01T00:00:00Z"
			case "ended":
				scope.Connection.(*humanConnection).peer.alive = false
			case "absent":
				get.GrantSetID = "missing-root"
				code = api.CodeNotFound
			case "lane":
				scope = f.scope
				code = api.CodeNotFound
			case "digest":
				changed := clone(t, root)
				changed.Data[0].SourceObjectID = "substituted-source"
				f.store.sets[root.ID] = changed
				code = api.CodeIntegrity
			case "other-principal":
				scope.Actor.ID = "other-human"
				scope.Connection.(*humanConnection).authority.PrincipalID = scope.Actor.ID
				scope.Connection.(*humanConnection).authority.SessionID = "other-read-session"
				scope.Connection.(*humanConnection).authority.CredentialID = "other-key"
				scope.Connection.(*humanConnection).id = "other-connection"
				if err := f.service.humanRead(context.Background(), scope); err != nil {
					t.Fatal("other principal lacks its own valid read session", err)
				}
				code = api.CodeNotFound
			case "issuance-absent":
				f.store.events = nil
				code = api.CodeNotFound
			}
			actual, err := f.service.GrantsGet(context.Background(), scope, get)
			expectCode(t, err, code)
			if !reflect.DeepEqual(actual, api.GrantSet{}) {
				t.Fatal("refused root read returned grant data")
			}
		})
	}
}
