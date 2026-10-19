//go:build linux

package store

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInitialPrivateProfileObjects(t *testing.T) {
	for _, fault := range []string{"", "no-native-seal", "unbound", "store", "scope", "key", "bytes", "class", "acl"} {
		t.Run("case-"+fault, func(t *testing.T) {
			s, _ := testStore(t)
			scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "service"}
			raw := []byte(testID(t))
			object := api.ObjectWrite{ObjectKey: testID(t), Class: "credential_evidence", Bytes: raw, SHA256: testDigest(raw), Origin: "service",
				ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "service", Generation: 1, Participants: []api.ID{}}, InputRefs: []api.BlobRef{}}
			cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
			tx := api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}
			ctx := s.initialProfileContext(context.Background(), tx)
			switch fault {
			case "no-native-seal":
				_, err := s.CommitInitial(context.Background(), tx)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
					t.Fatal("profile publication accepted a caller-created native seal", err)
				}
				return
			case "unbound":
				ctx = context.Background()
			case "store":
				other, _ := testStore(t)
				ctx = other.initialProfileContext(context.Background(), tx)
			case "scope":
				tx.Scope.Actor.ID = testID(t)
			case "key":
				tx.Writes.Objects[0].ObjectKey = testID(t)
			case "bytes":
				tx.Writes.Objects[0].Bytes[0] ^= 1
				tx.Writes.Objects[0].SHA256 = testDigest(tx.Writes.Objects[0].Bytes)
			case "class":
				tx.Writes.Objects[0].Class = "artifact"
			case "acl":
				tx.Writes.Objects[0].ACL.Owner.ID = testID(t)
			}
			_, err := s.Transact(ctx, tx)
			if fault != "" {
				if err == nil {
					t.Fatal("private profile object escaped its sealed native publication")
				}
				var count int
				if err := s.db.QueryRow("SELECT count(*) FROM objects").Scan(&count); err != nil || count != 0 {
					t.Fatal("refused private profile write left an object", err)
				}
				return
			}
			if err != nil {
				t.Fatal("sealed profile observation was not retained by the real store", err)
			}
			meta, err := s.ObjectMetadata(context.Background(), scope, object.ObjectKey)
			if err != nil || meta.Ref.Class != object.Class || meta.Ref.SHA256 != object.SHA256 || meta.ACL.Audience != "service" {
				t.Fatal("sealed profile observation lost its exact protected metadata", err)
			}
		})
	}
}
