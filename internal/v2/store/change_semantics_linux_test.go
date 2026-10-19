//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestChangeSemanticProjectionFence(t *testing.T) {
	for _, unchanged := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed_source", true: "unchanged_source_provenance"}[unchanged], func(t *testing.T) {
			s, _, tx := deferredChangeFixture(t)
			var change api.ChangeRequest
			if err := storedProjection(context.Background(), s.db, "change", tx.Effects[0].ApplyChange.ChangeID, &change); err != nil {
				t.Fatal(err)
			}
			// Already approved component metadata isolates source-provenance gating;
			// these records do not substitute for a native renderer or human proof.
			sourcePath := change.Files[0].Path
			if unchanged {
				sourcePath = "shared/unchanged-policy.toml"
			}
			fixtureProjection(t, s, "policy", api.ID(s.deps.Config), 1, api.EffectivePolicy{Generation: 1, SHA256: testDigest([]byte("old semantic policy")), Sources: []api.SourceRef{{ID: testID(t), Path: sourcePath, SHA256: change.Files[0].After.SHA256, Generation: 1}}})
			if _, err := s.Transact(context.Background(), tx); err == nil {
				t.Fatal("apply advanced org sources without an approved semantic/provenance projection")
			}
			var rows int
			if err := s.db.QueryRow("SELECT count(*) FROM effects WHERE id=?", string(tx.Deferred.EffectID)).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 0 {
				t.Fatal("semantic projection refusal queued canonical publication")
			}
		})
	}
}
