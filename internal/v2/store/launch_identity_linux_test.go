//go:build linux

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestLaneIdentityRequiresPlan(t *testing.T) {
	for _, origin := range []string{"service", "legacy_import"} {
		t.Run(origin, func(t *testing.T) {
			s, _ := testStore(t)
			input, binding := identityIntent(t)
			input.Events[0].Origin = origin
			if _, err := s.Transact(context.Background(), input); err == nil {
				t.Fatal("unreserved lane identity accepted " + origin)
			} else {
				expectCode(t, err, api.CodeForbidden)
			}
			if _, err := s.Launch(context.Background(), binding.Record.ID); err == nil {
				t.Fatal("refused identity left a live launch projection")
			} else {
				expectCode(t, err, api.CodeNotFound)
			}
		})
	}
}

func TestHistoricalIdentityStaysInert(t *testing.T) {
	s, _ := testStore(t)
	// The closed catalog declares no historical identity-import kind.
	// Migration may retain inert record history; it cannot mint an identity.
	input := testTransaction(t)
	input.Scope.Request, input.Reply = api.Request{}, nil
	input.Events[0].Origin = "legacy_import"
	var record api.Record
	if err := json.Unmarshal(input.Events[0].Payload, &record); err != nil {
		t.Fatal(err)
	}
	record.Origin = "legacy_import"
	var err error
	input.Events[0].Payload, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	input.Internal = &api.InternalIntent{ID: testID(t), Kind: api.InternalMigrationApply, Config: input.Scope.Config, Actor: input.Scope.Actor, RequestedBy: input.Scope.Actor}
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal("inert historical record import failed", err)
	}
	var saved api.Record
	if err := storedProjection(context.Background(), s.db, "record", record.ID, &saved); err != nil || saved.Origin != "legacy_import" {
		t.Fatal("historical record lost its inert provenance", err)
	}
	identity, binding := identityIntent(t)
	identity.Internal.Kind = api.InternalMigrationApply
	identity.Events[0].Origin = "legacy_import"
	if _, err := s.Transact(context.Background(), identity); err == nil {
		t.Fatal("migration emitter promoted historical identity to live authority")
	} else {
		expectCode(t, err, api.CodeInvalid)
	} // The closed emitter matrix refuses this kind.
	if _, err := s.Launch(context.Background(), binding.Record.ID); err == nil {
		t.Fatal("historical identity authenticated as a current launch")
	} else {
		expectCode(t, err, api.CodeNotFound)
	}
}

func TestOperationDigestProvenance(t *testing.T) {
	for _, source := range []string{"public", "internal"} {
		t.Run(source, func(t *testing.T) {
			s, _ := testStore(t)
			input := testPendingTransaction(t)
			originalDigest := input.Scope.Request.RequestSHA256
			if source == "internal" {
				intent := *input.Effects[0].Context
				intent.ID, intent.Kind = testID(t), api.InternalLifecycleEffect
				input.Internal = &intent
				input.Scope.Request, input.Events, input.Reply = api.Request{}, nil, nil
			}
			ctx := context.Background()
			if _, err := s.Transact(ctx, input); err != nil {
				t.Fatal("operation provenance setup failed", err)
			}
			claim, err := s.ClaimEffect(ctx, input.Scope, api.EffectClaimRequest{EffectID: input.Effects[0].ID, ExpectedGeneration: 1, ClaimantID: input.Scope.Actor.ID, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
			if err != nil {
				t.Fatal(err)
			}
			commit, err := s.CompleteEffect(ctx, input.Scope, api.EffectOutcome{EffectID: input.Effects[0].ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "failed", Error: api.NotImplemented("lb-v2-admin", "component measured failure")})
			if err != nil {
				t.Fatal("operation provenance completion failed", err)
			}
			var data []byte
			if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=?", uint64(commit.LastSeq)).Scan(&data); err != nil {
				t.Fatal(err)
			}
			var event api.Event
			if err := wire.Decode(data, &event); err != nil {
				t.Fatal(err)
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(event.Payload, &members); err != nil {
				t.Fatal(err)
			}
			_, present := members["request_sha256"]
			if source == "internal" && present {
				t.Fatal("internal completion invented a public request digest")
			}
			var payload api.OperationEvent
			if err := wire.Decode(event.Payload, &payload); err != nil {
				t.Fatal("operation payload no longer matches the wire schema", err)
			}
			if source == "public" && (!present || payload.RequestSHA256 != originalDigest) {
				t.Fatal("public completion lost its actual retained request digest")
			}
			if source == "internal" && payload.RequestSHA256 != "" {
				t.Fatal("internal completion decoded a synthetic request digest")
			}
			if verification, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verification.OK {
				t.Fatal("operation digest journal did not verify", err)
			}
		})
	}
}
