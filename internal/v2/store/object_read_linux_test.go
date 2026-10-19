//go:build linux

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func linearObjectFixture(t *testing.T) (*Service, api.Scope, api.BlobRef, []byte) {
	t.Helper()
	s, _ := testStore(t)
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "worker"}
	seed := []byte(testID(t))
	content := bytes.Repeat(seed, (3*api.MaxChunkBytes+19)/len(seed)+1)[:3*api.MaxChunkBytes+19]
	ref := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest(content), Bytes: int64(len(content))}
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
	object := api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: content, SHA256: ref.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "human", Participants: []api.ID{testID(t)}, Generation: 1}}
	if _, err := s.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
		t.Fatal("linear object retention setup failed", err)
	}
	scope.Request = testRequest(t, "blob.read", api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
	return s, scope, ref, content
}

func linearReadBack(ctx context.Context, s *Service, scope api.Scope, ref api.BlobRef) (result []byte, resultErr error) {
	scope, release, err := objectread.Bind(ctx, s, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	metadata, err := s.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil || metadata.Ref != ref {
		return nil, errors.Join(err, fault(api.CodeIntegrity, "linear object metadata differs"))
	}
	for int64(len(result)) < ref.Bytes {
		offset := int64(len(result))
		limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-offset))
		chunk, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: offset, Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) != limit || chunk.SHA256 != testDigest(chunk.Data) {
			return nil, fault(api.CodeIntegrity, "linear object chunk differs")
		}
		result = append(result, chunk.Data...)
	}
	tail, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
	if err != nil {
		return nil, err
	}
	if tail.ObjectID != ref.ID || tail.Offset != ref.Bytes || len(tail.Data) != 0 || tail.SHA256 != testDigest(nil) || testDigest(result) != ref.SHA256 {
		return nil, fault(api.CodeIntegrity, "linear object read-back is incomplete")
	}
	return result, nil
}

func TestObjectReadLinear(t *testing.T) {
	s, scope, ref, content := linearObjectFixture(t)
	var loads, loaded atomic.Int64
	ctx := context.WithValue(context.Background(), objectVerificationKey{}, func(id api.ID, size int64) {
		if id == ref.ID {
			loads.Add(1)
			loaded.Add(size)
		}
	})
	actual, err := linearReadBack(ctx, s, scope, ref)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("linear persisted read-back failed", err)
	}
	if loads.Load() != 1 || loaded.Load() != ref.Bytes {
		t.Fatal("multi-chunk read repeated full verification", loads.Load(), loaded.Load(), ref.Bytes)
	}
	if len(s.views) != 0 {
		t.Fatal("whole object read retained request view")
	}
	// A second request must load and verify the persisted object again.
	actual, err = linearReadBack(ctx, s, scope, ref)
	if err != nil || !bytes.Equal(actual, content) || loads.Load() != 2 || loaded.Load() != 2*ref.Bytes {
		t.Fatal("verified bytes escaped their request lifetime", err, loads.Load())
	}
}

func TestObjectReadTamper(t *testing.T) {
	for _, mode := range []string{"byte", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			s, scope, ref, content := linearObjectFixture(t)
			// Corrupt this disposable fixture, then restore its immutability
			// trigger before opening the actual production read view.
			if _, err := s.db.Exec("DROP TRIGGER objects_no_update"); err != nil {
				t.Fatal(err)
			}
			if mode == "byte" {
				bad := bytes.Clone(content)
				bad[len(bad)/2] ^= 1
				if _, err := s.db.Exec("UPDATE objects SET data=? WHERE id=?", bad, string(ref.ID)); err != nil {
					t.Fatal(err)
				}
			} else {
				var raw []byte
				if err := s.db.QueryRow("SELECT metadata FROM objects WHERE id=?", string(ref.ID)).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var metadata api.ObjectMetadata
				if err := json.Unmarshal(raw, &metadata); err != nil {
					t.Fatal(err)
				}
				metadata.Ref.SHA256 = testDigest([]byte(testID(t)))
				raw, err := json.Marshal(metadata)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec("UPDATE objects SET metadata=? WHERE id=?", raw, string(ref.ID)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec("CREATE TRIGGER objects_no_update BEFORE UPDATE ON objects BEGIN SELECT RAISE(ABORT, 'immutable objects'); END"); err != nil {
				t.Fatal(err)
			}
			view, err := s.BeginObjectRead(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := view.Close(); err != nil {
					t.Error(err)
				}
			})
			scope.ReadView = view
			chunk, err := s.Blob(context.Background(), scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "committed object bytes disagree with metadata" || len(chunk.Data) != 0 {
				t.Fatal("verified read accepted tampered object", err)
			}
		})
	}
}

func TestObjectReadScope(t *testing.T) {
	for _, mode := range []string{"request", "caller", "closed", "cancelled", "metadata_copy", "chunk_copy"} {
		t.Run(mode, func(t *testing.T) {
			s, scope, ref, content := linearObjectFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			view, err := s.BeginObjectRead(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := view.Close(); err != nil {
					t.Error(err)
				}
			})
			scope.ReadView = view
			metadata, err := s.ObjectMetadata(ctx, scope, ref.ID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "metadata_copy" {
				original := metadata.ACL.Participants[0]
				metadata.ACL.Participants[0] = testID(t)
				actual, err := s.ObjectMetadata(ctx, scope, ref.ID)
				if err != nil || actual.ACL.Participants[0] != original {
					t.Fatal("metadata caller mutated the verified pin", err)
				}
				return
			}
			if mode == "chunk_copy" {
				q := api.BlobReadRequest{ObjectID: ref.ID, Limit: 1}
				first, err := s.Blob(ctx, scope, q)
				if err != nil {
					t.Fatal(err)
				}
				first.Data[0] ^= 1
				second, err := s.Blob(ctx, scope, q)
				if err != nil || second.Data[0] != content[0] {
					t.Fatal("chunk caller mutated verified bytes", err)
				}
				return
			}
			switch mode {
			case "request":
				scope.Request.RequestID = testID(t)
			case "caller":
				scope.Actor.ID = testID(t)
			case "closed":
				if err := view.Close(); err != nil {
					t.Fatal(err)
				}
				if len(view.(*readView).objects) != 0 {
					t.Fatal("closed request retained verified bytes")
				}
			case "cancelled":
				cancel()
			}
			chunk, err := s.Blob(context.Background(), scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: 1})
			if mode == "cancelled" {
				if !errors.Is(err, context.Canceled) || len(chunk.Data) != 0 {
					t.Fatal("cancelled request reused verified bytes", err)
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated || len(chunk.Data) != 0 {
					t.Fatal("verified read crossed request binding", err)
				}
			}
		})
	}
}

func TestObjectReadRevocation(t *testing.T) {
	s, scope, ref, _ := linearObjectFixture(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	principal, credential, sessionID := testID(t), testID(t), testID(t)
	connection := &scopeConnection{id: testID(t), conn: a, peer: &scopePeer{}, binding: api.InstalledBinding{Config: scope.Config, Class: api.EndpointHuman, EndpointGeneration: 7}}
	end := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	idle := api.Timestamp(time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))
	connection.authority = &api.ReadAuthority{SessionID: sessionID, PrincipalID: principal, CredentialID: credential, Config: scope.Config,
		ConnectionID: connection.id, Generation: 1, EndpointGeneration: 7, ExpiresAt: end, IdleExpiresAt: idle}
	session := api.StoredReadSession{Session: api.HumanSession{ID: sessionID, Config: scope.Config, ExpiresAt: end, IdleExpiresAt: idle},
		PrincipalID: principal, CredentialID: credential, ConnectionID: connection.id, EndpointGeneration: 7, Generation: 1}
	fixtureProjection(t, s, "read_session", sessionID, 1, session)
	fixtureProjection(t, s, "enrollment", principal, 1, api.HumanEnrollment{Config: scope.Config, PrincipalID: principal, Generation: 1,
		Credentials: []api.HumanCredential{{ID: credential, Generation: 1}}})
	scope.Actor, scope.Connection, scope.EndpointGeneration, scope.Source = api.Actor{Kind: "human", ID: principal}, connection, 7, "cli"
	view, err := s.BeginObjectRead(context.Background(), scope)
	if err != nil {
		t.Fatal("live object read session setup failed", err)
	}
	t.Cleanup(func() {
		if err := view.Close(); err != nil {
			t.Error(err)
		}
	})
	scope.ReadView = view
	q := api.BlobReadRequest{ObjectID: ref.ID, Limit: 1}
	if _, err := s.Blob(context.Background(), scope, q); err != nil {
		t.Fatal("live object read session failed", err)
	}
	session.Revoked, session.Generation = true, 2
	fixtureProjection(t, s, "read_session", sessionID, 2, session)
	chunk, err := s.Blob(context.Background(), scope, q)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated || len(chunk.Data) != 0 {
		t.Fatal("verified read reused revoked authority", err)
	}
}
