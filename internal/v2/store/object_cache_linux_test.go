//go:build linux

package store

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func cacheRetain(t *testing.T, s *Service, scope api.Scope, raw []byte) api.BlobRef {
	t.Helper()
	scope.Request = api.Request{}
	ref := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest(raw), Bytes: int64(len(raw))}
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
	object := api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}
	if _, err := s.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
		t.Fatal("cache object retention failed", err)
	}
	return ref
}

// These are the store's existing component session fixtures, not native helper
// identity or installed-service acceptance. The ACL and object reads are real.
func cacheHuman(t *testing.T, s *Service, scope api.Scope) api.Scope {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
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
	return scope
}

func TestObjectCacheVisibility(t *testing.T) {
	s, owner, public, content := linearObjectFixture(t)
	private := cacheRetain(t, s, owner, []byte("private object "+string(testID(t))))
	if metadata, err := s.ObjectMetadata(context.Background(), owner, private.ID); err != nil || metadata.Ref != private {
		t.Fatal("private owner control failed", err)
	}
	scope := cacheHuman(t, s, owner)
	privateLoads := 0
	ctx := context.WithValue(context.Background(), objectVerificationKey{}, func(id api.ID, _ int64) {
		if id == private.ID {
			privateLoads++
		}
	})
	view, err := s.BeginObjectRead(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	scope.ReadView = view
	chunk, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: public.ID, Limit: 1})
	if err != nil || !bytes.Equal(chunk.Data, content[:1]) {
		t.Fatal("visible object cache control failed", err)
	}
	metadata, metaErr := s.ObjectMetadata(ctx, scope, private.ID)
	denied, blobErr := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: private.ID, Limit: 1})
	for _, err := range []error{metaErr, blobErr} {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			t.Fatal("private cache probe lost its visibility refusal", err)
		}
	}
	cached := view.(*readView)
	if _, exists := cached.objects[private.ID]; exists || privateLoads != 0 || cached.objectBytes != public.Bytes || len(cached.objects) != 1 || metadata.Ref.ID != "" || len(denied.Data) != 0 {
		t.Fatal("unauthorized object entered the read cache", privateLoads, cached.objectBytes, len(cached.objects))
	}
}

func TestObjectCacheBounds(t *testing.T) {
	for _, mode := range []string{"entries", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			s, scope, _, _ := linearObjectFixture(t)
			var refs []api.BlobRef
			count, size := 18, 32
			if mode == "bytes" {
				count, size = 2, (32<<20)+17
			}
			for i := 0; i < count; i++ {
				raw := bytes.Repeat([]byte{byte(i + 1)}, size)
				refs = append(refs, cacheRetain(t, s, scope, raw))
			}
			loads := map[api.ID]int{}
			ctx := context.WithValue(context.Background(), objectVerificationKey{}, func(id api.ID, _ int64) { loads[id]++ })
			view, err := s.BeginObjectRead(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			defer view.Close()
			scope.ReadView = view
			for _, ref := range refs {
				metadata, err := s.ObjectMetadata(ctx, scope, ref.ID)
				if err != nil || metadata.Ref != ref {
					t.Fatal("bounded cache metadata control failed", err)
				}
				chunk, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: 1})
				if err != nil || len(chunk.Data) != 1 || chunk.SHA256 != testDigest(chunk.Data) || loads[ref.ID] != 1 {
					t.Fatal("bounded cache repeated the current object verification", err, loads[ref.ID])
				}
				cached := view.(*readView)
				var retained int64
				for _, object := range cached.objects {
					retained += int64(len(object.data))
				}
				if len(cached.objects) > 16 || retained > 64<<20 || cached.objectBytes != retained {
					t.Fatal("object read cache exceeded its retained bounds", len(cached.objects), retained, cached.objectBytes)
				}
			}
			// Evicted bytes must be read and verified again on demand.
			if _, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: refs[0].ID, Limit: 1}); err != nil || loads[refs[0].ID] != 2 {
				t.Fatal("evicted object was not verified again", err, loads[refs[0].ID])
			}
			if err := view.Close(); err != nil || len(view.(*readView).objects) != 0 || view.(*readView).objectBytes != 0 {
				t.Fatal("closed view retained cache bytes", err)
			}
		})
	}
}
