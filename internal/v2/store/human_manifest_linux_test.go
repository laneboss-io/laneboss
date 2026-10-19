//go:build linux

package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
)

// This composes real enrollment/session finalization and the durable upload
// writer. The authenticated native peer/assertion remain declared fixtures.
func TestHumanManifestUpload(t *testing.T) {
	s, scope, _, _ := committedSessionFixture(t)
	ctx := context.Background()
	identities, err := identity.New(identity.Dependencies{Peers: &sessionPeerTripwire{}, Registry: &sessionRegistryTripwire{}, Store: s, Sessions: s, Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.FinalizeHumanSession(ctx, scope); err != nil {
		t.Fatal("human upload fixture did not finalize its actual session", err)
	}
	content := enrollmentJSON(t, map[string]string{"schema": "inert-manifest-proposal", "nonce": string(testID(t))})
	id, digest := testID(t), testDigest(content)
	expiry := api.Timestamp(s.deps.Clock.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339Nano))
	lease := api.UploadLease{ID: id, Class: "manifest", DeclaredBytes: int64(len(content)), SHA256: digest, ExpiresAt: expiry,
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}
	ref := api.BlobRef{ID: id, Class: lease.Class, Bytes: lease.DeclaredBytes, SHA256: digest}
	upload := api.BlobUpload{ObjectID: id, MaxChunkBytes: api.MaxChunkBytes, ExpiresAt: expiry}
	commit := func(method api.Method, body any, writes api.StateWrites, events []api.Event, reply any) {
		t.Helper()
		scope.Request = testRequest(t, method, body)
		scope.Frame = &sessionCommitFrame{raw: enrollmentJSON(t, scope.Request)}
		var err error
		scope, err = api.WithReadAuthority(ctx, scope)
		if err != nil {
			t.Fatal("manifest upload lost current same-connection authority", err)
		}
		result, err := s.Transact(ctx, api.Transaction{Scope: scope, RawRequest: scope.Frame.Bytes(), Writes: writes,
			Events: events, Reply: &api.RPCReply{Result: enrollmentJSON(t, reply)}})
		if err != nil || result.Reply == nil || result.Reply.Error != nil {
			t.Fatal("human manifest upload did not commit through its current session", err)
		}
	}
	commit("blob.begin", api.BlobBeginRequest{Class: lease.Class, Bytes: lease.DeclaredBytes, SHA256: digest},
		api.StateWrites{UploadBegins: []api.UploadLease{lease}}, nil, upload)
	chunk := api.BlobChunk{ObjectID: id, Data: content, SHA256: digest}
	commit("blob.chunk", chunk, api.StateWrites{UploadChunks: []api.BlobChunk{chunk}}, nil, upload)
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "blob.committed", Actor: scope.Actor,
		RequestedBy: scope.Actor, Origin: "observation", StarterChain: []api.ID{}, Payload: enrollmentJSON(t, ref)}
	commit("blob.commit", api.BlobCommitRequest{ObjectID: id, SHA256: digest},
		api.StateWrites{UploadCommits: []api.BlobCommitRequest{{ObjectID: id, SHA256: digest}}}, []api.Event{event}, ref)
	scope.Request = testRequest(t, "blob.read", api.BlobReadRequest{ObjectID: id, Limit: len(content)})
	metadata, err := s.ObjectMetadata(ctx, scope, id)
	if err != nil || metadata.Ref != ref || metadata.ACL.Owner != scope.Actor || metadata.ACL.Config != scope.Config ||
		metadata.ACL.Audience != "owner" || metadata.Origin != "observation" || metadata.SourceOperationID == "" {
		t.Fatal("uploaded manifest acquired trusted provenance or lost its owner", err)
	}
	actual, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: id, Limit: len(content)})
	if err != nil || !bytes.Equal(actual.Data, content) || actual.SHA256 != digest {
		t.Fatal("committed human manifest bytes differ", err)
	}
}

func TestManifestEmitterBoundary(t *testing.T) {
	s, _ := testStore(t)
	for _, actor := range []string{"human", "lane", "worker"} {
		for _, class := range []string{"manifest", "capture", "policy", "archive", "approval", "launch_spec"} {
			if actor == "human" && class == "manifest" {
				continue // The positive durable path is exercised above.
			}
			t.Run(actor+"/"+class, func(t *testing.T) {
				tx, err := s.db.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: actor, ID: testID(t)}}
				lease := api.UploadLease{ID: testID(t), Class: class, DeclaredBytes: 1, SHA256: testDigest([]byte("x")),
					ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)),
					ACL:       api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}
				err = s.uploadWrites(context.Background(), tx, api.Transaction{Scope: scope, Writes: api.StateWrites{UploadBegins: []api.UploadLease{lease}}},
					testID(t), api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), "UploadBegins")
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "upload class requires its trusted emitter" {
					t.Fatal("public upload bypassed the trusted emitter boundary")
				}
			})
		}
	}
}
