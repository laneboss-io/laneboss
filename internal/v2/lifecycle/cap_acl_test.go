package lifecycle

import (
	"bytes"
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type capSessionConn struct {
	api.ConnectionContext
	id        api.ID
	authority api.ReadAuthority
}

func (c *capSessionConn) ID() api.ID { return c.id }
func (c *capSessionConn) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	return c.authority, ctx.Err()
}

func TestCapFixtureHuman(t *testing.T) {
	f, store := newIOFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw := []byte("human capture " + string(launchIDForTest()))
	captureCommit(t, store, "stdout-stream", raw, false)
	request := api.AttachRequest{Target: f.target, Mode: "read"}
	scope := f.scope("lane.attach", request, store.root.RequestedBy)
	session := api.StoredReadSession{Session: api.HumanSession{ID: "cap-session", Config: scope.Config,
		ExpiresAt: "2030-01-02T03:05:05Z", IdleExpiresAt: "2030-01-02T03:05:05Z"},
		PrincipalID: scope.Actor.ID, CredentialID: "cap-credential", ConnectionID: "cap-connection",
		EndpointGeneration: scope.EndpointGeneration, Generation: 1}
	store.sessions[session.Session.ID] = session
	scope.Connection = &capSessionConn{ConnectionContext: scope.Connection, id: session.ConnectionID,
		authority: api.ReadAuthorityFromSession(session)}
	stream, err := f.service.OpenAttach(ctx, scope, request)
	if err != nil {
		t.Fatal("fixture rejected the root ticket's human reader", err)
	}
	defer stream.Close()
	if _, err := stream.Next(ctx); err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Next(ctx)
	if err != nil || frame.Chunk == nil || !bytes.Equal(frame.Chunk.Data, raw) {
		t.Fatal("fixture lost the human's exact captured bytes", err)
	}
	session.Revoked = true
	store.sessions[session.Session.ID] = session
	if _, err := stream.Next(ctx); err == nil {
		t.Fatal("fixture kept a revoked human capture stream open")
	}
	chunk, err := store.Blob(context.Background(), scope, api.BlobReadRequest{ObjectID: frame.Chunk.ObjectID, Limit: 100})
	if err == nil || len(chunk.Data) != 0 {
		t.Fatal("fixture returned capture bytes after session revocation")
	}
}

func TestCapFixtureACL(t *testing.T) {
	for _, mode := range []string{"grandparent", "sibling", "other-human", "peer-l5", "unauthenticated", "self", "config", "acl"} {
		t.Run(mode, func(t *testing.T) {
			f, store := newIOFixture(t)
			captureCommit(t, store, "stdout-stream", []byte("private stdout"), false)
			captureCommit(t, store, "stderr-stream", []byte("private stderr"), false)
			actor := api.Actor{Kind: "lane", ID: api.ID(mode), LifeID: api.ID(mode), Level: 5, Role: "supervisor"}
			if mode == "other-human" {
				actor = api.Actor{Kind: "human", ID: "another-human"}
			}
			if mode == "self" {
				actor.LifeID = f.target.LifeID
			}
			if mode == "config" || mode == "acl" || mode == "unauthenticated" {
				actor = f.parent
			}
			scope := f.scope("lane.attach", api.AttachRequest{Target: f.target, Mode: "read"}, actor)
			if mode == "config" {
				scope.Config = "another-config"
			}
			if mode == "unauthenticated" {
				scope.Connection = nil
			}
			for _, event := range store.events {
				if event.Kind != "capture.appended" {
					continue
				}
				record := captureRecord(t, event)
				if mode == "acl" {
					metadata := store.metadata[record.Data.ID]
					metadata.ACL.Config = "another-config"
					store.metadata[record.Data.ID] = metadata
				}
				chunk, err := store.Blob(context.Background(), scope, api.BlobReadRequest{ObjectID: record.Data.ID, Limit: 100})
				if err == nil || len(chunk.Data) != 0 {
					t.Error("fixture exposed captured bytes outside the reader set")
				}
				metadata, err := store.ObjectMetadata(context.Background(), scope, record.Data.ID)
				if err == nil || metadata.Ref.ID != "" {
					t.Error("fixture exposed capture metadata outside the reader set")
				}
			}
		})
	}
}
