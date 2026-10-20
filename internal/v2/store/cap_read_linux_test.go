//go:build linux

package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type capConnection struct {
	*fx.Connection
	authority api.ReadAuthority
}

func (c *capConnection) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	if err := c.Peer().Alive(ctx); err != nil {
		return api.ReadAuthority{}, err
	}
	return c.authority, nil
}

// Only enrollment/session inputs are modeled. Launches, ticket redemption,
// retained capture bytes and all reads use the production store.
func capHuman(t *testing.T, f *fx.Fixture, actor api.Actor) api.Scope {
	t.Helper()
	connection := &capConnection{Connection: &fx.Connection{Identity: fx.ID(t),
		Endpoint: api.InstalledBinding{Config: f.Deps.Config, Class: api.EndpointHuman, EndpointGeneration: 1},
		Verified: &fx.Peer{}}}
	expires := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	session := api.StoredReadSession{Session: api.HumanSession{ID: fx.ID(t), Config: f.Deps.Config,
		ExpiresAt: expires, IdleExpiresAt: expires}, PrincipalID: actor.ID, CredentialID: fx.ID(t),
		ConnectionID: connection.ID(), EndpointGeneration: 1, Generation: 1}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "enrollment", actor.ID, 1, api.HumanEnrollment{Config: f.Deps.Config,
		PrincipalID: actor.ID, Origin: "https://capture.invalid", RPID: "capture.invalid", Generation: 1,
		Credentials: []api.HumanCredential{{ID: session.CredentialID, RawCredentialID: []byte(fx.ID(t)),
			Algorithm: "EdDSA", PublicKeyDER: der, Generation: 1}}})
	f.Replace(t, "read_session", session.Session.ID, 1, session)
	connection.authority = api.ReadAuthorityFromSession(session)
	return api.Scope{Config: f.Deps.Config, Actor: actor, Connection: connection,
		EndpointGeneration: 1, PolicyGeneration: 1, Source: "cli"}
}

type capIdentity struct{ api.Authenticator }

func capInviteFixture(t *testing.T) *fx.Fixture {
	t.Helper()
	f := fx.Ready(t, true)
	f.Opened(t)
	return f
}

// Model the read-session DTO only; this helper never seeds the enrollment.
// The invitation/approval product writes its active credential inventory.
func capAdmissionReader(t *testing.T, f *fx.Fixture, enrollment api.HumanEnrollment) api.Scope {
	t.Helper()
	c := &capConnection{Connection: &fx.Connection{Identity: fx.ID(t), Endpoint: api.InstalledBinding{Config: f.Deps.Config, Class: api.EndpointHuman, EndpointGeneration: 1}, Verified: &fx.Peer{}}}
	expires := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	session := api.StoredReadSession{Session: api.HumanSession{ID: fx.ID(t), Config: f.Deps.Config, ExpiresAt: expires, IdleExpiresAt: expires},
		PrincipalID: enrollment.PrincipalID, CredentialID: enrollment.Credentials[0].ID, ConnectionID: c.ID(), EndpointGeneration: 1, Generation: 1}
	f.Replace(t, "read_session", session.Session.ID, 1, session)
	c.authority = api.ReadAuthorityFromSession(session)
	return api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "human", ID: enrollment.PrincipalID}, Connection: c, EndpointGeneration: 1}
}

func capAdminRequest(t *testing.T, scope api.Scope, request api.HumanAccessRequest) api.Scope {
	t.Helper()
	scope = capRequest(t, scope, "human.enroll", request)
	scope.Frame = &fx.Frame{Raw: fx.JSON(t, scope.Request)}
	return scope
}

func (capIdentity) Authorize(ctx context.Context, scope api.Scope, _ api.Request) error {
	if scope.Connection == nil || scope.Connection.Peer() == nil {
		return &api.Error{Code: api.CodeUnauthenticated, Message: "capture fixture requires its peer"}
	}
	return scope.Connection.Peer().Alive(ctx)
}

func capRequest(t *testing.T, scope api.Scope, method api.Method, params any) api.Scope {
	t.Helper()
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config,
		Method: method, RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, params)}
	var err error
	scope.Request.RequestSHA256, err = wire.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func capAppend(t *testing.T, f *fx.Fixture) map[api.ID][]byte {
	t.Helper()
	result := map[api.ID][]byte{}
	for _, stream := range f.Plan.Capture.Streams {
		if stream.Stream != "stdout" && stream.Stream != "stderr" {
			continue
		}
		raw := []byte(stream.Stream + " captured " + string(fx.ID(t)) + "\x00\xff\n")
		ref := f.CaptureData(t, raw)
		state, err := f.State.CaptureState(context.Background(), f.Worker, f.Plan.Capture.ID)
		if err != nil {
			t.Fatal(err)
		}
		request := f.AppendRequest(t, &ref, false)
		request.StreamID, request.ExpectedGeneration = stream.ID, state.Generation
		appended, err := f.State.AppendCapture(context.Background(), f.Worker, request)
		if err != nil {
			t.Fatal(err)
		}
		request.Offset, request.ExpectedGeneration = appended.NextOffset, appended.Generation
		request.Data, request.EOF = nil, true
		if _, err := f.State.AppendCapture(context.Background(), f.Worker, request); err != nil {
			t.Fatal(err)
		}
		result[ref.ID] = raw
	}
	if len(result) != 2 {
		t.Fatal("fixture lacks both actual capture streams")
	}
	return result
}

func capRead(t *testing.T, f *fx.Fixture, scope api.Scope, want map[api.ID][]byte, code api.ErrorCode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for id, raw := range want {
		request := api.BlobReadRequest{ObjectID: id, Limit: api.MaxChunkBytes}
		reader := capRequest(t, scope, "blob.read", request)
		chunk, err := f.State.Blob(ctx, reader, request)
		if code != "" {
			launchCode(t, err, code)
			if len(chunk.Data) != 0 {
				t.Fatal("refused capture read returned bytes")
			}
		} else if err != nil || chunk.ObjectID != id || chunk.Offset != 0 ||
			!bytes.Equal(chunk.Data, raw) || chunk.SHA256 != fx.Digest(raw) {
			t.Fatalf("public blob.read lost exact capture bytes: %v", err)
		}
		metadata, err := f.State.ObjectMetadata(ctx, reader, id)
		if code != "" {
			launchCode(t, err, code)
			if metadata.Ref.ID != "" {
				t.Fatal("refused capture read returned metadata")
			}
		} else if err != nil || metadata.Ref.ID != id {
			t.Fatalf("authorized capture metadata is absent: %v", err)
		}
	}
	svc, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: capIdentity{}, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	request := api.AttachRequest{Target: f.Reservation.Target, Mode: "read"}
	stream, err := svc.OpenAttach(ctx, capRequest(t, scope, "lane.attach", request), request)
	if code != "" {
		if stream != nil {
			stream.Close()
			t.Fatal("refused lane.attach opened a stream")
		}
		launchCode(t, err, code)
		return
	}
	if err != nil {
		t.Fatalf("public lane.attach lost its reader: %v", err)
	}
	defer stream.Close()
	seen := map[api.ID]bool{}
	for i := 0; i < 8; i++ {
		frame, err := stream.Next(ctx)
		if err != nil || frame.Error != nil {
			t.Fatalf("public lane.attach lost a capture frame: %v, %v", err, frame.Error)
		}
		if frame.End {
			if len(seen) != len(want) {
				t.Fatal("attach omitted a captured stream")
			}
			return
		}
		if frame.Chunk != nil {
			chunk := frame.Chunk
			if seen[chunk.ObjectID] || !bytes.Equal(chunk.Data, want[chunk.ObjectID]) || chunk.SHA256 != fx.Digest(chunk.Data) {
				t.Fatal("attach repeated or changed captured bytes")
			}
			seen[chunk.ObjectID] = true
		}
	}
	t.Fatal("attach did not reach retained EOF")
}

func capCase(t *testing.T, reader string) {
	t.Helper()
	root := fx.Ready(t, true)
	owner := capHuman(t, root, root.Human.Actor)
	var other api.Scope
	if reader == "other-human" {
		other = capHuman(t, root, api.Actor{Kind: "human", ID: fx.ID(t)})
	}
	root.Opened(t)
	parent := cascadeChild(t, root, 4)
	child := cascadeChild(t, parent, 3)
	scope, code := owner, api.ErrorCode("")
	switch reader {
	case "parent":
		scope = parent.LaneScope(t)
	case "grandparent":
		scope, code = root.LaneScope(t), api.CodeNotFound
	case "sibling":
		scope, code = cascadeChild(t, parent, 3).LaneScope(t), api.CodeNotFound
	case "other-human":
		scope, code = other, api.CodeNotFound
	case "peer-l5":
		peer := fx.NewIn(t, root.State, root.Deps)
		peer.Reserve(t)
		peer.Source(t)
		peer.BuildPlan(t, true)
		peer.Spec(t)
		peer.Bind(t)
		root.State, parent.State, child.State = peer.State, peer.State, peer.State
		scope, code = peer.LaneScope(t), api.CodeNotFound
	case "unauthenticated":
		scope.Connection, code = nil, api.CodeUnauthenticated
	case "self":
		scope, code = child.LaneScope(t), api.CodeNotFound
	}
	want := capAppend(t, child)
	capRead(t, child, scope, want, code)
}

func TestCapOwner(t *testing.T)       { capCase(t, "owner") }
func TestCapParent(t *testing.T)      { capCase(t, "parent") }
func TestCapGrandparent(t *testing.T) { capCase(t, "grandparent") }
func TestCapSibling(t *testing.T)     { capCase(t, "sibling") }
func TestCapOtherHuman(t *testing.T)  { capCase(t, "other-human") }
func TestCapPeerL5(t *testing.T)      { capCase(t, "peer-l5") }
func TestCapUnauth(t *testing.T)      { capCase(t, "unauthenticated") }
func TestCapSelf(t *testing.T)        { capCase(t, "self") }
