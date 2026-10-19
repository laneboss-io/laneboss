//go:build linux

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// These compose real socket/framing/storage components under fixture identities.
// They neither enable the public binding constructor nor implement identity.
func socketRecord(t *testing.T, state **store.Service, directory string) (api.Scope, api.Record) {
	t.Helper()
	f := fx.NewIn(t, *state, store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	*state = f.State
	ctx := context.Background()
	launch, actor := f.Binding.Record, f.Binding.Record.Actor
	content := []byte("component scoped record " + string(fixtureID(t)))
	ref := f.Retain(t, "record", content, actor, actor.LifeID)
	f.Opened(t)
	scope := api.Scope{Config: launch.Config, Actor: actor, LaunchID: launch.ID,
		EndpointGeneration: launch.EndpointGeneration, PolicyGeneration: launch.PolicyGeneration, Source: "cli"}
	record := api.Record{ID: fixtureID(t), Collection: "observations", LifeID: actor.LifeID, Run: 1,
		Content: ref, Actor: actor, Origin: "observation", Generation: 1,
		RecordedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	scope.Request = requestFor(t, "records.append", api.RecordAppendRequest{Collection: record.Collection,
		Content: record.Content, RelatedIDs: []api.ID{}})
	event := api.Event{Schema: api.SchemaVersion, ID: fixtureID(t), Config: scope.Config, Kind: "record.appended",
		Actor: actor, RequestedBy: actor, LifeID: actor.LifeID, Run: 1, Origin: "observation", StarterChain: []api.ID{}, Payload: fx.JSON(t, record)}
	if _, err := (*state).Transact(ctx, api.Transaction{Scope: scope, Events: []api.Event{event}, Reply: &api.RPCReply{Result: event.Payload}}); err != nil {
		t.Fatal(err)
	}
	return scope, record
}

func socketCall(t *testing.T, server *Server, request api.Request) api.Response {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rpc.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.EnableCredentials(listener); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil {
				t.Error("socket fixture accept failed")
			}
			return
		}
		defer connection.Close()
		server.serveConnection(ctx, connection)
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		stop()
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("socket fixture did not quiesce")
		}
	})
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(client, data); err != nil {
		t.Fatal(err)
	}
	data, err = wire.ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	response, err := wire.DecodeResponse(data, request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestSocketScopedRecords(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("socket storage fixture requires an unprivileged Linux UID")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".lb-v2-service-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	caller, wanted := socketRecord(t, &state, directory)
	_, sibling := socketRecord(t, &state, directory)
	head, err := state.HealthSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	server := fixtureServer(t)
	server.deps.Store = state
	server.deps.Authenticator = &authFixture{scope: caller, store: state}
	server.deps.Binding.LaunchID = caller.LaunchID
	server.deps.Binding.Target = &api.LifeRef{LifeID: caller.Actor.LifeID, Run: 1}
	if err := server.Register("records.query", func(ctx context.Context, scope api.Scope, data json.RawMessage) (json.RawMessage, error) {
		var request api.RecordQuery
		if err := wire.Decode(data, &request); err != nil {
			return nil, err
		}
		page, err := state.Records(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(page)
	}); err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, "records.query", api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 200})
	response := socketCall(t, server, request)
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	if response.LastSeq != head.LastSeq {
		t.Fatal("socket response lost committed head")
	}
	var page api.RecordPage
	if err := wire.Decode(response.Result, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || !reflect.DeepEqual(page.Records[0], wanted) {
		t.Fatal("scoped socket record leaked or changed")
	}
	if page.Records[0].ID == sibling.ID {
		t.Fatal("scoped socket returned sibling record")
	}
}

func TestSocketUploadAndReplay(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".lb-v2-service-upload-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	caller, _ := socketRecord(t, &state, directory)
	server := fixtureServer(t)
	server.deps.Store = state
	server.deps.Authenticator = &authFixture{scope: caller, store: state}
	server.deps.Binding.LaunchID, server.deps.Binding.Target = caller.LaunchID, &api.LifeRef{LifeID: caller.Actor.LifeID, Run: 1}
	core, err := New(server.deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Register(server); err != nil {
		t.Fatal(err)
	}
	content := []byte("Observed record " + string(fixtureID(t)))
	sum := sha256.Sum256(content)
	digest := api.Digest(hex.EncodeToString(sum[:]))
	begin := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "record", Bytes: int64(len(content)), SHA256: digest})
	response := socketCall(t, server, begin)
	if response.Error != nil {
		t.Fatal("socket upload begin failed", response.Error)
	}
	var upload api.BlobUpload
	if err := wire.Decode(response.Result, &upload); err != nil {
		t.Fatal(err)
	}
	retry := begin
	retry.RequestID = fixtureID(t)
	second := socketCall(t, server, retry)
	if second.Error != nil || !wire.SameJSON(second.Result, response.Result) {
		t.Fatal("socket upload replay changed exact result", second.Error)
	}
	chunk := requestFor(t, "blob.chunk", api.BlobChunk{ObjectID: upload.ObjectID, Data: content, SHA256: digest})
	if response := socketCall(t, server, chunk); response.Error != nil {
		t.Fatal("socket chunk failed", response.Error)
	}
	commit := requestFor(t, "blob.commit", api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: digest})
	response = socketCall(t, server, commit)
	if response.Error != nil {
		t.Fatal("socket object commit failed", response.Error)
	}
	var ref api.BlobRef
	if err := wire.Decode(response.Result, &ref); err != nil {
		t.Fatal(err)
	}
	read := requestFor(t, "blob.read", api.BlobReadRequest{ObjectID: ref.ID, Limit: len(content)})
	head, err := state.HealthSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	response = socketCall(t, server, read)
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	var got api.BlobChunk
	if err := wire.Decode(response.Result, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != string(content) || response.LastSeq != head.LastSeq {
		t.Fatal("socket object bytes or snapshot head changed")
	}
	metadata, err := state.ObjectMetadata(context.Background(), caller, ref.ID)
	if err != nil || metadata.Ref != ref {
		t.Fatal("committed socket object metadata changed", err)
	}
	changed := begin
	changed.Params, err = json.Marshal(api.BlobBeginRequest{Class: "record", Bytes: int64(len(content)) + 1, SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	changed.RequestSHA256, err = wire.RequestDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	response = socketCall(t, server, changed)
	if response.Error == nil || response.Error.Code != api.CodeIdempotencyConflict {
		t.Fatal("socket changed key reached upload preflight", response.Error)
	}
	verification, err := state.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("socket changes failed structural verification", err)
	}
}
