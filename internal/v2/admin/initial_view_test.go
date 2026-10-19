package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This capability pins the actual file-backed component store. It checks view
// propagation/lifetime, while the store package measures SQLite byte loads.
type initialViewStore struct {
	*initialTestStore
	begun, closed, unbound, chunks int
}

type initialView struct {
	store    *initialViewStore
	file     *os.File
	disk     initialDisk
	snapshot api.ReadSnapshot
	closed   bool
}

func (v *initialView) Snapshot() api.ReadSnapshot { return v.snapshot }
func (v *initialView) Close() error {
	if v.closed {
		return nil
	}
	v.closed = true
	v.store.closed++
	return v.file.Close()
}

func (s *initialViewStore) BeginObjectRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	view := &initialView{store: s, file: file}
	if err := json.NewDecoder(file).Decode(&view.disk); err != nil {
		file.Close()
		return nil, err
	}
	view.snapshot = api.ReadSnapshot{ID: view.disk.Operation.ID, Config: scope.Config,
		LastSeq: view.disk.Operation.LastSeq, PolicyGeneration: view.disk.Policy.Generation}
	s.begun++
	return view, nil
}

func (s *initialViewStore) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	if view, ok := scope.ReadView.(*initialView); ok && view.store == s && !view.closed {
		if metadata, exists := view.disk.Metadata[id]; exists {
			return metadata, nil
		}
		return api.ObjectMetadata{}, failure(api.CodeNotFound, "component view object absent")
	}
	return s.initialTestStore.ObjectMetadata(ctx, scope, id)
}

func (s *initialViewStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	view, ok := scope.ReadView.(*initialView)
	if !ok || view.store != s || view.closed {
		s.unbound++
		return s.initialTestStore.Blob(ctx, scope, request)
	}
	raw, exists := view.disk.Objects[request.ObjectID]
	if !exists || request.Offset < 0 || request.Offset >= int64(len(raw)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, failure(api.CodeNotFound, "component view range absent")
	}
	part := bytes.Clone(raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))])
	s.chunks++
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: digestBytes(part)}, nil
}

func TestInitialReadView(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "state.json")
	raw := bytes.Repeat([]byte("retained component bytes"), api.MaxChunkBytes/8)
	ref := api.BlobRef{ID: "large-component-object", Class: "artifact", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	disk := initialDisk{Objects: map[api.ID][]byte{ref.ID: raw}, Metadata: map[api.ID]api.ObjectMetadata{ref.ID: {Ref: ref}}}
	if err := os.WriteFile(path, initialEncode(t, disk), 0600); err != nil {
		t.Fatal(err)
	}
	s := &initialViewStore{initialTestStore: &initialTestStore{path: path}}
	actual, err := initialRead(context.Background(), s, api.Scope{Config: "admin-case"}, ref)
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatal("initial view byte control failed", err)
	}
	if s.begun != 1 || s.closed != 1 || s.unbound != 0 || s.chunks < 2 {
		t.Fatal("initial chunks did not share a released view", s.begun, s.closed, s.unbound, s.chunks)
	}
	changed := ref
	changed.SHA256 = digestBytes([]byte("different bytes"))
	if _, err := initialRead(context.Background(), s, api.Scope{Config: "admin-case"}, changed); err == nil || s.begun != 2 || s.closed != 2 {
		t.Fatal("initial view hid tampering or leaked on refusal", err)
	}
}

func TestInitialSnapshotView(t *testing.T) {
	b := initialFixture(t)
	ctx, channel := initialTestContext(t)
	base := &initialTestStore{path: filepath.Join(privateTestDir(t), "state.json")}
	clock := enrollmentClock{now: time.Now().UTC()}
	want, err := commitInitial(ctx, b, base, clock, channel)
	if err != nil {
		t.Fatal(err)
	}
	s := &initialViewStore{initialTestStore: base}
	actual, err := commitInitial(ctx, b, s, clock, channel)
	if err != nil || actual != want {
		t.Fatal("initial snapshot receipt control failed", err)
	}
	if s.begun != 1 || s.closed != 1 || s.unbound != 0 || s.chunks < len(b.objects) {
		t.Fatal("initial read-back did not share one view", s.begun, s.closed, s.unbound, s.chunks)
	}
}
