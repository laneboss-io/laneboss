package grants

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Exercise the worker primitive through the fixture reader; service preflight
// no longer reads or assembles file content under service authority.
func (s *Service) checkFile(ctx context.Context, scope api.Scope, entry api.ObjectEntry) error {
	return manifest.VerifyContent(ctx, entry, api.MaxObjectBytes,
		func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
			return s.deps.Store.Blob(ctx, scope, request)
		})
}

func TestCommittedMetadata(t *testing.T) {
	for _, item := range []struct {
		name   string
		mutate func(*api.ObjectMetadata)
	}{
		{"identity", func(m *api.ObjectMetadata) { m.Ref.ID = "other" }},
		{"digest", func(m *api.ObjectMetadata) { m.Ref.SHA256 = manifest.Hash([]byte("other")) }},
		{"length", func(m *api.ObjectMetadata) { m.Ref.Bytes++ }},
		{"class", func(m *api.ObjectMetadata) { m.Ref.Class = "policy" }},
		{"config", func(m *api.ObjectMetadata) { m.ACL.Config = "other" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			ref := f.store.metadata["input-bytes"].Ref
			bytes, err := f.service.readRef(context.Background(), f.scope, ref)
			if err != nil || string(bytes) != "input" {
				t.Fatal("committed metadata control failed", err)
			}
			metadata := f.store.metadata[ref.ID]
			item.mutate(&metadata)
			f.store.metadata[ref.ID] = metadata
			_, err = f.service.readRef(context.Background(), f.scope, ref)
			expectCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestAssemblyBytes(t *testing.T) {
	// Exercise the streaming digest primitive with small parts. The manifest
	// parser separately requires large files to use this representation.
	for _, item := range []struct {
		name   string
		mutate func(*api.ObjectAssembly)
	}{
		{"order", func(a *api.ObjectAssembly) { a.Parts[0], a.Parts[1] = a.Parts[1], a.Parts[0] }},
		{"length", func(a *api.ObjectAssembly) { a.Bytes++ }},
		{"digest", func(a *api.ObjectAssembly) { a.SHA256 = manifest.Hash([]byte("other")) }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			second := api.BlobRef{ID: "second", Class: "artifact", Bytes: 1, SHA256: manifest.Hash([]byte("!"))}
			f.store.blobs[second.ID] = []byte("!")
			f.store.retain(second)
			assembly := api.ObjectAssembly{SHA256: manifest.Hash([]byte("input!")), Bytes: 6,
				Parts: []api.BlobRef{f.store.metadata["input-bytes"].Ref, second}}
			entry := api.ObjectEntry{Kind: "file", Assembly: &assembly}
			if err := f.service.checkFile(context.Background(), f.scope, entry); err != nil {
				t.Fatal("assembly byte control failed", err)
			}
			item.mutate(&assembly)
			err := f.service.checkFile(context.Background(), f.scope, entry)
			expectCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestArtifactMetadata(t *testing.T) {
	for _, item := range []struct {
		name   string
		mutate func(*api.ObjectACL)
	}{
		{"owner-kind", func(a *api.ObjectACL) { a.Owner.Kind = "service" }},
		{"owner-life", func(a *api.ObjectACL) { a.Owner.LifeID = "sibling" }},
		{"scope-life", func(a *api.ObjectACL) { a.LifeID = "parent" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			request := f.testRequest(child)
			if _, err := f.service.BoundChildTest(context.Background(), f.scope, request); err != nil {
				t.Fatal("child-owned artifact control failed", err)
			}
			metadata := f.store.metadata[request.Candidate.ID]
			item.mutate(&metadata.ACL)
			f.store.metadata[request.Candidate.ID] = metadata
			_, err := f.service.BoundChildTest(context.Background(), f.scope, request)
			expectCode(t, err, api.CodeForbidden)
		})
	}
}

func TestPinnedChildRecheck(t *testing.T) {
	f := newFixture(t)
	child := f.child()
	request := f.testRequest(child)
	initial, err := f.store.BeginRead(context.Background(), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	f.scope.ReadView = initial
	f.store.onBlobObject = request.Candidate.ID
	f.store.onBlob = func() {
		lane := f.store.lanes[child.LifeID]
		lane.Run++
		f.store.lanes[child.LifeID] = lane
	}
	_, err = f.service.BoundChildTest(context.Background(), f.scope, request)
	expectCode(t, err, api.CodeConflict)
	if f.store.onBlob != nil || f.worker.testCalls != 0 {
		t.Fatal("pinned child transition was not verified before dispatch")
	}
	if initial.(*fixtureReadView).closed {
		t.Fatal("authority check closed the handler's borrowed snapshot")
	}
	for _, view := range f.store.views {
		if view != initial && !view.closed {
			t.Fatal("authority check leaked a read snapshot")
		}
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
}
