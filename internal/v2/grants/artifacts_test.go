package grants

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestReferenceBounds(t *testing.T) {
	f := newFixture(t)
	f.store.blobs["bounded"] = []byte("prefix-and-more")
	ref := api.BlobRef{ID: "bounded", SHA256: manifest.Hash([]byte("prefix")), Bytes: 6, Class: "artifact"}
	// Fault-injected committed metadata claims a prefix. The reader must still
	// detect the actual extra byte through the store's exact-end protocol.
	f.store.retain(ref)
	_, err := f.service.readRef(context.Background(), f.scope, ref)
	expectCode(t, err, api.CodeIntegrity)
	ref.Bytes = 100
	f.store.retain(ref)
	_, err = f.service.readRef(context.Background(), f.scope, ref)
	expectCode(t, err, api.CodeIntegrity)
	ref = api.BlobRef{ID: "empty", SHA256: manifest.Hash(nil), Bytes: 0, Class: "artifact"}
	_, err = f.service.readRef(context.Background(), f.scope, ref)
	expectCode(t, err, api.CodeNotFound)
	f.store.blobs["empty"] = []byte{}
	f.store.retain(ref)
	data, err := f.service.readRef(context.Background(), f.scope, ref)
	if err != nil || len(data) != 0 {
		t.Fatal("real committed empty object was rejected", err)
	}
}

func TestArtifactOrigins(t *testing.T) {
	for _, item := range []struct {
		name   string
		mutate func(*api.Event)
	}{
		{"sibling", func(e *api.Event) { e.Actor.LifeID = "sibling" }},
		{"observation", func(e *api.Event) { e.Origin = "observation" }},
		{"imported", func(e *api.Event) { e.Origin = "legacy_import" }},
		{"old-run", func(e *api.Event) { e.Run++ }},
		{"other-config", func(e *api.Event) { e.Config = "another" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			request := f.testRequest(child)
			item.mutate(&f.store.events[0])
			_, err := f.service.BoundChildTest(context.Background(), f.scope, request)
			expectCode(t, err, api.CodeForbidden)
			if f.worker.testCalls != 0 {
				t.Fatal("unrelated artifact reached the child worker")
			}
		})
	}
}

func TestCandidateCannotUnionInputs(t *testing.T) {
	f := newFixture(t)
	child := f.child()
	request := f.testRequest(child)
	var object api.ObjectManifest
	if err := json.Unmarshal(f.store.blobs[request.Candidate.ID], &object); err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "parent-artifact", SHA256: manifest.Hash([]byte("ungranted")), Bytes: 9, Class: "artifact"}
	f.store.blobs[ref.ID] = []byte("ungranted")
	f.store.retain(ref)
	object.Entries[0].Content = &ref
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs[request.Candidate.ID] = raw
	request.Candidate.SHA256, request.Candidate.Bytes = manifest.Hash(raw), int64(len(raw))
	f.store.retain(request.Candidate)
	f.store.events[0].Payload, err = json.Marshal(request.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	var plan api.WorkerPlan
	if err := json.Unmarshal(f.store.blobs[request.TestPlan.ID], &plan); err != nil {
		t.Fatal(err)
	}
	plan.Input = request.Candidate
	raw, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs[request.TestPlan.ID] = raw
	request.TestPlan.SHA256, request.TestPlan.Bytes = manifest.Hash(raw), int64(len(raw))
	f.store.retain(request.TestPlan)
	_, err = f.service.GrantsTestChild(context.Background(), f.scope, request)
	expectCode(t, err, api.CodeForbidden)
	if f.worker.testCalls != 0 {
		t.Fatal("parent-only bytes entered the child worker")
	}
}
