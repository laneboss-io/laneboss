package grants

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// This constructs an in-memory worker receipt for resolver validation. It is
// never evidence of a real filesystem copy or of OS confinement.
func receiptFixture(t *testing.T) (*fixture, api.GrantSet, api.Materialization) {
	t.Helper()
	f := newFixture(t)
	second := f.request.Requested.Data[0]
	second.RelativePath, second.Destination = "private", "/data/fixture"
	f.request.Requested.Data = append(f.request.Requested.Data, second)
	child := f.child()
	objects := []api.MaterializedObject{}
	for _, grant := range child.Data {
		var source api.ObjectManifest
		if err := json.Unmarshal(f.store.blobs[grant.SourceObjectID], &source); err != nil {
			t.Fatal(err)
		}
		selected, err := manifest.Select(source, grant.RelativePath)
		if err != nil {
			t.Fatal(err)
		}
		bytes, err := json.Marshal(selected)
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, api.MaterializedObject{GrantID: grant.ID,
			SourceIdentity: "source:" + grant.RelativePath, DestinationIdentity: "copy:" + grant.Destination,
			SnapshotSHA256: manifest.Hash(bytes), WorkspaceID: "workspace"})
	}
	raw, err := json.Marshal(objects)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs["materialization"] = raw
	receipt := api.Materialization{GrantSetID: child.ID, Objects: objects,
		Manifest: api.BlobRef{ID: "materialization", SHA256: manifest.Hash(raw), Bytes: int64(len(raw)), Class: "manifest"}}
	f.worker.materialization, f.worker.materializeErr = receipt, nil
	return f, child, receipt
}

func TestMaterializeReceipts(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*api.Materialization)
	}{
		{"foreign-set", func(r *api.Materialization) { r.GrantSetID = "another" }},
		{"missing-object", func(r *api.Materialization) { r.Objects = r.Objects[:1] }},
		{"foreign-grant", func(r *api.Materialization) { r.Objects[0].GrantID = "another" }},
		{"alias", func(r *api.Materialization) { r.Objects[1].DestinationIdentity = r.Objects[0].DestinationIdentity }},
		{"source-id", func(r *api.Materialization) { r.Objects[0].SourceIdentity = "" }},
		{"snapshot", func(r *api.Materialization) { r.Objects[0].SnapshotSHA256 = "invalid" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f, child, valid := receiptFixture(t)
			actual, err := f.service.Materialize(context.Background(), child)
			if err != nil || !reflect.DeepEqual(actual, valid) {
				t.Fatal("valid worker receipt was rejected", err)
			}
			invalid := clone(t, valid)
			item.change(&invalid)
			f.worker.materialization = invalid
			_, err = f.service.Materialize(context.Background(), child)
			expectCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestMaterializeFinalCheck(t *testing.T) {
	f, child, _ := receiptFixture(t)
	f.worker.onMaterialize = func() { f.updateParent(func(p *api.GrantSet) { p.Revoked = true }) }
	_, err := f.service.Materialize(context.Background(), child)
	if f.worker.materializeCalls != 1 {
		t.Fatal("worker completion control was not reached")
	}
	expectCode(t, err, api.CodeForbidden)
}

func TestDurableTestReceipt(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*api.Operation)
	}{
		{"life", func(o *api.Operation) { o.LifeID = "another" }},
		{"run", func(o *api.Operation) { o.Run++ }},
		{"sequence", func(o *api.Operation) { o.FirstSeq++ }},
		{"status", func(o *api.Operation) { o.Status = "invented" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			request := f.testRequest(child)
			op := api.Operation{ID: "test-op", Status: "succeeded", LifeID: child.LifeID, Run: 1, FirstSeq: 10, LastSeq: 12}
			f.worker.operation, f.worker.testErr, f.store.operation = op, nil, op
			actual, err := f.service.GrantsTestChild(context.Background(), f.scope, request)
			if err != nil || !reflect.DeepEqual(actual, op) {
				t.Fatal("durable test receipt control failed", err)
			}
			item.change(&f.store.operation)
			_, err = f.service.GrantsTestChild(context.Background(), f.scope, request)
			expectCode(t, err, api.CodeIntegrity)
		})
	}
}
