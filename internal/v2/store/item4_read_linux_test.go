//go:build linux

package store

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestItem4KeywordSearch(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	input := testTransaction(t)
	content := []byte("A violet observatory keeps the measured result.")
	ref := api.BlobRef{ID: testID(t), Class: "record", SHA256: testDigest(content), Bytes: int64(len(content))}
	var record api.Record
	if err := json.Unmarshal(input.Events[0].Payload, &record); err != nil {
		t.Fatal(err)
	}
	record.Content = ref
	input.Events[0].Payload, _ = json.Marshal(record)
	input.Reply.Result = input.Events[0].Payload
	input.Scope.Request = testRequest(t, "records.append", api.RecordAppendRequest{Collection: "observations", Content: ref, RelatedIDs: []api.ID{}})
	objects := []api.ObjectWrite{{ObjectKey: ref.ID, Class: ref.Class, SHA256: ref.SHA256, Bytes: content, Origin: "service",
		ACL: api.ObjectACL{Config: input.Scope.Config, Owner: input.Scope.Actor, Audience: "owner", Generation: 1}}}
	internal := input.Scope
	internal.Request = api.Request{}
	intent := api.InternalIntent{ID: testID(t), Kind: api.InternalObjectRetain, Config: internal.Config, Actor: internal.Actor, RequestedBy: internal.Actor}
	if _, err := s.Transact(ctx, api.Transaction{Scope: internal, Internal: &intent, Writes: api.StateWrites{Objects: objects}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transact(ctx, input); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"violet", "VIOLET", "violet observatory", "missing"} {
		page, err := s.Records(ctx, input.Scope, api.RecordQuery{Collection: "observations", SearchMode: "keyword", Query: query, Limit: 1})
		if err != nil {
			t.Fatal("scoped content search refused", err)
		}
		want := 1
		if query == "missing" {
			want = 0
		}
		if len(page.Records) != want || want == 1 && page.Records[0].ID != record.ID {
			t.Fatal("keyword search ignored the committed bytes")
		}
	}
}
