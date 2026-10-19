//go:build linux

package store_test

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestItem4SearchVisibilityAndPages(t *testing.T) {
	f, _ := judgeExecutionFixture(t)
	ctx := context.Background()
	objects := []api.ObjectWrite{}
	events := []api.Event{}
	var wanted api.ID
	for index, text := range []string{"unrelated prelude", "violet measured output", "violet ultraviolet private content"} {
		body := []byte(text)
		owner, life := f.Human.Actor, f.Lane.LifeID
		if index == 2 {
			owner = api.Actor{Kind: "lane", ID: fx.ID(t), LifeID: fx.ID(t), Level: 3, Role: "executor"}
			life = owner.LifeID
		}
		ref := api.BlobRef{ID: fx.ID(t), Class: "record", SHA256: fx.Digest(body), Bytes: int64(len(body))}
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, SHA256: ref.SHA256, Bytes: body, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, LifeID: life, Audience: "owner", Generation: 1}})
		record := api.Record{ID: fx.ID(t), Collection: "observations", LifeID: f.Lane.LifeID, Run: f.Lane.Run, Content: ref, Actor: f.Execution.Actor, Origin: "observation", Generation: 1, RecordedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
		if index == 1 {
			wanted = record.ID
		}
		event := f.Event(t, "record.appended", record)
		event.RequestedBy = f.Execution.Actor
		event.Origin = record.Origin
		events = append(events, event)
	}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalOrgBootstrap, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: objects}, Events: events}); err != nil {
		t.Fatal(err)
	}
	query := api.RecordQuery{Collection: "observations", SearchMode: "keyword", Query: "violet", Limit: 1}
	page, err := f.State.Records(ctx, f.Human, query)
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != wanted || page.Cursor == "" {
		t.Fatal("matching visible content after a nonmatching row was not paged", err)
	}
	replayed, err := f.State.Records(ctx, f.Human, query)
	if err != nil || len(replayed.Records) != 1 || replayed.Records[0].ID != wanted || replayed.Cursor != page.Cursor {
		t.Fatal("search replay changed a fixed record snapshot", err)
	}
	query.Cursor = page.Cursor
	last, err := f.State.Records(ctx, f.Human, query)
	if err != nil || len(last.Records) != 0 || last.Cursor != "" {
		t.Fatal("record-level visibility exposed foreign content bytes", err)
	}
	query.Query = "ultraviolet"
	if _, err := f.State.Records(ctx, f.Human, query); err == nil {
		t.Fatal("changed search filters reused a stale cursor")
	}
	query.Cursor = ""
	private, err := f.State.Records(ctx, f.Human, query)
	if err != nil || len(private.Records) != 0 {
		t.Fatal("foreign object contents became searchable", err)
	}
}
