//go:build linux

package store_test

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestCanonicalDecisionsAndFilteredPages(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	content := f.Retain(t, "record", []byte("canonical record "+string(fx.ID(t))), f.Execution.Actor, "")
	canonical := api.Record{ID: fx.ID(t), Collection: "decisions", Content: content, Actor: f.Execution.Actor, Origin: "service", Generation: 1, RecordedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	events := []api.Event{}
	appendRecord := func(record api.Record) {
		events = append(events, api.Event{Schema: api.SchemaVersion, ID: fx.ID(t), Config: f.Deps.Config, Kind: "record.appended", Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor, LifeID: record.LifeID, Run: record.Run, Origin: record.Origin, StarterChain: []api.ID{}, Payload: fx.JSON(t, record)})
	}
	for i := 0; i < 205; i++ {
		sibling := canonical
		sibling.ID, sibling.LifeID, sibling.Run = fx.ID(t), fx.ID(t), 1
		sibling.Collection, sibling.Origin = "reports", "observation"
		appendRecord(sibling)
	}
	appendRecord(canonical)
	own := canonical
	own.ID, own.LifeID, own.Run = fx.ID(t), f.Reservation.Target.LifeID, 1
	own.Collection, own.Origin = "observations", "observation"
	appendRecord(own)
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalOrgBootstrap, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Events: events}); err != nil {
		t.Fatal("record query inventory setup failed", err)
	}
	scope := api.Scope{Config: f.Deps.Config, Actor: f.Binding.Record.Actor, LaunchID: f.Binding.Record.ID, EndpointGeneration: 1, PolicyGeneration: 1}
	page, err := f.State.Records(ctx, scope, api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 1})
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != own.ID {
		t.Fatal("unmatched rows hid a later visible record", err)
	}
	page, err = f.State.Records(ctx, scope, api.RecordQuery{Collection: "decisions", RecordID: canonical.ID, SearchMode: "keyword", Limit: 1})
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != canonical.ID {
		t.Fatal("canonical decision was hidden from lane", err)
	}
	page, err = f.State.Records(ctx, scope, api.RecordQuery{Collection: "decisions", SearchMode: "keyword", Limit: 200})
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != canonical.ID {
		t.Fatal("canonical decision search page was hidden from lane", err)
	}
}
