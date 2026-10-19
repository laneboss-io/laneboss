//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	"laneboss.io/laneboss/internal/v2/store/testfx"
)

// This adapter exercises the real SQLite reader and its component lane scope.
// Native human authentication and observer authority are separate gates.
type storeReader struct {
	state *store.Service
	scope api.Scope
	calls int
}

func (c *storeReader) Close() error { return nil }

func (c *storeReader) Call(ctx context.Context, request api.Request) (api.Response, error) {
	c.calls++
	var selected api.EventTailRequest
	if request.Method != "event.tail" {
		return api.Response{}, errors.New("component reader only accepts the selected event operation")
	}
	if err := api.DecodeObject(request.Params, &selected); err != nil {
		return api.Response{}, err
	}
	scope := c.scope
	scope.Config = request.Config
	page, err := c.state.Events(ctx, scope, selected)
	response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) {
			return api.Response{}, err
		}
		response.Error = typed
		return response, nil
	}
	for _, event := range page.Events {
		if event.Seq > response.LastSeq {
			response.LastSeq = event.Seq
		}
	}
	response.Result, err = json.Marshal(page)
	return response, err
}

func TestStoreReaderSelection(t *testing.T) {
	f := testfx.Ready(t, true)
	f.Opened(t)
	connection := &storeReader{state: f.State, scope: f.LaneScope(t)}
	selected := api.EventTailRequest{LifeID: f.Lane.LifeID, Run: f.Lane.Run}
	request := func(query api.EventTailRequest) api.Request {
		return api.Request{Config: f.Deps.Config, Method: "event.tail", Params: testfx.JSON(t, query)}
	}
	var first bytes.Buffer
	if err := exchange(context.Background(), connection, request(selected), &first); err != nil {
		t.Fatal("real-store selected read failed", err)
	}
	var response api.Response
	if err := json.Unmarshal(first.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var page api.EventPage
	if err := api.DecodeObject(response.Result, &page); err != nil || len(page.Events) == 0 || response.LastSeq == 0 {
		t.Fatal("reader omitted the real committed run events", err)
	}
	for _, event := range page.Events {
		if event.Config != f.Deps.Config || event.LifeID != selected.LifeID || event.Run != selected.Run {
			t.Fatal("real-store selected read crossed its binding")
		}
	}
	var replay bytes.Buffer
	if err := exchange(context.Background(), connection, request(selected), &replay); err != nil {
		t.Fatal("read replay failed", err)
	}
	var repeated api.Response
	if err := json.Unmarshal(replay.Bytes(), &repeated); err != nil || !bytes.Equal(repeated.Result, response.Result) || repeated.LastSeq != response.LastSeq {
		t.Fatal("read replay changed real-store bytes or journal head", err)
	}
	foreign := selected
	foreign.LifeID = testfx.ID(t)
	if err := exchange(context.Background(), connection, request(foreign), &bytes.Buffer{}); err == nil {
		t.Fatal("real-store reader accepted a foreign life")
	}
	for _, fault := range []string{"missing_life", "missing_run", "follow"} {
		t.Run(fault, func(t *testing.T) {
			query := selected
			switch fault {
			case "missing_life":
				query.LifeID = ""
			case "missing_run":
				query.Run = 0
			case "follow":
				query.Follow = true
			}
			before := connection.calls
			err := exchange(context.Background(), connection, request(query), &bytes.Buffer{})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || connection.calls != before {
				t.Fatal("invalid event selection reached the real store", err)
			}
		})
	}
}
