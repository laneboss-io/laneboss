package event

import (
	"bytes"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/testdata"
)

func TestTailExternalUntil(t *testing.T) {
	f := testdata.OpenStore(t)
	appendEvent := func(id, kind string, payload map[string]any, external bool) {
		t.Helper()
		e := testdata.Envelope(payload)
		e["id"], e["kind"] = id, kind
		var err error
		if external {
			_, err = f.Store.AppendExternal(e, "supervisor:top")
		} else {
			_, err = f.Store.Append(e)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	appendEvent("external-state", "lane.state", map[string]any{"state": "accepted"}, true)
	appendEvent("after-external", "demo.note", map[string]any{}, false)
	appendEvent("real-state", "lane.state", map[string]any{"state": "abandoned"}, false)
	appendEvent("after-real", "demo.note", map[string]any{}, false)
	var out bytes.Buffer
	if err := tail(f.Config, eventstore.Options{Since: 3, Until: "lane.state"}, caller.Principal{ID: "human"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatal("tail stopped at the appended state or passed the launcher state")
	}
	for i, line := range lines {
		var e map[string]any
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e["externally_appended"] != (i == 0) {
			t.Fatal("tail omitted or misreported stored event origin")
		}
	}
}
