package event

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/testdata"
)

func TestLifecycleAppendAuthorized(t *testing.T) {
	fixture := testdata.OpenStore(t)
	for _, from := range []caller.Principal{{ID: "human"}, {ID: "supervisor:mini", Level: 4}, {ID: "supervisor:top", Level: 5}, {ID: "supervisor:root", Level: 6}, {ID: "instance:L4", Level: 4}} {
		for _, kind := range lifeKinds() {
			err := authorizeEvent(map[string]any{"kind": kind, "lane": "worker", "actor": "laneboss"}, from)
			if err != nil {
				t.Fatalf("%s appended by %s did not reach payload validation: %v", kind, from.ID, err)
			}
			if err := authorizeLifecycle(fixture.Config, eventstore.Object{"kind": kind, "lane": "unseen"}, from); err != nil {
				t.Fatalf("a configured supervisor or human lost lifecycle append: %v", err)
			}
		}
		if err := authorizeEvent(map[string]any{"kind": "test.note", "lane": "worker", "actor": "note"}, from); err != nil {
			t.Fatal("the lifecycle gate refused an ordinary event")
		}
	}
}

func lifeKinds() []string {
	return []string{"lane.planned", "lane.started", "lane.adopted", "lane.resumed", "lane.ended", "lane.timeout", "lane.stuck", "lane.lost", "lane.gone", "lane.delivered", "lane.returned", "lane.cleaned", "lane.state", "lane.merged", "lane.deployed", "lane.landed"}
}

func TestLifecycleLaneRefused(t *testing.T) {
	for _, from := range []caller.Principal{{ID: "lane:worker", Level: 3}, {ID: "lane:worker", Level: 6}, {ID: "instance:L3", Level: 3}, {ID: "supervisor:low", Level: 3}, {ID: "supervisor:high", Level: 7}, {ID: ""}} {
		for _, target := range []string{"worker", "other"} {
			for _, kind := range lifeKinds() {
				err := authorizeLifecycle(nil, eventstore.Object{"kind": kind, "lane": target}, from)
				if err == nil || !strings.Contains(err.Error(), "Instead: report up with laneboss report") {
					t.Fatalf("%s gained lifecycle append for %s (%s): %v", from.ID, target, kind, err)
				}
			}
		}
	}
}

func TestAdvanceGate(t *testing.T) {
	f := testdata.OpenStore(t)
	before, err := f.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	human := caller.Principal{ID: "human"}
	for _, kind := range []string{"lane.started", "lane.resumed", "lane.adopted"} {
		if err := authorizeLifecycle(f.Config, eventstore.Object{"kind": kind, "lane": testdata.Lane}, human); err == nil || !strings.Contains(err.Error(), "Instead: use lane start, resume or turn") {
			t.Fatalf("a launched lane accepted %s: %v", kind, err)
		}
		if err := authorizeLifecycle(f.Config, eventstore.Object{"kind": kind, "lane": "unseen"}, human); err != nil {
			t.Fatalf("an external-only name lost %s: %v", kind, err)
		}
	}
	appendCLI := func(e map[string]any) error {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		return appendEvent(f.Config, eventstore.Options{File: "-"}, human, bytes.NewReader(data), &out)
	}
	original := before[0]["payload"].(map[string]any)
	p := map[string]any{}
	for key, value := range original {
		p[key] = value
	}
	p["run"], p["how"] = 2, "resume"
	e := testdata.Envelope(p)
	e["id"], e["kind"] = "blocked-start", "lane.started"
	if err := appendCLI(e); err == nil || !strings.Contains(err.Error(), "Instead: use lane start, resume or turn") {
		t.Fatalf("the actual append path accepted a launched run: %v", err)
	}
	after, err := f.Store.Events(0)
	if err != nil || eventstore.Canonical(after) != eventstore.Canonical(before) {
		t.Fatal("a refused advance changed the store")
	}
	p["run"], p["how"] = 1, "start"
	p["session"] = map[string]any{"socket": f.Config.Socket(f.Config.StatePath), "name": "unseen"}
	p["log"] = filepath.Join(f.Config.StatePath, "lanes", "unseen", "output.log")
	brief := original["brief"].(map[string]any)
	p["brief"] = map[string]any{"sha256": brief["sha256"], "path": filepath.Join(f.Config.StatePath, "lanes", "unseen", "rendered", brief["sha256"].(string)+".md")}
	e = testdata.Envelope(p)
	e["id"], e["kind"], e["lane"] = "external-unseen", "lane.started", "unseen"
	if err := appendCLI(e); err != nil {
		t.Fatalf("a never-launched name lost its observation: %v", err)
	}
}

func TestClosingGate(t *testing.T) {
	f := testdata.OpenStore(t)
	events, err := f.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	original := events[0]["payload"].(map[string]any)
	p := map[string]any{}
	for key, value := range original {
		p[key] = value
	}
	p["run"], p["how"] = 2, "resume"
	e := testdata.Envelope(p)
	e["id"], e["kind"] = "real-open", "lane.started"
	if _, err := f.Store.Append(e); err != nil {
		t.Fatal(err)
	}
	appendCLI := func(e map[string]any) error {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		return appendEvent(f.Config, eventstore.Options{File: "-"}, caller.Principal{ID: "human"}, bytes.NewReader(data), &out)
	}
	for _, kind := range []string{"lane.ended", "lane.lost", "lane.gone"} {
		end := map[string]any{"run": 2, "survivors": 0}
		if kind == "lane.ended" {
			end = map[string]any{"run": 2, "survivors": 0, "reason": "exit", "exit_code": 0,
				"signal": nil, "duration_seconds": 0, "pattern": nil, "classification": nil}
		} else if kind == "lane.gone" {
			end = map[string]any{"run": 2, "launch": original["launch"]}
		}
		e := testdata.Envelope(end)
		e["id"], e["kind"] = "blocked-"+kind, kind
		before, err := f.Store.Events(0)
		if err != nil {
			t.Fatal(err)
		}
		if err := appendCLI(e); err == nil || !strings.Contains(err.Error(), "event append may not end a launcher-recorded lane's run") || !strings.Contains(err.Error(), "Instead: use lane stop, or lane check") {
			t.Fatalf("run-closing append was accepted for %s: %v", kind, err)
		}
		after, err := f.Store.Events(0)
		if err != nil || eventstore.Canonical(after) != eventstore.Canonical(before) {
			t.Fatal("a refused close changed the actual store")
		}
		lane := "unseen-" + strings.TrimPrefix(kind, "lane.")
		start := map[string]any{}
		for key, value := range original {
			start[key] = value
		}
		start["session"] = map[string]any{"socket": f.Config.Socket(f.Config.StatePath), "name": lane}
		start["log"] = filepath.Join(f.Config.StatePath, "lanes", lane, "output.log")
		brief := original["brief"].(map[string]any)
		start["brief"] = map[string]any{"sha256": brief["sha256"], "path": filepath.Join(f.Config.StatePath, "lanes", lane, "rendered", brief["sha256"].(string)+".md")}
		observed := testdata.Envelope(start)
		observed["id"], observed["kind"], observed["lane"] = "start-"+lane, "lane.started", lane
		if err := appendCLI(observed); err != nil {
			t.Fatalf("the never-launched start control failed: %v", err)
		}
		end["run"] = 1
		e["id"], e["lane"] = "close-"+lane, lane
		if err := appendCLI(e); err != nil {
			t.Fatalf("a never-launched name lost %s: %v", kind, err)
		}
	}
}

func TestLifeValidationFirst(t *testing.T) {
	fixture := testdata.OpenStore(t)
	before, err := fixture.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	original := before[0]["payload"].(map[string]any)
	for _, diagnostic := range []string{"session_id", "payload.session", "lifecycle append requires"} {
		payload := map[string]any{}
		for key, value := range original {
			payload[key] = value
		}
		e := testdata.Envelope(payload)
		e["id"], e["kind"] = "invalid-life", "lane.started"
		if diagnostic == "session_id" {
			e["kind"] = "lane.adopted"
			for _, key := range []string{"run", "how", "launch", "mail", "session_id"} {
				delete(payload, key)
			}
			payload["idle_seconds"] = nil
		} else if diagnostic == "payload.session" {
			payload["session"] = map[string]any{"socket": "/tmp/other", "name": "other"}
		} else {
			e["kind"], e["payload"] = "lane.state", map[string]any{"state": "abandoned"}
		}
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = appendEvent(fixture.Config, eventstore.Options{File: "-"}, caller.Principal{ID: "lane:fixture", Level: 3}, bytes.NewReader(data), &out)
		if err == nil || !strings.Contains(err.Error(), diagnostic) || out.Len() != 0 {
			t.Fatalf("validation/access order changed for %s: %v", diagnostic, err)
		}
	}
	after, err := fixture.Store.Events(0)
	if err != nil || eventstore.Canonical(after) != eventstore.Canonical(before) {
		t.Fatalf("refused lifecycle inputs changed the store: %v", err)
	}
}

func TestMessageAppendStillRefused(t *testing.T) {
	for _, kind := range []string{"lane.mailed", "report.sent", "owner.message.sent"} {
		err := authorizeEvent(map[string]any{"kind": kind, "lane": "worker", "actor": "laneboss"}, caller.Principal{ID: "human"})
		if err == nil || !strings.Contains(err.Error(), "event append may not append lane.mailed, report.* or owner.message.*") {
			t.Fatalf("message append boundary changed for %s: %v", kind, err)
		}
	}
}
