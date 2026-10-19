package eventstore_test

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/testdata"
)

func TestExternalLifecycleStoredOrigin(t *testing.T) {
	fixture := testdata.OpenStore(t)
	value := testdata.Envelope(map[string]any{"state": "abandoned"})
	value["kind"], value["id"], value["actor"] = "lane.state", "external-state", "laneboss"
	before := eventstore.Canonical(value["payload"])
	first, err := fixture.Store.AppendExternal(value, "supervisor:top")
	if err != nil {
		t.Fatal(err)
	}
	again, err := fixture.Store.AppendExternal(value, "supervisor:top")
	if err != nil || again["duplicate"] != true || again["sha256"] != first["sha256"] || again["seq"] != first["seq"] {
		t.Fatalf("external append lost idempotence: %v", err)
	}
	events, err := fixture.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if !eventstore.ExternallyAppended(last) || last["actor"] != "event.append:supervisor:top" || last["sha256"] != first["sha256"] {
		t.Fatal("a claimed launcher actor was stored without hashed external provenance")
	}
	if eventstore.Canonical(last["payload"]) != before || value["actor"] != "laneboss" {
		t.Fatal("marking origin changed the input or payload")
	}
	for _, event := range events[:len(events)-1] {
		if eventstore.ExternallyAppended(event) {
			t.Fatal("a real launcher record acquired external origin")
		}
	}
	if _, err = fixture.Store.Verify(); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.Store.Rebuild(); err != nil {
		t.Fatal(err)
	}
}

func TestExternalStartValidationOrder(t *testing.T) {
	fixture := testdata.OpenStore(t)
	events, err := fixture.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{}
	for key, value := range events[0]["payload"].(map[string]any) {
		payload[key] = value
	}
	payload["run"], payload["how"], payload["launch"] = 2, "resume", strings.Repeat("a", 32)
	value := testdata.Envelope(payload)
	value["kind"], value["id"], value["actor"] = "lane.started", "external-start", "laneboss"
	wrong := map[string]any{}
	for key, item := range payload {
		wrong[key] = item
	}
	wrong["session"] = map[string]any{"socket": "/tmp/another-scope", "name": testdata.Lane}
	value["payload"] = wrong
	if _, err = fixture.Store.AppendExternal(value, "human"); err == nil || !strings.Contains(err.Error(), "payload.session") {
		t.Fatalf("the replay/session diagnostic was hidden: %v", err)
	}
	value["payload"] = payload
	if _, err = fixture.Store.AppendExternal(value, "human"); err != nil {
		t.Fatal(err)
	}
	events, err = fixture.Store.Events(0)
	if err != nil || !eventstore.ExternallyAppended(events[len(events)-1]) {
		t.Fatalf("a valid start was not retained as an external observation: %v", err)
	}
	adoption := map[string]any{}
	for key, item := range payload {
		if key != "run" && key != "how" && key != "launch" {
			adoption[key] = item
		}
	}
	adoption["idle_seconds"] = nil
	value["kind"], value["id"], value["payload"] = "lane.adopted", "missing-session", adoption
	if _, err = fixture.Store.AppendExternal(value, "human"); err == nil || !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("the missing session_id diagnostic was hidden: %v", err)
	}
}
