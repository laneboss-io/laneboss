package event

import (
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
)

func TestEventAuthorizationAndVisibility(t *testing.T) {
	from := caller.Principal{ID: "lane:a1", Level: 3}
	for _, kind := range []string{"lane.mailed", "report.sent", "report.delivered", "owner.message.received"} {
		if err := authorizeEvent(map[string]any{"kind": kind, "lane": "a1", "actor": "e2e"}, from); err == nil {
			t.Fatal("reserved message kind reached event append")
		}
	}
	for _, actor := range []string{"human", "human:owner", "Human-operator"} {
		if err := authorizeEvent(map[string]any{"kind": "test.note", "lane": "a1", "actor": actor}, from); err == nil {
			t.Fatal("a CLI-supplied human actor reached event append")
		}
	}
	if err := authorizeEvent(map[string]any{"kind": "test.note", "lane": "b1", "actor": "e2e"}, from); err == nil {
		t.Fatal("a lane appended for another lane")
	}
	for _, sibling := range []string{"a10", "a1-other", "a1.child"} {
		if err := authorizeEvent(map[string]any{"kind": "test.note", "lane": sibling, "actor": "e2e"}, from); err == nil {
			t.Fatal("a sibling lane prefix reached event append")
		}
	}
	allowed := map[string]any{"kind": "test.note", "lane": "a1", "actor": "supervisor:mini-b"}
	if err := authorizeEvent(allowed, from); err != nil || allowed["actor"] != "lane:a1" {
		t.Fatal("the self event did not force the resolved lane actor")
	}
	for _, row := range []struct {
		e       eventstore.Object
		visible bool
	}{
		{eventstore.Object{"lane": "a1"}, true},
		{eventstore.Object{"lane": "b1"}, false},
		{eventstore.Object{"lane": "a10"}, false},
		{eventstore.Object{"lane": "a1-other"}, false},
		{eventstore.Object{"payload": map[string]any{"to": "lane:a1"}}, true},
		{eventstore.Object{"payload": map[string]any{"to": "lane:b1"}}, false},
		{eventstore.Object{"payload": map[string]any{"to": "lane:a10"}}, false},
		{eventstore.Object{"payload": map[string]any{"to": "lane:a1-other"}}, false},
		{eventstore.Object{"payload": map[string]any{"to": "human"}}, false},
	} {
		if got := visibleEvent(row.e, from); got != row.visible {
			t.Fatal("lane event tail leaked another recipient or hid its own message")
		}
	}
}
