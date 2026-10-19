package peers

import (
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/caller"
)

func TestAllowedUsesRecordedAncestry(t *testing.T) {
	a := caller.Principal{ID: "lane:a1", Level: 3, Starter: "supervisor:mini-a"}
	for _, row := range []struct {
		from, to caller.Principal
		allowed  bool
	}{
		{a, caller.Principal{ID: "lane:a2", Level: 3, Starter: a.Starter}, true},
		{a, caller.Principal{ID: "lane:b1", Level: 3, Starter: "supervisor:mini-b"}, false},
		{a, caller.Principal{ID: "lane:mini-a", Level: 4, Starter: a.Starter}, false},
		{a, caller.Principal{ID: a.Starter, Level: 4}, true},
		{caller.Principal{ID: a.Starter, Level: 4}, a, true},
		{caller.Principal{ID: "human"}, caller.Principal{ID: "lane:top", Level: 6}, true},
		{caller.Principal{ID: "human"}, caller.Principal{ID: "lane:old"}, true},
		{caller.Principal{}, a, false},
		{caller.Principal{ID: "human-spoof"}, a, false},
		{caller.Principal{ID: "lane:old"}, caller.Principal{ID: "lane:also-old"}, false},
		{caller.Principal{ID: "lane:null-parent", Level: 3}, caller.Principal{ID: "lane:null-parent-two", Level: 3}, false},
		{caller.Principal{ID: "supervisor:top", Level: 5}, a, false},
	} {
		if got := Allowed(row.from, row.to); got != row.allowed {
			t.Fatalf("permission for %+v -> %+v = %v, want %v", row.from, row.to, got, row.allowed)
		}
	}
	from := caller.Principal{ID: "lane:web-2", Level: 3, Starter: "supervisor:mini-a"}
	to := caller.Principal{ID: "lane:api-1", Level: 3, Starter: "supervisor:mini-b"}
	others := []caller.Principal{{ID: "lane:web-3", Level: 3, Starter: from.Starter}, {ID: "lane:web-1", Level: 3, Starter: from.Starter}, from, to}
	want := "lane web-2 (L3, supervisor supervisor:mini-a) may not message lane api-1 (L3, supervisor supervisor:mini-b): lanes talk only to lanes of the same level under the same supervisor.\nInstead: report up with laneboss report (to supervisor:mini-a), or message web-1, web-3 (L3, supervisor supervisor:mini-a)."
	if got := Refusal(from, to, others); got != want {
		t.Fatalf("refusal text differs:\n%s", got)
	}
}

func TestChannelsFollowSelectedSupervisor(t *testing.T) {
	base := t.TempDir()
	c := caller.Configuration("brief", filepath.Join(base, "config"), filepath.Join(base, "state"), filepath.Join(base, "config", "configs", "brief"), filepath.Join(base, "state", "brief"), map[string]any{"owner_channel": "human-file", "supervisors": map[string]any{"mini-a": map[string]any{"owner_channel": "mini-chat"}}, "owner_channels": map[string]any{"human-file": map[string]any{"kind": "file", "path": "reports.md"}, "mini-chat": map[string]any{"kind": "chat", "service": "discord", "target": "configured"}}})
	human, err := Channels(c, "")
	if err != nil {
		t.Fatal(err)
	}
	mini, err := Channels(c, "supervisor:mini-a")
	if err != nil {
		t.Fatal(err)
	}
	if !human["dashboard"] || !human["file"] || human["discord"] || human["terminal"] {
		t.Fatalf("human fallback channels differ from the installed settings: %v", human)
	}
	if !mini["dashboard"] || mini["file"] || !mini["discord"] || mini["terminal"] {
		t.Fatalf("the supervisor's channel was not selected: %v", mini)
	}
}
