package peers

import (
	"testing"

	"laneboss.io/laneboss/internal/caller"
)

func TestMessageDecision(t *testing.T) {
	legacy := caller.Principal{ID: "lane:old"}
	known := caller.Principal{ID: "lane:known", Level: 5}
	for _, row := range []struct {
		from, to        caller.Principal
		allowed, legacy bool
	}{
		{caller.Principal{ID: "supervisor:mini", Level: 4}, legacy, true, true},
		{caller.Principal{ID: "human"}, legacy, true, true},
		{caller.Principal{}, legacy, false, false},
		{caller.Principal{ID: "lane:child", Level: 4, Starter: legacy.ID}, legacy, true, false},
		{caller.Principal{ID: "supervisor:root", Level: 6}, known, true, true},
		{caller.Principal{ID: "supervisor:top", Level: 5}, known, false, false},
		{caller.Principal{ID: "supervisor:mini", Level: 4}, known, false, false},
		{caller.Principal{ID: "supervisor:other", Level: 6}, caller.Principal{ID: "lane:current", Level: 3, Starter: "supervisor:mini"}, false, false},
	} {
		allowed, legacy := MessageDecision(row.from, row.to)
		if allowed != row.allowed || legacy != row.legacy {
			t.Fatalf("decision for %+v -> %+v = (%v, %v), want (%v, %v)", row.from, row.to, allowed, legacy, row.allowed, row.legacy)
		}
	}
}
