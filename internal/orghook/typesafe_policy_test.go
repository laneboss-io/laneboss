package orghook

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/decisionsrv"
)

func TestGuidanceCannotRefuse(t *testing.T) {
	settings := decisionsrv.GuideSettings{Judge: "stand-in", WarnAt: 0.5, RefuseAt: 0.85, RefuseSet: true, OnUnavailable: "refuse"}
	decision := decisionsrv.GuideDecision{ID: "fixture-decision", Answer: "Review the requested change."}
	for _, row := range []struct {
		outcome string
		p       float64
		band    decisionsrv.Band
	}{
		{"answered", 0.99, decisionsrv.BandRefuse},
		{"answered", 0.5, decisionsrv.BandWarn},
		{"timeout", 0, decisionsrv.BandNone},
		{"output", 0, decisionsrv.BandNone},
		{"withheld", 0, decisionsrv.BandNone},
		{"partial", 0, decisionsrv.BandNone},
	} {
		allowed, _, advice, note := guardVerdict(settings, []decisionsrv.Scored{{Decision: decision, Outcome: row.outcome, Score: row.p, Band: row.band}}, "baseline permits", false)
		if !allowed || advice == "" || !strings.Contains(advice, decision.ID) {
			t.Fatalf("ordinary %s guidance refused or lost its advice", row.outcome)
		}
		if note["band"] == "refuse" || note["band"] == "refuse-unscored" {
			t.Fatal("receipt claims refusal authority")
		}
	}
	allowed, reason, advice, _ := guardVerdict(settings, []decisionsrv.Scored{{Decision: decision, Outcome: "answered", Score: 0.1, Band: decisionsrv.BandNone}}, "baseline permits", false)
	if !allowed || reason != "baseline permits" || advice != "" {
		t.Fatal("low-probability control changed ordinary work")
	}
}
