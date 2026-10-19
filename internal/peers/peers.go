// Package peers applies the recorded report-line rule to every message path.
package peers

import (
	"fmt"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/caller/records"
)

// Allowed permits the human to reach every lane, recorded parent/child traffic,
// and lane peers with equal non-null levels and equal non-null starters.
func Allowed(from, to caller.Principal) bool {
	if !records.ValidID(from.ID) || !records.ValidID(to.ID) {
		return false
	}
	if from.ID == "human" && strings.HasPrefix(to.ID, "lane:") {
		return true
	}
	if from.Starter != "" && from.Starter == to.ID || to.Starter != "" && to.Starter == from.ID {
		return true
	}
	return strings.HasPrefix(from.ID, "lane:") && strings.HasPrefix(to.ID, "lane:") && from.Level > 0 && to.Level == from.Level && from.Starter != "" && to.Starter == from.Starter
}

// LegacyAllowed is the compatibility rule for a recorded lane without a
// starter. The caller must first resolve both principals in the same
// configuration. Historical lanes without a level used the protocol's L3.
// This does not grant legacy lanes peers or attach permission.
func LegacyAllowed(from, to caller.Principal) bool {
	if !records.ValidID(from.ID) || !strings.HasPrefix(to.ID, "lane:") || !records.ValidID(to.ID) || to.Starter != "" {
		return false
	}
	if from.ID == "human" {
		return true
	}
	level := to.Level
	if level == 0 {
		level = 3
	}
	return from.Level >= 4 && from.Level <= 6 && from.Level > level
}

// MessageDecision preserves recorded relationships. Only permission supplied
// by the fallback is marked, except that human mail to a legacy lane is always
// marked. The principals must come from the same configuration's records.
func MessageDecision(from, to caller.Principal) (allowed, legacy bool) {
	allowed = Allowed(from, to)
	if !allowed || from.ID == "human" {
		legacy = LegacyAllowed(from, to)
	}
	return allowed || legacy, legacy
}

func description(p caller.Principal) string {
	name := p.ID
	if strings.HasPrefix(name, "lane:") {
		name = "lane " + strings.TrimPrefix(name, "lane:")
	}
	level := "unrecorded"
	if p.Level > 0 {
		level = fmt.Sprintf("L%d", p.Level)
	}
	starter := p.Starter
	if starter == "" {
		starter = "unrecorded"
	}
	return fmt.Sprintf("%s (%s, supervisor %s)", name, level, starter)
}

// Refusal produces the design's explanation and alternatives from real records.
func Refusal(from, to caller.Principal, lanes []caller.Principal) string {
	target := from.Starter
	if target == "" {
		target = "human"
	}
	names := []string{}
	for _, p := range lanes {
		if p.ID != from.ID && strings.HasPrefix(p.ID, "lane:") && p.Level == from.Level && p.Starter != "" && p.Starter == from.Starter && Allowed(from, p) {
			names = append(names, strings.TrimPrefix(p.ID, "lane:"))
		}
	}
	sort.Strings(names)
	alternative := ""
	if len(names) > 0 {
		alternative = fmt.Sprintf(", or message %s (L%d, supervisor %s)", strings.Join(names, ", "), from.Level, from.Starter)
	}
	return fmt.Sprintf("%s may not message %s: lanes talk only to lanes of the same level under the same supervisor.\nInstead: report up with laneboss report (to %s)%s.", description(from), description(to), target, alternative)
}
