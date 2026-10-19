package eventstore

import (
	"fmt"
	"strings"

	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/faults"
)

// External lifecycle observations use a reserved actor namespace, covered by
// the existing event hash. This keeps version-1 envelopes and payloads readable
// by every command group. Launcher principals can never occupy this namespace.
const externalActorPrefix = "event.append:"

// RunMismatch keeps recovery guidance identical for lane and turn operations.
func RunMismatch(lane string) string {
	return fmt.Sprintf("lane %s's external projection differs from its launcher-recorded run; no launch or signal was attempted\nInstead: the human marks the lane abandoned with lane mark --state abandoned and starts work under a new name.", lane)
}

func LifecycleKind(kind string) bool {
	switch kind {
	case "lane.planned", "lane.started", "lane.adopted", "lane.resumed", "lane.ended", "lane.timeout", "lane.stuck", "lane.lost", "lane.gone", "lane.delivered", "lane.returned", "lane.cleaned", "lane.state", "lane.merged", "lane.deployed", "lane.landed":
		return true
	}
	return false
}

// ExternallyAppended describes stored origin, never the claimed payload or
// actor supplied to event append. Only AppendExternal sets that command's actor.
func ExternallyAppended(e Object) bool {
	return LifecycleKind(text(e["kind"])) && strings.HasPrefix(text(e["actor"]), externalActorPrefix)
}

// CheckExternalBinding runs the existing replay-scope validation before the
// CLI authorizes a validated event. It neither opens nor creates the store.
func (c *Configuration) CheckExternalBinding(e Object) error {
	switch text(e["kind"]) {
	case "lane.started", "lane.adopted", "lane.resumed":
		return checkBinding(e, &Directory{Config: c, Path: realPath(c.StatePath)})
	}
	return nil
}

// AppendExternal preserves validation and transition diagnostics, but cannot
// create launcher authority even when the input claims actor "laneboss". The
// authenticated appender replaces that claim. Repeated inputs remain idempotent.
func (s *Store) AppendExternal(value any, principal string) (Object, error) {
	e, err := ValidateCLI(value)
	if err != nil {
		return nil, err
	}
	if !records.ValidID(principal) {
		return nil, Refuse("the caller has no recorded identity")
	}
	if LifecycleKind(text(e["kind"])) {
		if e["kind"] == "lane.started" && faults.Get("event-allow-started").Point != "" {
			if err := faults.Reach("event-allow-started"); err != nil {
				return nil, err
			}
		} else {
			e["actor"] = externalActorPrefix + principal
		}
	}
	return s.Append(e)
}
