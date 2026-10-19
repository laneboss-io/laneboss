package lane

import (
	"strings"

	"laneboss.io/laneboss/internal/eventstore"
)

// One filter feeds operational event readers and the authority projection.
// Its inputs are the store's integrity-checked events, not cached projections.
func (s *session) launcherEvents(lane string, kinds ...string) ([]object, error) {
	events, err := s.observedLaneEvents(lane, kinds...)
	if err != nil {
		return nil, err
	}
	owned := []object{}
	for _, event := range events {
		if !eventstore.ExternallyAppended(event) {
			owned = append(owned, event)
		}
	}
	return owned, nil
}

func noLauncherLife(lane string) error {
	return refuse("lane %s has no launcher-recorded life; reuse, resume, archive and clean use only the launcher's own records", lane)
}

func (s *session) recordedRow(lane string) (object, error) {
	observed, err := s.observedRow(lane)
	if err != nil || observed == nil {
		return nil, err
	}
	events, err := s.launcherEvents(lane)
	if err != nil {
		return nil, err
	}
	var row object
	started := false
	for _, event := range events {
		kind := str(event["kind"])
		if kind == "lane.started" || kind == "lane.adopted" {
			started = true
		}
		if started && strings.HasPrefix(kind, "lane.") {
			row = applyProjection(row, event)
		}
	}
	if !started && integer(observed["run"]) > 0 {
		return nil, noLauncherLife(lane)
	}
	return row, nil
}

// Starting a run must not act and only then discover that an observation has
// advanced the public run counter. Collection can safely use its own records.
func (s *session) checkLaunchProjection(lane string, row object) error {
	observed, err := s.observedRow(lane)
	if err != nil {
		return err
	}
	if integer(observed["run"]) != integer(row["run"]) {
		return refuse("%s", eventstore.RunMismatch(lane))
	}
	return nil
}
