package laneturns

import (
	"strings"

	"laneboss.io/laneboss/internal/eventstore"
)

// Operational readers use verified launcher records. The store's readers keep
// the complete observation stream for display and append validation.
func (s *laneSession) events(lane, kind string) ([]object, error) {
	events, err := s.store.events(lane, kind)
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

func (s *laneSession) last(lane, kind string) (object, error) {
	events, err := s.events(lane, kind)
	if err != nil || len(events) == 0 {
		return nil, err
	}
	event := events[len(events)-1]
	if strings.HasPrefix(kind, "lane.") {
		if err := checkPayload(kind, obj(event["payload"])); err != nil {
			return nil, integrity("event seq %d: %s; no turn acts on an event written in an earlier form", integer(event["seq"]), err)
		}
	}
	return event, nil
}

func (s *laneSession) recordedRow(lane string) (object, error) {
	events, err := s.events(lane, "")
	if err != nil {
		return nil, err
	}
	var row object
	for _, event := range events {
		kind := str(event["kind"])
		if row == nil && (kind == "lane.started" || kind == "lane.adopted") {
			row = emptyRow(lane)
		}
		if row != nil && strings.HasPrefix(kind, "lane.") {
			row = applyEvent(row, event)
		}
	}
	return row, nil
}

func noLauncherLife(lane string) error {
	return refused("lane %s has no launcher-recorded life; no turn or signal was attempted\nInstead: lane adopt", lane)
}

func (s *laneSession) checkLaunchProjection(lane string, row object) error {
	observed, err := s.known(lane)
	if err != nil {
		return err
	}
	if integer(observed["run"]) != integer(row["run"]) {
		return refused("%s", eventstore.RunMismatch(lane))
	}
	return nil
}

// An empty turn may acknowledge a name-only observation without trusting any
// runner, session, directory or report-line fields from that observation.
func (s *laneSession) turnState(lane string, idle bool) (object, bool, error) {
	row, err := s.recordedRow(lane)
	if err != nil {
		return nil, false, err
	}
	if row == nil {
		observed, err := s.known(lane)
		if err != nil {
			return nil, false, err
		}
		if integer(observed["run"]) == 0 {
			return nil, false, refused("lane %s has not run yet; start it with lane start --turns", lane)
		}
		mail := obj(observed["mail"])
		if !idle && !flag(observed["running"]) && flag(mail["turn_based"]) && queued(mail) == 0 {
			return nil, true, nil
		}
		return nil, false, noLauncherLife(lane)
	}
	if err := s.checkLaunchProjection(lane, row); err != nil {
		return nil, false, err
	}
	return row, false, nil
}
