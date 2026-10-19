package laneturns

import (
	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/report"
	"laneboss.io/laneboss/internal/rolepolicy"
)

func (c *configuration) callerConfig() *config.Configuration {
	return caller.Configuration(c.name, c.home, c.states, c.dir, c.state, c.data)
}

// starter resolves who adopts a lane and the report line the lane records; see the same method in package lane.
func (c *configuration) starter(a arguments) (caller.Principal, caller.Line, error) {
	level, err := rolepolicy.ParseLevel(a.get("level"))
	if err != nil {
		return caller.Principal{}, caller.Line{}, refused("%s", err.Error())
	}
	principal, line, err := caller.LaunchLevel(c.callerConfig(), level)
	if err != nil {
		return caller.Principal{}, caller.Line{}, refused("%s", err)
	}
	if err = rolepolicy.Authenticated(a.get("principal"), principal.ID); err != nil {
		return caller.Principal{}, caller.Line{}, refused("%s", err.Error())
	}
	return principal, line, nil
}

func (c *configuration) caller() (caller.Principal, error) {
	p, err := caller.Resolve(c.callerConfig())
	if err != nil {
		return caller.Principal{}, refused("%s", err)
	}
	return p, nil
}

func (c *configuration) messagePermission(from caller.Principal, lane string) error {
	_, err := report.CheckMessage(c.name, from, lane)
	if err != nil {
		return refused("%s", err)
	}
	return nil
}

func checkMailPermission(c *configuration, from caller.Principal, lane string, attached bool) (bool, error) {
	if attached {
		if err := report.CheckAttach(c.name, from, lane); err != nil {
			return false, err
		}
	}
	return report.CheckMessage(c.name, from, lane)
}

// Attach is an input source, never a principal. Its event retains the resolved
// caller as actor; re-resolve that ID (carriedSender) and recheck the current report line.
func mailedPrincipal(c *configuration, lane string, event object) (caller.Principal, error) {
	id := str(obj(event["payload"])["sender"])
	if id == "attach" {
		id = str(event["actor"])
	}
	return carriedSender(c, lane, id)
}

// The first carried message is the one that wakes a turn. Every carried sender
// is checked again against the current recorded report line before any write.
func turnActor(s *laneSession, lane string, taken []any) (string, error) {
	if len(taken) == 0 {
		return "laneboss", nil
	}
	events, err := s.store.events(lane, "lane.mailed")
	if err != nil {
		return "", err
	}
	mailed := map[int]object{}
	for _, event := range events {
		p := obj(event["payload"])
		mailed[integer(p["sequence"])] = event
	}
	actor := ""
	for _, sequence := range taken {
		event, ok := mailed[integer(sequence)]
		if !ok {
			return "", integrity("a carried message has no recorded sender")
		}
		from, err := mailedPrincipal(s.c, lane, event)
		if err != nil {
			return "", refused("the carried message's sender cannot be resolved: %s", err)
		}
		if _, err = checkMailPermission(s.c, from, lane, obj(event["payload"])["sender"] == "attach"); err != nil {
			return "", refused("%s", err)
		}
		if actor == "" {
			actor = caller.LifecycleActor(from.ID)
		}
	}
	return actor, nil
}
