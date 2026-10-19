package identityd

import (
	"context"
	"strings"
)

func laneOwner(name, actor string, previous Record) error {
	if actor == "lane:"+name {
		if unboundStarter() {
			return nil
		}
		return refuse("a lane cannot record a run of itself\nInstead: ask its recorded starter to launch the next run.")
	}
	if previous.Principal != nil && previous.Principal.Starter != actor {
		if unboundStarter() {
			return nil
		}
		return refuse("the lane belongs to another recorded starter\nInstead: have that starter record the next run; a handover needs its own authorized operation.")
	}
	return nil
}

func (s *store) rootCollision(ctx context.Context, proposed Peer, exceptSession *Peer) error {
	check := func(record Record) error {
		if ctx.Err() != nil {
			return refuse("the service request timed out\nInstead: reconnect before recording the lane root.")
		}
		if exceptSession != nil && samePeer(*record.Process, *exceptSession) {
			return nil
		}
		current, err := processFor(ProcessRef{PID: record.Process.PID, Start: record.Process.Start})
		if err != nil || !samePeer(*record.Process, current.Peer) {
			return nil
		}
		line, err := ancestry(current.Peer)
		if err != nil {
			return err
		}
		if inAncestry(proposed, line) {
			if overlapRoot() {
				return nil
			}
			return refuse("the proposed root contains a live recorded session or lane root\nInstead: record a separate process root outside every existing identity tree.")
		}
		return nil
	}
	for _, record := range s.sessions {
		if err := check(record); err != nil {
			return err
		}
	}
	for _, runs := range s.lanes {
		for _, record := range runs {
			if err := check(record); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *store) authorizeLane(ctx context.Context, request Request, principal Principal, peer Peer) (Record, error) {
	if principal.ID == "" {
		return Record{}, unidentified(true)
	}
	if !laneName.MatchString(request.Lane) || request.Run < 1 || request.Process == nil {
		return Record{}, refuse("a lane run needs a lane name, run number, PID and start time\nInstead: record the live run through its identified launcher.")
	}
	previous := s.latestLane(request.Lane)
	if err := laneOwner(request.Lane, principal.ID, previous); err != nil {
		return Record{}, err
	}
	if request.Run != previous.Run+1 {
		return Record{}, refuse("the lane run number is not the next recorded run\nInstead: use the next run number for this lane.")
	}
	if previous.Process != nil {
		if _, err := processFor(ProcessRef{PID: previous.Process.PID, Start: previous.Process.Start}); err == nil && !replaceLiveRun() {
			return Record{}, refuse("the lane's previous run is still live\nInstead: wait for that root to exit before recording the next run.")
		}
	}
	level := request.Level
	if level == 0 {
		level = 3
	}
	if level < 3 || level > 6 || principal.Level > 0 && level >= principal.Level {
		return Record{}, refuse("the lane's level must be below its starter's recorded level\nInstead: select the lane's own lower level.")
	}
	anchor, err := processFor(*request.Process)
	if err != nil {
		return Record{}, err
	}
	childLine, err := ancestry(anchor.Peer)
	if err != nil || anchor.PID == peer.PID || !inAncestry(peer, childLine) {
		return Record{}, refuse("the lane process is not the identified launcher's live descendant\nInstead: record the child from its identified launcher before detaching it.")
	}
	if err := s.rootCollision(ctx, anchor.Peer, nil); err != nil {
		return Record{}, err
	}
	lane := Principal{ID: "lane:" + request.Lane, Level: level, Starter: principal.ID}
	return Record{Op: "lane-started", Actor: principal.ID, Peer: peer, Principal: &lane, Process: &anchor.Peer, Lane: request.Lane, Run: request.Run}, nil
}

func (s *store) authorizeGrant(ctx context.Context, grant Grant, principal Principal, peer Peer, line []process, service Peer) (Record, error) {
	if !validSupervisor(grant.Principal) || !grant.DedicatedSession || principal.Level > 0 && grant.Principal.Level > principal.Level {
		return Record{}, refuse("a role ticket cannot raise the session's recorded level or select a shared root\nInstead: request the dedicated session and role authorized by the bootstrap verifier.")
	}
	anchor, err := processFor(grant.Session)
	if err != nil {
		return Record{}, err
	}
	if !inAncestry(anchor.Peer, line) || anchor.UID == service.UID {
		return Record{}, refuse("the verified session is not the peer's independent live ancestor\nInstead: register from the session authorized by the bootstrap ticket.")
	}
	existing := s.sessionAnchor(line)
	if existing != nil {
		anchorLine, err := ancestry(anchor.Peer)
		if err != nil || !inAncestry(*existing, anchorLine) {
			return Record{}, refuse("registration may not broaden the recorded session root\nInstead: keep the anchor at or below the current dedicated session.")
		}
	}
	if err := s.rootCollision(ctx, anchor.Peer, existing); err != nil {
		return Record{}, err
	}
	return Record{Op: "register", Actor: grant.Principal.ID, Peer: peer, Principal: &grant.Principal, Process: &anchor.Peer}, nil
}

func laneScope(request Request, principal Principal) (string, error) {
	lane := request.Lane
	if strings.HasPrefix(principal.ID, "lane:") {
		own := strings.TrimPrefix(principal.ID, "lane:")
		if lane != "" && lane != own && !foreignLaneScope() {
			return "", refuse("a lane may append records only for itself\nInstead: report up with laneboss report.")
		}
		if lane == "" {
			lane = own
		}
	}
	return lane, nil
}
