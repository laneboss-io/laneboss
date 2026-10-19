package laneturns

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/authorship"
	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/report"
)

func checkMessage(data []byte) error {
	if len(data) > maxMessage {
		return refused("the message is larger than 262144 bytes, the most a message may hold")
	}
	if err := checkText(data, "the message", "message"); err != nil {
		return err
	}
	if strings.TrimSpace(string(data)) == "" {
		return refused("the message is empty: it holds nothing but white space")
	}
	return nil
}
func sendCommand(c *configuration, a arguments, stdin io.Reader) (object, error) {
	sender, err := report.Resolve(c.name)
	if err != nil {
		return nil, refused("%s\nInstead: report up with laneboss report.", err.Error())
	}
	if v, ok := a.values["from"]; ok {
		if authorship.Reserved(v) {
			return nil, refused("human sender names are reserved for the dashboard; use your lane, instance, supervisor or cli identity\nInstead: omit --from, so the launcher records who you are, or report up with laneboss report.")
		}
		if !records.ValidSender(v) {
			return nil, refused("--from must be a valid sender ID (instance names contain 1 to 96 safe characters)")
		}
		if rule, _ := findCredential(v); rule != "" {
			return nil, refused("--from: looks like a credential (%s); nothing was stored", rule)
		}
		if v != sender.ID {
			return nil, refused("--from must equal the resolved principal ID; a lane cannot supply another sender\nInstead: omit --from and report up with laneboss report.")
		}
	}
	file, hasFile := a.values["file"]
	if hasFile && a.source != nil {
		return nil, refused("lane send takes the message from --file PATH or from standard input (-), not from both")
	}
	if a.source != nil && *a.source != "-" {
		return nil, refused("lane send never takes the message as an argument, because a shell would expand it before the launcher saw it: give --file PATH, or - to read it from standard input")
	}
	if !hasFile && a.source == nil {
		return nil, refused("lane send needs the message: give --file PATH, or - to read it from standard input")
	}
	var data []byte
	if hasFile {
		data, err = c.readExternal(file, "--file", maxBrief)
	} else {
		if stdin == nil {
			return nil, refused("standard input is closed, so there is no message to read from it")
		}
		data, err = io.ReadAll(io.LimitReader(stdin, maxMessage+1))
	}
	if err != nil {
		return nil, err
	}
	if a.flags["ask"] {
		// The message is a question. One that a recorded decision already answers gets the recorded answer back and is
		// not stored; any other is stored as usual, with the decisions that the judge found related (docs/decisions.md,
		// "Guiding agents").
		if err = checkMessage(data); err != nil {
			return nil, err
		}
		if _, err = report.CheckMessage(c.name, sender, a.get("lane")); err != nil {
			return nil, refused("%s\nInstead: report up with laneboss report.", err.Error())
		}
		decided, check := decidedQuestion(c, a, data, sender)
		if decided != nil {
			return decided, nil
		}
		result, err := sendMessage(c, a.get("lane"), sender, data)
		if err != nil {
			return nil, err
		}
		result["decided"] = false
		result["judge"] = check["judge"]
		result["related"] = check["related"]
		return result, nil
	}
	return sendMessage(c, a.get("lane"), sender, data)
}
func mailTarget(s *laneSession, lane string) (object, error) {
	row, err := s.recordedRow(lane)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// report.CheckMessage authorizes this observation by name alone.
		row, err = s.known(lane)
		if err != nil {
			return nil, err
		}
	}
	m := obj(row["mail"])
	if !flag(m["turn_based"]) {
		return nil, refused("lane %s is not turn-based: only a lane started with lane start --turns, or an adopted lane, takes mail", lane)
	}
	if flag(row["cleaned"]) {
		return nil, refused("lane %s was cleaned, so it takes no mail", lane)
	}
	if row["state"] == "abandoned" {
		return nil, refused("lane %s is abandoned, so it takes no mail; its mail is kept", lane)
	}
	previous, err := s.latest(lane)
	if err != nil {
		return nil, err
	}
	// An observed runner may explain a refusal, but only a launcher-made run
	// authorizes mail; no observed metadata reaches the queue.
	runnerName := str(row["runner"])
	if previous != nil {
		runnerName = str(previous["runner"])
	}
	r, runnerErr := s.c.runner(runnerName)
	if runnerErr != nil && previous != nil {
		return nil, runnerErr
	}
	if runnerErr == nil {
		if problems := turnProblems(runnerName, r); len(problems) > 0 {
			return nil, refused("lane %s cannot take mail: runner %s cannot take turns, because %s", lane, runnerName, strings.Join(problems, "; "))
		}
	}
	if previous == nil {
		return nil, refused("lane %s has not run yet, so it takes no mail\nInstead: lane adopt the running session, or lane start --turns", lane)
	}
	if queued(m) >= 1000 {
		return nil, refused("lane %s already has 1000 messages that wait or have returned, the most a lane holds; a turn takes them", lane)
	}
	return row, nil
}
func sendMessage(c *configuration, lane string, sender caller.Principal, data []byte) (object, error) {
	return queueMessage(c, lane, sender, data, false)
}

// attached changes only the displayed sender. The resolved principal remains
// the authority and event actor, including when a later turn takes the mail.
func queueMessage(c *configuration, lane string, sender caller.Principal, data []byte, attached bool) (object, error) {
	legacy, err := checkMailPermission(c, sender, lane, attached)
	if err != nil {
		return nil, refused("%s", err.Error())
	}
	if err := checkMessage(data); err != nil {
		return nil, err
	}
	s, err := openSession(c, false)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if s.state == nil {
		return nil, refused("lane %s is not known to configuration %s", lane, c.name)
	}
	if _, err = s.known(lane); err != nil {
		return nil, err
	}
	if err = s.drain(lane); err != nil {
		return nil, err
	}
	if _, err = mailTarget(s, lane); err != nil {
		return nil, err
	}
	dir, err := s.state.dir("lanes/"+lane, true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	lock, err := lockRoot(dir, "mail.lock", c.setting("lanes", "lock_wait_seconds", 60), "mail lock", false, true)
	if err != nil {
		return nil, err
	}
	defer lock.close()
	// Lifecycle events and pending-event drains use this same lane-directory
	// lock. Hold it from the life/permission recheck through the durable append,
	// without taking the global lifecycle lock that a turn or stop may hold.
	stateLock, err := lockRoot(dir, ".", c.setting("lanes", "lock_wait_seconds", 60), "lane directory lock", false, false)
	if err != nil {
		return nil, err
	}
	defer stateLock.close()
	if err = s.drainLocked(lane, dir); err != nil {
		return nil, err
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	row, err := mailTarget(s, lane)
	if err != nil {
		return nil, err
	}
	// Recheck the report line while the state and mail locks hold: a reused
	// lane must not inherit authorization from its previous legacy life.
	legacy, err = checkMailPermission(c, sender, lane, attached)
	if err != nil {
		return nil, refused("%s", err.Error())
	}
	sequence := integer(obj(row["mail"])["last"]) + 1
	if sequence > 999999999 {
		return nil, refused("the lane has reached the maximum message sequence")
	}
	dig := digest(data)
	name := fmt.Sprintf("%09d-%s", sequence, dig)
	maildir, err := s.state.dir("lanes/"+lane+"/mail", true)
	if err != nil {
		return nil, err
	}
	defer maildir.Close()
	err = writeAtomic(maildir, name, data, 0600, false)
	if os.IsExist(err) {
		kept, readErr := readAt(maildir, name, "the existing message", maxMessage+1)
		if readErr != nil {
			return nil, integrity("the mail file of sequence %d exists and cannot be read back; nothing was recorded", sequence)
		}
		if digest(kept) != dig {
			return nil, integrity("the mail file of sequence %d exists and does not hold the bytes its name promises; it was left as it is and nothing was recorded", sequence)
		}
	} else if err != nil {
		return nil, err
	}
	if err = syncDir(maildir); err != nil {
		return nil, err
	}
	payload := object{"sequence": sequence, "sender": sender.ID, "sha256": dig, "bytes": len(data)}
	if attached {
		payload["sender"] = "attach"
	}
	if legacy {
		payload["legacy_relationship"] = true
	}
	actor := sender.ID
	if faults.Get("mail-actor-fixed-supervisor").Point != "" {
		if err = faults.Reach("mail-actor-fixed-supervisor"); err != nil {
			return nil, err
		}
		actor = "supervisor"
	}
	env, err := envelope("lane.mailed", lane, actor, payload)
	if err != nil {
		return nil, err
	}
	// The lane-directory lock is already held and its pending queue drained.
	// append would try to take that lock again; use the normal transactional
	// store writer directly, retaining its validation and transition checks.
	event, err := s.store.append(env)
	if err != nil {
		return nil, err
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	row, err = s.known(lane)
	if err != nil {
		return nil, err
	}
	result := copyObject(payload)
	result["lane"] = lane
	result["file"] = s.state.lanePath(lane, "mail", name)
	result["event"] = eventRef(event)
	result["waiting"] = queued(obj(row["mail"]))
	return result, nil
}

// SendReport delivers report's terminal channel through the same authorization
// and durable queue as lane send. The principal comes from caller.Resolve.
func SendReport(configName string, from caller.Principal, lane string, data []byte) error {
	c, err := loadConfig(configName)
	if err != nil {
		return err
	}
	_, err = sendMessage(c, lane, from, data)
	return err
}

// SendDashboard is for the authenticated dashboard compose handler. It is not
// exposed as a CLI actor option; the dashboard owns token and Origin checks and
// starts only for the human, so the message goes through sendMessage as the
// human principal: sender and actor are "human", and the peer rule lets the
// human reach a lane at any level.
func SendDashboard(configName, lane, text string) (map[string]any, error) {
	c, err := loadConfig(configName)
	if err != nil {
		return nil, err
	}
	return sendMessage(c, lane, caller.Principal{ID: "human"}, []byte(text))
}
func takeMail(s *laneSession, lane string, m object) ([]byte, []any, error) {
	events, err := s.store.events(lane, "lane.mailed")
	if err != nil {
		return nil, nil, err
	}
	mailed := map[int]object{}
	for _, e := range events {
		if err = checkPayload("lane.mailed", obj(e["payload"])); err != nil {
			return nil, nil, integrity("event seq %d: %s", integer(e["seq"]), err.Error())
		}
		mailed[integer(obj(e["payload"])["sequence"])] = e
	}
	returned := map[int]bool{}
	for _, n := range array(m["returned"]) {
		returned[integer(n)] = true
	}
	parts := [][]byte{}
	taken := []any{}
	size := 0
	queue := append(append([]any{}, array(m["returned"])...), array(m["waiting"])...)
	for _, n := range queue {
		if len(taken) == 64 {
			break
		}
		sequence := integer(n)
		e := mailed[sequence]
		if e == nil {
			return nil, nil, integrity("lane %s: message %d is in the lane's queue, but no lane.mailed event announces it", lane, sequence)
		}
		p := obj(e["payload"])
		name := fmt.Sprintf("%09d-%s", sequence, str(p["sha256"]))
		data, err := s.state.read("lanes/"+lane+"/mail/"+name, maxMessage+1)
		if err != nil {
			return nil, nil, integrity("lane %s: the mail file of sequence %d (event seq %d) is missing or cannot be read as a regular file", lane, sequence, integer(e["seq"]))
		}
		if digest(data) != p["sha256"] || len(data) != integer(p["bytes"]) {
			return nil, nil, integrity("lane %s: the mail file of sequence %d (event seq %d) no longer holds the bytes its name and its event give", lane, sequence, integer(e["seq"]))
		}
		if err = checkText(data, fmt.Sprintf("message %d", sequence), "message"); err != nil {
			return nil, nil, err
		}
		from, err := mailedPrincipal(s.c, lane, e)
		if err != nil {
			return nil, nil, refused("the carried message's sender cannot be resolved: %s", err)
		}
		legacy, err := checkMailPermission(s.c, from, lane, p["sender"] == "attach")
		if err != nil {
			return nil, nil, refused("%s", err)
		}
		if legacy && faults.Get("legacy-turn-strict-only").Point != "" {
			if err := faults.Reach("legacy-turn-strict-only"); err != nil {
				return nil, nil, err
			}
			return nil, nil, refused("the strict-only turn policy refused legacy mail")
		}
		again := ""
		if returned[sequence] {
			again = " (again)"
		}
		part := []byte(fmt.Sprintf("## Message %d from %s at %s%s\n\n", sequence, str(p["sender"]), str(eventTime(e)), again))
		if legacy {
			part = append(part, []byte("legacy_relationship: true\n\n")...)
		}
		part = append(part, data...)
		if !bytes.HasSuffix(data, []byte{'\n'}) {
			part = append(part, '\n')
		}
		added := len(part)
		if len(parts) > 0 {
			added++
		}
		if len(parts) > 0 && size+added > 1048576 {
			break
		}
		parts = append(parts, part)
		taken = append(taken, n)
		size += added
	}
	return bytes.Join(parts, []byte{'\n'}), taken, nil
}
