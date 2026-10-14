package laneturns

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
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
	sender := "supervisor"
	if v, ok := a.values["from"]; ok {
		if !senderPattern.MatchString(v) {
			return nil, refused("--from must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
		}
		if rule, _ := findCredential(v); rule != "" {
			return nil, refused("--from: looks like a credential (%s); nothing was stored", rule)
		}
		sender = v
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
	var err error
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
	return sendMessage(c, a.get("lane"), sender, data)
}
func mailTarget(s *laneSession, lane string) (object, error) {
	row, err := s.known(lane)
	if err != nil {
		return nil, err
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
	if previous == nil {
		return nil, refused("lane %s has not run yet, so it takes no mail", lane)
	}
	r, err := s.c.runner(str(previous["runner"]))
	if err != nil {
		return nil, err
	}
	if problems := turnProblems(str(previous["runner"]), r); len(problems) > 0 {
		return nil, refused("lane %s cannot take mail: runner %s cannot take turns, because %s", lane, str(previous["runner"]), strings.Join(problems, "; "))
	}
	if queued(m) >= 1000 {
		return nil, refused("lane %s already has 1000 messages that wait or have returned, the most a lane holds; a turn takes them", lane)
	}
	return row, nil
}
func sendMessage(c *configuration, lane, sender string, data []byte) (object, error) {
	if err := checkMessage(data); err != nil {
		return nil, err
	}
	s, err := openSession(c, false)
	if err != nil {
		return nil, err
	}
	defer s.close()
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
	if err = s.refresh(); err != nil {
		return nil, err
	}
	row, err := mailTarget(s, lane)
	if err != nil {
		return nil, err
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
	payload := object{"sequence": sequence, "sender": sender, "sha256": dig, "bytes": len(data)}
	event, err := s.append("lane.mailed", lane, "supervisor", payload)
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
		again := ""
		if returned[sequence] {
			again = " (again)"
		}
		part := append([]byte(fmt.Sprintf("## Message %d from %s at %s%s\n\n", sequence, str(p["sender"]), str(eventTime(e)), again)), data...)
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
