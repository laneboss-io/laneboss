package eventstore

import (
	"fmt"
	"unicode/utf8"
)

// ReadMail reads only a message announced by an integrity-checked lane.mailed
// event, using the same contained file reader and digest rules as state verify.
// No event-supplied path is opened, and display callers must screen the text.
func ReadMail(c *Configuration, event Object) (string, error) {
	if event["kind"] != "lane.mailed" || !laneGrammar.MatchString(text(event["lane"])) {
		return "", Integrity("the message event is not a lane mail record")
	}
	p := object(event["payload"])
	sequence, ok := integerValue(p["sequence"])
	dig := text(p["sha256"])
	if !ok || sequence < 1 || sequence > 999999999 || !digestGrammar.MatchString(dig) {
		return "", Integrity("the message event has invalid file metadata")
	}
	d, err := c.OpenDirectory(false)
	if err != nil {
		return "", err
	}
	if d == nil {
		return "", Integrity("the recorded message directory is missing")
	}
	defer d.Close()
	marker, err := d.Marker()
	if err != nil {
		return "", err
	}
	if object(marker["store"]) == nil {
		return "", Integrity("the message directory has no recorded event store owner")
	}
	data, err := d.ReadLane(text(event["lane"]), "mail", fmt.Sprintf("%09d-%s", sequence, dig), 262144)
	if err != nil {
		return "", err
	}
	if data == nil || digest(data) != dig || int64(len(data)) != num(p["bytes"]) || !utf8.Valid(data) {
		return "", Integrity("the recorded message does not match its hash and size")
	}
	return string(data), nil
}
