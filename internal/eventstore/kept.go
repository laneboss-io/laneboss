package eventstore

import (
	"fmt"
	"regexp"
	"strings"
)

var releaseGrammar = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`)

func CheckRendered(e Object, state *Directory) error {
	p := object(e["payload"])
	label := eventLabel(e)
	fail := func(message string) error { return Refuse("%s: %s", label, message) }
	lane := text(e["lane"])
	if e["lane"] == nil {
		return fail("needs a lane")
	}
	if !keysEqual(p, []string{"inputs", "output", "project", "touches", "launcher_version"}) {
		return fail("its payload must hold exactly inputs, output, project, touches and launcher_version")
	}
	inputs, ok := p["inputs"].([]any)
	if !ok || len(inputs) < 2 {
		return fail("inputs must list the brief, the protocol and each rules file")
	}
	for i, v := range inputs {
		role, detail := "rules", "path"
		if i == 0 {
			role = "brief"
		}
		if i == 1 {
			role, detail = "protocol", "version"
		}
		item := object(v)
		if !keysEqual(item, []string{"role", "sha256", "copy", detail}) || item["role"] != role {
			return fail(fmt.Sprintf("input %d is not a %s input", i, role))
		}
		dig := text(item["sha256"])
		copy := "lanes/" + lane + "/inputs/" + dig
		if !digestGrammar.MatchString(dig) || item["copy"] != copy {
			return fail(fmt.Sprintf("input %d is not kept under the lane by its hash", i))
		}
		s, ok := item[detail].(string)
		if !ok || s == "" || role == "protocol" && !protocolGrammar.MatchString(s) {
			return fail(fmt.Sprintf("input %d has no valid %s", i, detail))
		}
		var data []byte
		var err error
		if state != nil {
			data, err = state.ReadLane(lane, "inputs", dig, 8*1024*1024)
			if err != nil {
				return err
			}
		}
		if data == nil {
			return fail("kept input " + copy + " is missing")
		}
		if digest(data) != dig {
			return fail("kept input " + copy + " does not match its hash")
		}
	}
	out := object(p["output"])
	if !keysEqual(out, []string{"path", "sha256"}) || !strings.HasPrefix(text(out["path"]), "/") || !digestGrammar.MatchString(text(out["sha256"])) {
		return fail("output must name an absolute path and its hash")
	}
	if p["project"] != nil && !nameGrammar.MatchString(text(p["project"])) {
		return fail("project is not a project name")
	}
	if err := touches(p["touches"], "touches"); err != nil {
		return fail("touches must be a sorted list of billing and deploy")
	}
	if !releaseGrammar.MatchString(text(p["launcher_version"])) {
		return fail("launcher_version is not a version")
	}
	return nil
}
func verifyInputs(d *Directory, events []Object) (int, error) {
	for _, e := range events {
		if e["kind"] == "brief.rendered" {
			if err := CheckRendered(e, d); err != nil {
				return 0, Integrity("%s", err.Error())
			}
		}
	}
	files, err := d.AllFiles("inputs")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, file := range files {
		if strings.HasPrefix(file.Name, ".tmp-") {
			continue
		}
		lane := file.Lane
		if !laneGrammar.MatchString(lane) {
			lane = "<a lane directory>"
		}
		where := "lanes/" + lane + "/inputs"
		if !digestGrammar.MatchString(file.Name) {
			return 0, Integrity("a kept input under %s is not named by a SHA-256 digest", where)
		}
		data, err := d.ReadLane(file.Lane, "inputs", file.Name, 8*1024*1024)
		if err != nil {
			return 0, err
		}
		if data == nil || digest(data) != file.Name {
			return 0, Integrity("kept input %s/%s does not match its hash", where, file.Name)
		}
		count++
	}
	return count, nil
}

var mailNameGrammar = regexp.MustCompile(`^[0-9]{9}-[0-9a-f]{64}$`)

func verifyMail(d *Directory, events []Object) (int, int, error) {
	type key struct{ lane, name string }
	named := map[key]Object{}
	for _, e := range events {
		if e["kind"] == "lane.mailed" {
			p := object(e["payload"])
			named[key{text(e["lane"]), fmt.Sprintf("%09d-%s", num(p["sequence"]), text(p["sha256"]))}] = e
		}
	}
	files, err := d.AllFiles("mail")
	if err != nil {
		return 0, 0, err
	}
	found := map[key]int{}
	for _, file := range files {
		if strings.HasPrefix(file.Name, ".tmp-") {
			continue
		}
		lane := file.Lane
		if !laneGrammar.MatchString(lane) {
			lane = "<a lane directory>"
		}
		where := "lanes/" + lane + "/mail"
		if !mailNameGrammar.MatchString(file.Name) {
			return 0, 0, Integrity("a file under %s is not named SEQUENCE-DIGEST (nine digits of sequence, a hyphen and the SHA-256 of its bytes)", where)
		}
		info, err := d.mailEntry(file.Lane, file.Name)
		if err != nil {
			return 0, 0, Integrity("%s/%s cannot be read as a message: %s", where, file.Name, err)
		}
		if info == nil {
			continue
		}
		if !info.Mode().IsRegular() {
			return 0, 0, Integrity("%s/%s is not a regular file (a message is a file that is not a link)", where, file.Name)
		}
		data, err := d.ReadLane(file.Lane, "mail", file.Name, 262144)
		if err != nil {
			return 0, 0, Integrity("%s/%s cannot be read as a message: %s", where, file.Name, err)
		}
		if data == nil {
			continue
		}
		if digest(data) != strings.SplitN(file.Name, "-", 2)[1] {
			return 0, 0, Integrity("%s/%s does not match its hash: its name says what its bytes must hash to", where, file.Name)
		}
		found[key{file.Lane, file.Name}] = len(data)
	}
	for k, e := range named {
		size, ok := found[k]
		if !ok {
			return 0, 0, Integrity("lane %s: the mail file of sequence %d (event seq %d) is missing: lanes/%s/mail/%s", k.lane, num(object(e["payload"])["sequence"]), num(e["seq"]), k.lane, k.name)
		}
		if int64(size) != num(object(e["payload"])["bytes"]) {
			return 0, 0, Integrity("lane %s: the mail file of sequence %d (event seq %d) has %d bytes, and its event says %d", k.lane, num(object(e["payload"])["sequence"]), num(e["seq"]), size, num(object(e["payload"])["bytes"]))
		}
	}
	orphans := 0
	for k := range found {
		if named[k] == nil {
			orphans++
		}
	}
	return len(found), orphans, nil
}
