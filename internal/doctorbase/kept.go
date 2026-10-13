package doctorbase

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
)

func jsonNumber(s string) json.Number { return json.Number(s) }
func (s *State) readDirectory(relative string) ([]os.DirEntry, error) {
	parts := strings.Split(relative, "/")
	for i := range parts {
		info, err := s.Root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, Refuse("a directory inside the state directory is a symbolic link or not a directory")
		}
	}
	f, err := s.Root.OpenFile(relative, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}
func checkRendered(state *State, event map[string]any) error {
	p := Object(event["payload"])
	lane := String(event["lane"])
	fail := func(s string) error { return Integrity("event seq %d: %s", integral(event["seq"]), s) }
	if lane == "" {
		return fail("a brief.rendered event needs a lane")
	}
	if !ExactKeys(p, "inputs", "output", "project", "touches", "launcher_version") {
		return fail("its payload must hold exactly inputs, output, project, touches and launcher_version")
	}
	inputs, ok := p["inputs"].([]any)
	if !ok || len(inputs) < 2 {
		return fail("inputs must list the brief, the protocol and each rules file")
	}
	for i, x := range inputs {
		item, ok := x.(map[string]any)
		role, detail := "rules", "path"
		if i == 0 {
			role = "brief"
		} else if i == 1 {
			role = "protocol"
			detail = "version"
		}
		if !ok || !ExactKeys(item, "role", "sha256", "copy", detail) || item["role"] != role {
			return fail(fmt.Sprintf("input %d is not a %s input", i, role))
		}
		digest := String(item["sha256"])
		copy := "lanes/" + lane + "/inputs/" + digest
		if !Digest.MatchString(digest) || item["copy"] != copy {
			return fail(fmt.Sprintf("input %d is not kept under the lane by its hash", i))
		}
		if value, ok := item[detail].(string); !ok || value == "" || role == "protocol" && !versionGrammar.MatchString(value) {
			return fail(fmt.Sprintf("input %d has no valid %s", i, detail))
		}
		b, err := state.Read(copy, 8*1024*1024)
		if err != nil {
			return fail(fmt.Sprintf("kept input %d is missing or cannot be read (%s)", i, OSReason(err)))
		}
		if Hash(b) != digest {
			return fail(fmt.Sprintf("kept input %d does not match its hash", i))
		}
	}
	output, ok := p["output"].(map[string]any)
	if !ok || !ExactKeys(output, "path", "sha256") || !strings.HasPrefix(String(output["path"]), "/") || !Digest.MatchString(String(output["sha256"])) {
		return fail("output must name an absolute path and its hash")
	}
	if p["project"] != nil && !Name.MatchString(String(p["project"])) {
		return fail("project is not a project name")
	}
	if err := eventTouches(p["touches"], "touches"); err != nil {
		return fail("touches must be a sorted list of billing and deploy")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`).MatchString(String(p["launcher_version"])) {
		return fail("launcher_version is not a version")
	}
	return nil
}
func verifyKept(state *State, events []map[string]any) error {
	type mailKey struct{ Lane, Name string }
	named := map[mailKey]int64{}
	for _, event := range events {
		if event["kind"] == "brief.rendered" {
			if err := checkRendered(state, event); err != nil {
				return err
			}
		}
		if event["kind"] == "lane.mailed" {
			p := Object(event["payload"])
			name := fmt.Sprintf("%09d-%s", integral(p["sequence"]), String(p["sha256"]))
			named[mailKey{String(event["lane"]), name}] = integral(p["bytes"])
		}
	}
	lanes, err := state.readDirectory("lanes")
	if os.IsNotExist(err) {
		lanes = nil
	} else if err != nil {
		return Integrity("the lanes directory cannot be read (%s)", OSReason(err))
	}
	found := map[mailKey]int64{}
	mailName := regexp.MustCompile(`^[0-9]{9}-[0-9a-f]{64}$`)
	for _, entry := range lanes {
		lane := entry.Name()
		if _, err := state.readDirectory("lanes/" + lane); err != nil {
			return Integrity("a lane directory is a link, not a directory or cannot be read")
		}
		for _, sub := range []string{"inputs", "mail"} {
			relative := "lanes/" + lane + "/" + sub
			files, err := state.readDirectory(relative)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return Integrity("a lane's %s directory cannot be read (%s)", sub, OSReason(err))
			}
			for _, file := range files {
				name := file.Name()
				if strings.HasPrefix(name, ".tmp-") {
					continue
				}
				limit := int64(8 * 1024 * 1024)
				digest := name
				if sub == "inputs" {
					if !Digest.MatchString(name) {
						return Integrity("a kept input under a lane's inputs directory is not named by a SHA-256 digest")
					}
				} else {
					limit = 262144
					if !mailName.MatchString(name) {
						return Integrity("a file under a lane's mail directory is not named SEQUENCE-DIGEST (nine digits of sequence, a hyphen and the SHA-256 of its bytes)")
					}
					digest = name[10:]
				}
				bytes, err := state.Read(relative+"/"+name, limit)
				if err != nil {
					return Integrity("a kept %s file is not a regular file or cannot be read (%s)", sub, OSReason(err))
				}
				if Hash(bytes) != digest {
					return Integrity("a kept %s file does not match its hash", sub)
				}
				if sub == "mail" {
					found[mailKey{lane, name}] = int64(len(bytes))
				}
			}
		}
	}
	for key, size := range named {
		actual, ok := found[key]
		if !ok {
			return Integrity("a lane.mailed event's mail file is missing")
		}
		if actual != size {
			return Integrity("a mail file's byte count does not match its event")
		}
	}
	return nil
}
