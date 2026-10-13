package start

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func (s *storeSnapshot) verifyRendered(event map[string]any) error {
	p, lane := object(event["payload"]), str(event["lane"])
	fail := func(message string) error {
		return integrity(fmt.Sprintf("event seq %d: %s", integer(event["seq"]), message))
	}
	if !laneRE.MatchString(lane) {
		return fail("brief.rendered needs a lane")
	}
	if !exactKeys(p, "inputs", "output", "project", "touches", "launcher_version") {
		return fail("its payload must hold exactly inputs, output, project, touches and launcher_version")
	}
	inputs, ok := p["inputs"].([]any)
	if !ok || len(inputs) < 2 {
		return fail("inputs must list the brief, protocol and each rules file")
	}
	for i, value := range inputs {
		item, ok := value.(map[string]any)
		role, detail := "rules", "path"
		if i == 0 {
			role = "brief"
		}
		if i == 1 {
			role, detail = "protocol", "version"
		}
		if !ok || !exactKeys(item, "role", "sha256", "copy", detail) || item["role"] != role {
			return fail(fmt.Sprintf("input %d is not a %s input", i, role))
		}
		sha := str(item["sha256"])
		copy := "lanes/" + lane + "/inputs/" + sha
		if !digestRE.MatchString(sha) || item["copy"] != copy {
			return fail(fmt.Sprintf("input %d is not kept under the lane by its hash", i))
		}
		detailValue, ok := item[detail].(string)
		if !ok || detailValue == "" || role == "protocol" && !rx(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`).MatchString(detailValue) {
			return fail(fmt.Sprintf("input %d has no valid %s", i, detail))
		}
		data, err := readState(s.root, copy, 8*1024*1024)
		if err != nil {
			return fail("a kept input is missing or unreadable")
		}
		if digest(data) != sha {
			return fail("a kept input does not match its hash")
		}
	}
	output, ok := p["output"].(map[string]any)
	if !ok || !exactKeys(output, "path", "sha256") || !strings.HasPrefix(str(output["path"]), "/") || !digestRE.MatchString(str(output["sha256"])) {
		return fail("output must name an absolute path and its hash")
	}
	if p["project"] != nil && !nameRE.MatchString(str(p["project"])) {
		return fail("project is not a project name")
	}
	if err := touchesCheck("", p["touches"], ""); err != nil {
		return fail("touches must be a sorted list of billing and deploy")
	}
	if !rx(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`).MatchString(str(p["launcher_version"])) {
		return fail("launcher_version is not a version")
	}
	return nil
}
func (s *storeSnapshot) verifyFiles() error {
	named := map[string]any{}
	for _, event := range s.events {
		if event["kind"] == "brief.rendered" {
			if err := s.verifyRendered(event); err != nil {
				return err
			}
		}
		if event["kind"] == "lane.mailed" {
			p := object(event["payload"])
			path := fmt.Sprintf("lanes/%s/mail/%09d-%s", str(event["lane"]), integer(p["sequence"]), str(p["sha256"]))
			named[path] = p["bytes"]
		}
	}
	lanes, err := stateEntries(s.root, "lanes")
	if err != nil {
		return integrity("kept lane files cannot be read")
	}
	sort.Slice(lanes, func(i, j int) bool { return lanes[i].Name() < lanes[j].Name() })
	for _, lane := range lanes {
		base := filepath.Join("lanes", lane.Name())
		info, err := s.root.Lstat(base)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return integrity("a lane directory is a link or is not a directory")
		}
		for _, kind := range []string{"inputs", "mail"} {
			directory := filepath.Join(base, kind)
			entries, err := stateEntries(s.root, directory)
			if err != nil {
				return integrity("kept lane files cannot be read")
			}
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, ".tmp-") {
					continue
				}
				limit := int64(8 * 1024 * 1024)
				sha := name
				if kind == "inputs" {
					if !digestRE.MatchString(name) {
						return integrity("a kept input is not named by a SHA-256 digest")
					}
				} else {
					limit = 262144
					if !rx(`^[0-9]{9}-[0-9a-f]{64}$`).MatchString(name) {
						return integrity("a mail file is not named SEQUENCE-DIGEST")
					}
					sha = name[10:]
				}
				path := filepath.Join(directory, name)
				bytes, err := readState(s.root, path, limit)
				if err != nil {
					return integrity("a kept lane file is not a readable regular file")
				}
				if digest(bytes) != sha {
					return integrity("a kept lane file does not match its hash")
				}
				if expected, ok := named[filepath.ToSlash(path)]; ok {
					if int64(len(bytes)) != integer(expected) {
						return integrity("a mail file's length does not match its event")
					}
					delete(named, filepath.ToSlash(path))
				}
			}
		}
	}
	if len(named) > 0 {
		return integrity("the mail file of a recorded sequence is missing")
	}
	return nil
}
