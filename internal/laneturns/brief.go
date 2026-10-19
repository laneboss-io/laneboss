package laneturns

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/peers"
	"laneboss.io/laneboss/internal/protocol"
	"laneboss.io/laneboss/internal/rolepolicy"
)

var protocolBytes = protocol.Bytes()

func ended(data []byte) []byte {
	if bytes.HasSuffix(data, []byte{'\n'}) {
		return data
	}
	return append(append([]byte{}, data...), '\n')
}
func composeBrief(c *configuration, lane, project string, data []byte, label string, recorded caller.Line, selected ...*rolepolicy.Selection) ([]byte, error) {
	return composeTurnBrief(c, lane, project, data, label, recorded, false, selected...)
}

// composeTurnBrief places the loop's automatic idle payload at byte zero when
// requested by turn. Manual idle, task and mail messages retain policy first.
func composeTurnBrief(c *configuration, lane, project string, data []byte, label string, recorded caller.Line, idleFirst bool, selected ...*rolepolicy.Selection) ([]byte, error) {
	if err := checkText(data, label, "brief"); err != nil {
		return nil, err
	}
	p := project
	if p == "" {
		p = "none"
	}
	var b bytes.Buffer
	intro := "Everything above this block is the brief exactly as written."
	if idleFirst && len(data) > 0 {
		b.Write(ended(data))
		b.WriteByte('\n')
	}
	if len(selected) > 0 && selected[0] != nil {
		// Every message carries the current project and level decisions. Only
		// automatic idle turns carry that policy after their original payload.
		section := decisionsrv.BriefSectionFor(selected[0].Catalog.Root, project, selected[0].Level, func(text string) bool {
			rule, _ := findCredential(text)
			return rule != ""
		})
		var prefix []byte
		var err error
		if idleFirst {
			prefix, err = selected[0].PolicyWith(section)
		} else {
			prefix, err = selected[0].PrefixWith(section)
		}
		if err != nil {
			return nil, refused("%s", err.Error())
		}
		if err := credentialError("org role and protocol", prefix); err != nil {
			return nil, err
		}
		b.Write(prefix)
		intro = "The task after 'Your task' is the brief exactly as written; org policy precedes it."
		if idleFirst {
			intro = "The idle payload at the start is exactly as written; org policy follows it in this same message."
		}
	}
	if !idleFirst && len(data) > 0 {
		b.Write(ended(data))
	}
	reportLine, err := peers.ReportLine(c.callerConfig(), lane, recorded)
	if err != nil {
		return nil, refused("%s", err)
	}
	fmt.Fprintf(&b, "\n<!-- laneboss launcher block: begin (protocol %s) -->\n\n---\n\n# Launcher block\n\n%s laneboss %s appended this block.\n\n- Configuration: %s\n- Project: %s\n- Lane: %s\n\n%s- Protocol version: %s\n- Brief sha256: %s\n\n", protocolVersion, intro, launcherVersion, c.name, p, lane, reportLine, protocolVersion, digest(data))
	b.Write(ended(protocolBytes))
	for _, rule := range c.allRules(project) {
		fmt.Fprintf(&b, "\n## Standing rules: %s (sha256 %s)\n\n", rule.path, digest(rule.data))
		b.Write(ended(rule.data))
	}
	b.WriteString("\n<!-- laneboss launcher block: end -->\n")
	if b.Len() > 5*1024*1024 {
		return nil, refused("the rendered brief exceeds its 5 MiB handover limit")
	}
	return b.Bytes(), nil
}
func checkRendered(s *stateDir, lane string, p object) error {
	if !exactKeys(p, "inputs output project touches launcher_version") || len(array(p["inputs"])) < 2 {
		return refused("brief.rendered: invalid input inventory")
	}
	for i, v := range array(p["inputs"]) {
		input := obj(v)
		role := "rules"
		detail := "path"
		if i == 0 {
			role = "brief"
		}
		if i == 1 {
			role = "protocol"
			detail = "version"
		}
		if !exactKeys(input, "role sha256 copy "+detail) || input["role"] != role || !hashPattern.MatchString(str(input["sha256"])) || str(input["copy"]) != "lanes/"+lane+"/inputs/"+str(input["sha256"]) {
			return refused("brief.rendered: input %d is invalid", i)
		}
		data, err := s.read(str(input["copy"]), 8*1024*1024)
		if err != nil || digest(data) != input["sha256"] {
			return integrity("brief.rendered: kept input %d is missing or does not match its hash", i)
		}
	}
	out := obj(p["output"])
	if !exactKeys(out, "path sha256") || str(out["path"]) != s.lanePath(lane, "rendered", str(out["sha256"])+".md") {
		return refused("brief.rendered: output is not bound to its lane")
	}
	data, err := s.read("lanes/"+lane+"/rendered/"+str(out["sha256"])+".md", 8*1024*1024)
	if err != nil || digest(data) != out["sha256"] {
		return integrity("brief.rendered: output is missing or does not match its hash")
	}
	return nil
}
func renderBrief(s *laneSession, lane, project, source string, data, output []byte, selected ...*rolepolicy.Selection) (object, error) {
	// Reject a damaged or unrecorded store before creating any input copies.
	st, err := openStore(s.state, true)
	if err != nil {
		return nil, err
	}
	st.close()
	inputs := []any{}
	consumed := []struct {
		role, detail, value string
		data                []byte
	}{{"brief", "path", realPath(source), data}, {"protocol", "version", protocolVersion, protocolBytes}}
	for _, r := range s.c.allRules(project) {
		consumed = append(consumed, struct {
			role, detail, value string
			data                []byte
		}{"rules", "path", r.path, r.data})
	}
	if len(selected) > 0 && selected[0] != nil {
		for _, input := range selected[0].Inputs {
			consumed = append(consumed, struct {
				role, detail, value string
				data                []byte
			}{"rules", "path", input.Path, input.Bytes})
		}
	}
	created := []string{}
	for _, input := range consumed {
		dig := digest(input.data)
		rel := "lanes/" + lane + "/inputs/" + dig
		err = s.state.write(rel, input.data, 0600, false)
		if os.IsExist(err) {
			kept, e := s.state.read(rel, 8*1024*1024)
			if e != nil || digest(kept) != dig {
				return nil, integrity("kept input does not match its hash")
			}
		} else if err != nil {
			return nil, err
		} else {
			created = append(created, rel)
		}
		inputs = append(inputs, object{"role": input.role, input.detail: input.value, "sha256": dig, "copy": rel})
	}
	dig := digest(output)
	rel := "lanes/" + lane + "/rendered/" + dig + ".md"
	out := object{"path": s.state.lanePath(lane, "rendered", dig+".md"), "sha256": dig}
	err = s.state.write(rel, output, 0644, false)
	written := err == nil
	if os.IsExist(err) {
		kept, e := s.state.read(rel, len(output)+1)
		if e != nil || !bytes.Equal(kept, output) {
			return nil, integrity("the rendered brief does not hold the bytes its name promises")
		}
	} else if err != nil {
		return nil, err
	}
	_, err = s.append("brief.rendered", lane, "laneboss", object{"inputs": inputs, "output": out, "project": nilIfEmpty(project), "touches": []any{}, "launcher_version": launcherVersion})
	if err != nil {
		if written {
			parent, e := s.state.dir(filepath.Dir(rel), false)
			if e == nil {
				parent.Remove(filepath.Base(rel))
				parent.Close()
			}
		}
		for _, path := range created {
			check, e := openStore(s.state, false)
			if e != nil || check == nil {
				continue
			}
			var n int
			e = check.db.QueryRow("SELECT count(*) FROM events WHERE kind = 'brief.rendered' AND lane = ? AND instr(payload, ?) > 0", lane, path).Scan(&n)
			check.close()
			if e == nil && n == 0 {
				parent, e := s.state.dir(filepath.Dir(path), false)
				if e == nil {
					parent.Remove(filepath.Base(path))
					parent.Close()
				}
			}
		}
		return nil, err
	}
	return out, nil
}
func verifyRendered(s *laneSession, lane string, item object) error {
	if !hashPattern.MatchString(str(item["sha256"])) || str(item["path"]) != s.state.lanePath(lane, "rendered", str(item["sha256"])+".md") {
		return integrity("lane %s's brief is not where the store says it is", lane)
	}
	data, err := s.state.read("lanes/"+lane+"/rendered/"+str(item["sha256"])+".md", 8*1024*1024)
	if err != nil || digest(data) != item["sha256"] {
		return integrity("lane %s's brief is missing or no longer matches its hash", lane)
	}
	return nil
}
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
