package lane

import (
	"fmt"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/observation"
)

type refusalInfo struct {
	id, path string
	run      int
	offset   int64
	when     float64
	targets  []string
	shingles map[string]bool
	checked  bool
}

func position(item *scanItem) object {
	return observation.Position(safePath(item.record.shown), item.line, item.offset, item.index)
}
func (scan *refusalScan) search(item *scanItem) (*guard, string) {
	deadline := time.Now().Add(time.Second)
	if item.cut {
		item.record.count(item.run, "cut_results", 1)
	}
	parts := []string{item.text}
	if item.tail != "" {
		parts = append(parts, item.tail)
	}
	lineParts := [][]string{}
	for _, part := range parts {
		lines := recordLines(part)
		for _, line := range lines {
			if len([]rune(line)) > 4096 {
				item.record.count(item.run, "cut_lines", 1)
			}
		}
		lineParts = append(lineParts, lines)
	}
	for _, lines := range lineParts {
		for i, line := range lines {
			runes := []rune(line)
			if len(runes) > 4096 {
				runes = runes[:4096]
			}
			for index := range scan.guards {
				g := &scan.guards[index]
				result := g.expression.search(string(runes), deadline)
				if result == regexTimeout {
					item.record.count(item.run, "timed_out", 1)
					return nil, ""
				}
				if result == regexHit {
					end := i + 3
					if end > len(lines) {
						end = len(lines)
					}
					return g, strings.Join(lines[i:end], "\n")
				}
			}
		}
	}
	return nil, ""
}
func (scan *refusalScan) handle(item *scanItem) error {
	key := item.record.path + "\x00" + item.id
	if item.kind == "call" {
		if item.class == "shell" {
			if err := scan.substitutionCall(item); err != nil {
				return err
			}
		}
		if item.id == "" {
			return nil
		}
		if _, ok := scan.calls[key]; !ok {
			scan.callOrder = append(scan.callOrder, key)
		}
		scan.calls[key] = item
		if len(scan.calls) > 4096 {
			for len(scan.callOrder) > 0 {
				oldest := scan.callOrder[0]
				scan.callOrder = scan.callOrder[1:]
				if call := scan.calls[oldest]; call != nil {
					if call.class == "shell" {
						if err := scan.decide(call); err != nil {
							return err
						}
					}
					delete(scan.calls, oldest)
					break
				}
			}
		}
		return nil
	}
	var g *guard
	var message string
	if item.kind == "hook" || item.error {
		g, message = scan.search(item)
	}
	if g != nil {
		call := scan.calls[key]
		delete(scan.calls, key)
		return scan.refusedCall(item, call, g, message)
	}
	if item.kind == "result" {
		if call := scan.calls[key]; call != nil && !call.compared {
			call.compare = append([]*refusalInfo{}, scan.refused...)
			call.compared = true
			call.resultWhen = item.when
		}
	}
	return nil
}

func (scan *refusalScan) substitutionCall(call *scanItem) error {
	found, err := ShellSubstitutionInText(call.text, scan.textTools)
	if err != nil || !found {
		return err
	}
	place := call.id
	if place == "" {
		place = fmt.Sprintf("@%d:%d", call.offset, call.index)
	}
	id := "ws-" + recordDigest(scan.lane, observation.Kind, call.record.path, place)[:24]
	if scan.known[id] {
		return nil
	}
	tool := safeName(call.tool, `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`)
	if tool == nil {
		tool = "shell"
	}
	command := excerpt(call.text)
	command["length"] = call.length
	command["sha256"] = call.sha
	p := observation.Payload(call.run, id, tool, call.at, command, safeName(call.id, `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`), position(call))
	if err := scan.emitPayload("lane.workaround_suspected", p, call.at); err != nil {
		return err
	}
	scan.known[id] = true
	return nil
}
func (scan *refusalScan) emitPayload(kind string, p object, at any) error {
	e := envelope(scan.lane, kind, checkedRefusal(p), "laneboss")
	e["occurred_at"] = at
	if scan.emit != nil {
		return scan.emit(e)
	}
	_, err := scan.s.record(e, 10)
	if err != nil {
		if _, ok := err.(*storeRefusalError); ok {
			scan.refusedEvents++
			return nil
		}
		return err
	}
	field := "refusals"
	if kind == "lane.workaround_suspected" {
		field = "suspicions"
	}
	scan.appended[field] = integer(scan.appended[field]) + 1
	return nil
}
func (scan *refusalScan) refusedCall(result, call *scanItem, g *guard, message string) error {
	place := result.id
	if place == "" {
		place = fmt.Sprintf("@%d:%d", result.offset, result.index)
	}
	id := "rf-" + recordDigest(scan.lane, result.record.path, place)[:24]
	info := &refusalInfo{id: id, path: result.record.path, run: result.run, offset: result.offset, when: result.when, targets: []string{}}
	if call != nil {
		if call.class == "shell" {
			writes, named := analyseShell(call.text, call.cwd)
			info.targets = writes
			if len(writes) == 0 {
				info.targets = named
			}
		} else {
			info.targets = call.writes
			if len(info.targets) == 0 {
				info.targets = call.named
			}
		}
		info.shingles = shingles(call.text)
		info.checked = true
	}
	scan.refused = append(scan.refused, info)
	if len(scan.refused) > 64 {
		scan.refused = scan.refused[len(scan.refused)-64:]
	}
	if scan.known[id] {
		return nil
	}
	via := "tool-result"
	var hook, tool, command, callPosition any
	if result.kind == "hook" {
		via = "hook"
		hook = object{"event": safeName(result.event, `[A-Za-z][A-Za-z0-9_]{0,63}`), "name": safeName(result.name, `[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}`)}
	}
	if call != nil {
		tool = safeName(call.tool, `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`)
		excerpt := excerpt(call.text)
		excerpt["length"] = call.length
		excerpt["sha256"] = call.sha
		command = excerpt
		callPosition = position(call)
	}
	targets := []string{}
	for _, path := range info.targets {
		targets = append(targets, safePath(path))
	}
	payload := object{"run": result.run, "refusal": id, "guard": g.name, "kind": g.kind, "format": result.record.format, "via": via, "hook": hook, "tool": tool, "at": result.at, "command": command, "message": excerpt(message), "targets": cappedPaths(targets, nil), "call": object{"id": safeName(result.id, `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`), "record": callPosition}, "record": position(result), "workarounds_checked": info.checked}
	scan.known[id] = true
	return scan.emitPayload("lane.refusal", payload, result.at)
}
func (scan *refusalScan) refusedText(item *scanItem, g *guard, message string) error {
	id := "rf-" + recordDigest(scan.lane, item.record.path, item.record.launch, fmt.Sprintf("@%d:0", item.offset))[:24]
	if scan.known[id] {
		return nil
	}
	scan.known[id] = true
	p := object{"run": item.run, "refusal": id, "guard": g.name, "kind": g.kind, "format": "text", "via": "log", "hook": nil, "tool": nil, "at": nil, "command": nil, "message": excerpt(message), "targets": []any{}, "call": nil, "record": position(item), "workarounds_checked": false}
	return scan.emitPayload("lane.refusal", p, nil)
}
func (scan *refusalScan) decide(call *scanItem) error {
	infos := scan.refused
	if call.compared {
		infos = call.compare
	}
	var writes []string
	var mine map[string]bool
	analysed := false
	for _, info := range infos {
		later := call.run > info.run
		if call.run == info.run {
			if call.record.path == info.path {
				later = call.offset > info.offset
			} else {
				later = call.when > 0 && info.when > 0 && call.when > info.when
			}
		}
		if !info.checked || !later {
			continue
		}
		if !analysed {
			writes, _ = analyseShell(call.text, call.cwd)
			mine = shingles(call.text)
			analysed = true
		}
		hit := []string{}
		for _, path := range writes {
			if contains(info.targets, path) {
				hit = append(hit, path)
			}
		}
		ways, paths := []string{}, []string{}
		if len(hit) > 0 {
			ways = append(ways, "shell-write")
			paths = append(paths, hit...)
		}
		similar := reworded(mine, info.shingles)
		if similar != nil {
			ways = append(ways, "reworded")
			paths = append(paths, writes...)
		}
		if len(ways) == 0 {
			continue
		}
		place := call.id
		if place == "" {
			place = fmt.Sprintf("@%d:%d", call.offset, call.index)
		}
		id := "ws-" + recordDigest(info.id, call.record.path, place)[:24]
		if scan.known[id] {
			continue
		}
		scan.known[id] = true
		safePaths, safeHit := []string{}, []string{}
		for _, path := range paths {
			safePaths = append(safePaths, safePath(path))
		}
		for _, path := range hit {
			safeHit = append(safeHit, safePath(path))
		}
		if len(safePaths) == 0 {
			safePaths = append(safePaths, "(command)")
		}
		tool := safeName(call.tool, `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`)
		if tool == nil {
			tool = "shell"
		}
		command := excerpt(call.text)
		command["length"] = call.length
		command["sha256"] = call.sha
		p := object{"run": call.run, "suspicion": id, "refusal": info.id, "how": unique(ways), "paths": cappedPaths(safePaths, safeHit), "tool": tool, "at": call.at, "command": command, "call": object{"id": safeName(call.id, `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`), "record": position(call)}, "similarity": similar}
		if err := scan.emitPayload("lane.workaround_suspected", p, call.at); err != nil {
			return err
		}
	}
	return nil
}
