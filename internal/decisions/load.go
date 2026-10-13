package decisions

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type operation struct {
	kind, target, hash string
	record             object
	line               int
}
type write struct {
	op     *operation
	id     string
	insert bool
	record object
	first  string
}
type plan struct {
	writes                       []write
	added, superseded, unchanged int
	weaker                       map[string]bool
}

func readBatch(path string) ([]*operation, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, invalid("cannot read batch file")
	}
	if len(raw) == 0 {
		return nil, invalid("batch file is empty")
	}
	lines := bytes.Split(raw, []byte{'\n'})
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	ops := []*operation{}
	for i, line := range lines {
		if !utf8.Valid(line) {
			return nil, lineError(i+1, invalid("invalid UTF-8"))
		}
		if strings.Trim(string(line), " \t\r") == "" {
			return nil, lineError(i+1, invalid("empty line"))
		}
		value, e := parseJSON(line)
		if e != nil {
			return nil, lineError(i+1, e)
		}
		op, e := buildOperation(value)
		if e != nil {
			return nil, lineError(i+1, e)
		}
		op.line = i + 1
		ops = append(ops, op)
	}
	return ops, nil
}
func buildOperation(value any) (*operation, error) {
	v := obj(value)
	if v == nil {
		return nil, invalid("operation must be a JSON object")
	}
	kind := str(v["op"])
	if !member(kind, "add supersede") {
		return nil, invalid(`op must be "add" or "supersede"`)
	}
	for _, k := range keys(v) {
		if k != "op" && k != "record" && !(kind == "supersede" && k == "target") {
			return nil, invalid("unknown field: " + k)
		}
	}
	if _, ok := v["record"]; !ok {
		return nil, invalid("missing required field: record")
	}
	target := ""
	if kind == "supersede" {
		if _, ok := v["target"]; !ok {
			return nil, invalid("missing required field: target")
		}
		target = str(v["target"])
		if !idPattern.MatchString(target) {
			return nil, invalid("target must be the id of an existing record")
		}
	}
	record, e := validateRecord(v["record"])
	if e != nil {
		return nil, e
	}
	if kind == "add" {
		for _, f := range []string{"supersedes", "superseded_by"} {
			if record[f] != nil {
				return nil, invalid("record." + f + " is not allowed with op add; use op supersede")
			}
		}
	} else if e = markSuperseding(record, target); e != nil {
		return nil, e
	}
	return &operation{kind: kind, target: target, hash: digest(canonical(record)), record: record}, nil
}
func comparable(v object) object {
	v = clone(v)
	if v["status"] == "superseded" {
		v["status"] = v["status_before_superseded"]
	}
	delete(v, "status_before_superseded")
	delete(v, "superseded_by")
	return v
}
func walk(left, right any, path string) string {
	lm, rm := obj(left), obj(right)
	if lm != nil && rm != nil {
		all := object{}
		for k := range lm {
			all[k] = nil
		}
		for k := range rm {
			all[k] = nil
		}
		for _, k := range keys(all) {
			p := k
			if path != "" {
				p = path + "." + k
			}
			lv, lok := lm[k]
			rv, rok := rm[k]
			if !lok || !rok {
				return p
			}
			if found := walk(lv, rv, p); found != "" {
				return found
			}
		}
		return ""
	}
	if !equal(left, right) {
		return path
	}
	return ""
}
func sameAnswer(left, right object) bool {
	return obj(left["answer"])["verbatim"] == obj(right["answer"])["verbatim"]
}
func outcomeDifference(stored, incoming object) string {
	left, right := clone(stored), clone(incoming)
	lo, ro := obj(left["outcome"]), obj(right["outcome"])
	delete(left, "outcome")
	delete(right, "outcome")
	if f := walk(left, right, ""); f != "" {
		return f
	}
	for _, field := range []string{"actions", "evidence", "followups"} {
		wanted := list(ro[field])
		have := list(lo[field])
		if len(wanted) > len(have) {
			return "outcome." + field
		}
		if !equal(append([]any{}, have[:len(wanted)]...), append([]any{}, wanted...)) {
			return "outcome." + field
		}
	}
	return ""
}
func weakerDifference(stored, incoming object) string {
	if !sameAnswer(stored, incoming) {
		return "answer.verbatim"
	}
	return outcomeDifference(comparable(stored), comparable(incoming))
}
func namedDifference(stored, incoming object, first string) string {
	if !sameAnswer(stored, incoming) {
		return "answer.verbatim"
	}
	original := clone(stored)
	if original["status"] == "superseded" {
		original["status"] = original["status_before_superseded"]
		delete(original, "status_before_superseded")
		delete(original, "superseded_by")
	}
	if digest(canonical(original)) == first {
		if f := walk(original, incoming, ""); f != "" {
			return f
		}
		return "record"
	}
	if f := weakerDifference(stored, incoming); f != "" {
		return f
	}
	return "outcome; the record was annotated after it was first written, and a re-run must carry the record as it was first written"
}
func checkExisting(op *operation, stored object, first string) (bool, error) {
	id := str(op.record["id"])
	if first != "" {
		if op.hash != first {
			return false, invalid("id " + id + " already exists with different content (" + namedDifference(stored, op.record, first) + ")")
		}
		if f := weakerDifference(stored, op.record); f != "" {
			return false, invalid("id " + id + " already exists with different content (" + f + "); its stored first-written hash matches this line, but the stored record does not")
		}
		return false, nil
	}
	if stored["status"] == "superseded" && stored["status_before_superseded"] == nil {
		return false, invalid("id " + id + " was superseded by an older release that did not record its earlier status, so this line cannot be compared with it; leave the line out of the batch")
	}
	if f := weakerDifference(stored, op.record); f != "" {
		return false, invalid("id " + id + " already exists with different content (" + f + ")")
	}
	return true, nil
}
func (s *store) makePlan(ops []*operation) (*plan, error) {
	p := &plan{writes: []write{}, weaker: map[string]bool{}}
	stored := map[string]object{}
	lookup := func(id string) (object, error) {
		if v, ok := stored[id]; ok {
			return v, nil
		}
		row, e := s.one("SELECT * FROM records WHERE id = ?", id)
		if e != nil {
			return nil, e
		}
		var v object
		if row != nil {
			v, e = s.checkedRecord(row)
			if e != nil {
				return nil, e
			}
		}
		stored[id] = v
		return v, nil
	}
	chosen := map[string]*operation{}
	distinct := []*operation{}
	for _, op := range ops {
		id := str(op.record["id"])
		first := chosen[id]
		if first == nil {
			chosen[id] = op
			distinct = append(distinct, op)
		} else if op.hash != first.hash {
			field := "answer.verbatim"
			if sameAnswer(first.record, op.record) {
				field = walk(first.record, op.record, "")
			}
			return nil, lineError(op.line, invalid(fmt.Sprintf("id %s is also written on line %d with different content (%s)", id, first.line, field)))
		}
	}
	fresh := []*operation{}
	for _, op := range distinct {
		id := str(op.record["id"])
		current, e := lookup(id)
		if e != nil {
			return nil, e
		}
		if current == nil {
			fresh = append(fresh, op)
			continue
		}
		first, e := s.firstWritten(id)
		if e != nil {
			return nil, e
		}
		weaker, e := checkExisting(op, current, first)
		if e != nil {
			return nil, lineError(op.line, e)
		}
		if weaker {
			p.weaker[id] = true
		}
		if op.kind == "supersede" {
			target, e := lookup(op.target)
			if e != nil {
				return nil, e
			}
			if target == nil || target["superseded_by"] != id {
				return nil, lineError(op.line, invalid("id "+id+" already exists but "+op.target+" is not superseded by it"))
			}
		}
	}
	pending := map[string]*operation{}
	for _, op := range fresh {
		pending[str(op.record["id"])] = op
	}
	claims := map[string]*operation{}
	for _, op := range fresh {
		if op.kind != "supersede" {
			continue
		}
		if previous := claims[op.target]; previous != nil {
			return nil, lineError(op.line, invalid(fmt.Sprintf("target %s is also superseded on line %d", op.target, previous.line)))
		}
		claims[op.target] = op
		if pending[op.target] != nil {
			continue
		}
		current, e := lookup(op.target)
		if e != nil {
			return nil, e
		}
		if current == nil {
			return nil, lineError(op.line, invalid("target "+op.target+" does not exist"))
		}
		if current["status"] == "superseded" {
			return nil, lineError(op.line, invalid("target "+op.target+" is already superseded by "+str(current["superseded_by"])))
		}
	}
	settled := map[string]bool{}
	for _, op := range fresh {
		path := []string{}
		seen := map[string]int{}
		current := op
		for current != nil && current.kind == "supersede" && !settled[str(current.record["id"])] {
			id := str(current.record["id"])
			if start, ok := seen[id]; ok {
				lines := []int{}
				for _, name := range path[start:] {
					lines = append(lines, pending[name].line)
				}
				sort.Ints(lines)
				names := []string{}
				for _, line := range lines {
					names = append(names, strconv.Itoa(line))
				}
				return nil, invalid("lines " + strings.Join(names, ", ") + " supersede each other in a loop")
			}
			seen[id] = len(path)
			path = append(path, id)
			current = pending[current.target]
		}
		for _, id := range path {
			settled[id] = true
		}
	}
	final := map[string]object{}
	for id, op := range pending {
		final[id] = clone(op.record)
	}
	updates := map[string]object{}
	for target, op := range claims {
		if final[target] != nil {
			if e := markSuperseded(final[target], str(op.record["id"])); e != nil {
				return nil, e
			}
		} else {
			v, e := lookup(target)
			if e != nil {
				return nil, e
			}
			updates[target] = clone(v)
			if e = markSuperseded(updates[target], str(op.record["id"])); e != nil {
				return nil, e
			}
		}
	}
	for _, op := range fresh {
		id := str(op.record["id"])
		p.writes = append(p.writes, write{op, id, true, final[id], op.hash})
		if op.kind == "supersede" && updates[op.target] != nil {
			p.writes = append(p.writes, write{op, op.target, false, updates[op.target], ""})
		}
		if op.kind == "add" {
			p.added++
		} else {
			p.superseded++
		}
	}
	p.unchanged = len(ops) - len(fresh)
	return p, nil
}
func (s *store) loadFile(path string, dry bool) (object, error) {
	ops, e := readBatch(path)
	if e != nil {
		return nil, e
	}
	var p *plan
	before, after := 0, 0
	body := func() error {
		var e error
		before, e = s.count("SELECT count(*) FROM records")
		if e != nil {
			return e
		}
		p, e = s.makePlan(ops)
		if e != nil {
			return e
		}
		if dry {
			after = before + p.added + p.superseded
			return nil
		}
		for _, w := range p.writes {
			if w.insert {
				e = s.insertRecord(w.record, w.first)
			} else {
				e = s.updateRecord(w.record)
			}
			if e != nil {
				if sqliteCode(e) == 19 {
					return lineError(w.op.line, invalid("record "+w.id+" could not be written: database constraint"))
				}
				return e
			}
		}
		if len(p.writes) > 0 {
			if _, e = s.verifySnapshot(4); e != nil {
				return e
			}
		}
		after, e = s.count("SELECT count(*) FROM records")
		return e
	}
	if dry {
		if _, e = s.exec("BEGIN"); e != nil {
			return nil, e
		}
		e = body()
		_, rollback := s.exec("ROLLBACK")
		if e == nil {
			e = rollback
		}
	} else {
		e = s.transaction(body)
	}
	if e != nil {
		return nil, e
	}
	weaker := []string{}
	for id := range p.weaker {
		weaker = append(weaker, id)
	}
	sort.Strings(weaker)
	v := object{"added": p.added, "superseded": p.superseded, "unchanged": p.unchanged, "records_before": before, "records_after": after, "unchanged_by_weaker_comparison": weaker}
	if dry {
		v["dry_run"] = true
	}
	return v, nil
}
