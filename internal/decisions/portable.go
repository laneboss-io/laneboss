package decisions

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"laneboss.io/laneboss/internal/faults"
)

const exportFormat = "laneboss-decisions-jsonl"
const earlierExportFormat = "sup-decisions-jsonl"
const olderExport = "this export comes from an older release whose egress receipts have no previous_entry_sha256 (they predate the egress hash chain), so it cannot be imported as it is and its egress history cannot be carried into this store. Its records can: keep the manifest line and the record lines, set the models, vectors and egress counts in the manifest to 0, and import that; see the Older layout section of docs/decisions.md"

func exportIntoPipe(path string) (bool, error) {
	info, e := os.Stat(path)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, invalid("cannot write export file")
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		if err := faults.Reach("pipe-checked"); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, invalid("export destination already exists")
}
func writeExport(path string, pipe bool, entries []object) error {
	flags := os.O_WRONLY
	if !pipe {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, e := os.OpenFile(path, flags, 0600)
	if os.IsExist(e) {
		return invalid("export destination already exists")
	}
	if e != nil {
		return invalid("cannot write export file")
	}
	if pipe {
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return invalid("cannot write export file")
		}
		if info.Mode()&os.ModeNamedPipe == 0 {
			f.Close()
			return invalid("export destination changed: it is no longer a named pipe; nothing was written")
		}
	}
	for _, entry := range entries {
		if _, e = io.WriteString(f, canonical(entry)+"\n"); e != nil {
			f.Close()
			return invalid("cannot write export file")
		}
	}
	if e = f.Close(); e != nil {
		return invalid("cannot write export file")
	}
	return nil
}
func (s *store) export(path string) (object, error) {
	pipe, e := exportIntoPipe(path)
	if e != nil {
		return nil, e
	}
	entries := []object{}
	var stats object
	e = s.transaction(func() error {
		if _, e := s.verifySnapshot(4); e != nil {
			return e
		}
		var e error
		stats, e = s.stats()
		if e != nil {
			return e
		}
		first := map[string]string{}
		rows, e := s.query("SELECT record_id, record_sha256 FROM first_written")
		if e != nil {
			return e
		}
		for _, r := range rows {
			first[str(r["record_id"])] = str(r["record_sha256"])
		}
		manifest := object{"type": "manifest", "format": exportFormat, "schema_version": 1, "counts": object{"records": stats["records"], "models": len(stats["models"].([]object)), "vectors": stats["vectors"], "egress": stats["egress_entries"]}}
		if len(first) > 0 {
			manifest["first_written"] = len(first)
		}
		entries = append(entries, manifest)
		rows, e = s.query("SELECT * FROM records ORDER BY id")
		if e != nil {
			return e
		}
		for _, r := range rows {
			v, e := s.checkedRecord(r)
			if e != nil {
				return e
			}
			entry := object{"type": "record", "record": v}
			if h, ok := first[str(r["id"])]; ok {
				entry["first_written_sha256"] = h
			}
			entries = append(entries, entry)
		}
		rows, e = s.query("SELECT * FROM models ORDER BY model")
		if e != nil {
			return e
		}
		for _, r := range rows {
			entries = append(entries, object{"type": "model", "model": r})
		}
		rows, e = s.query("SELECT * FROM vectors ORDER BY record_id, which_text, model")
		if e != nil {
			return e
		}
		for _, r := range rows {
			blob, ok := r["vector"].([]byte)
			if !ok {
				return integrity("invalid float32 vector blob")
			}
			r["vector"] = base64.StdEncoding.EncodeToString(blob)
			entries = append(entries, object{"type": "vector", "vector": r})
		}
		rows, e = s.egress()
		if e != nil {
			return e
		}
		for _, r := range rows {
			entries = append(entries, object{"type": "egress", "egress": r})
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if e = writeExport(path, pipe, entries); e != nil {
		return nil, e
	}
	return object{"exported": stats["records"], "out": path}, nil
}
func readJSONLines(path, label string) ([]any, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, invalid("cannot read " + label + " file")
	}
	lines := bytes.Split(raw, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	entries := []any{}
	for _, line := range lines {
		v, e := parseJSON(line)
		if e != nil {
			return nil, e
		}
		entries = append(entries, v)
	}
	return entries, nil
}
func requiredCategory(entry any) (string, object, error) {
	m := obj(entry)
	category := str(m["type"])
	if m == nil || !member(category, "record model vector egress") {
		return "", nil, invalid("invalid import entry type")
	}
	payload := obj(m[category])
	if payload == nil {
		return "", nil, invalid("invalid import entry payload")
	}
	for _, k := range keys(m) {
		if k != "type" && k != category && !(category == "record" && k == "first_written_sha256") {
			return "", nil, invalid("unknown import entry field: " + k)
		}
	}
	return category, payload, nil
}
func (s *store) importFile(path string) (object, error) {
	entries, e := readJSONLines(path, "import")
	if e != nil {
		return nil, e
	}
	if len(entries) == 0 || obj(entries[0]) == nil {
		return nil, invalid("import requires a manifest")
	}
	manifest := obj(entries[0])
	version, ok := integer(manifest["schema_version"])
	format := str(manifest["format"])
	if manifest["type"] != "manifest" || (format != exportFormat && format != earlierExportFormat) || !ok || version != 1 {
		return nil, invalid("invalid import manifest")
	}
	declared := int64(0)
	if x, ok := manifest["first_written"]; ok {
		n, ok := integer(x)
		if !ok || n < 1 {
			return nil, invalid("invalid import manifest: first_written must be a positive integer")
		}
		declared = n
	}
	entries = entries[1:]
	for _, entry := range entries {
		m := obj(entry)
		if m["type"] == "egress" {
			payload := obj(m["egress"])
			if payload != nil {
				if _, ok := payload["previous_entry_sha256"]; !ok {
					return nil, invalid(olderExport)
				}
			}
		}
	}
	counts := object{"records": 0, "models": 0, "vectors": 0, "egress": 0}
	carried := int64(0)
	e = s.transaction(func() error {
		mismatch, e := s.layoutMismatch(4)
		if e != nil {
			return e
		}
		if mismatch != "" {
			return integrity("schema definition mismatch: " + mismatch)
		}
		stats, e := s.stats()
		if e != nil {
			return e
		}
		for _, k := range []string{"records", "egress_entries", "lane_records", "feedback_events"} {
			n, _ := integer(stats[k])
			if n > 0 {
				return invalid("import requires an empty initialized store")
			}
		}
		if len(stats["models"].([]object)) > 0 {
			return invalid("import requires an empty initialized store")
		}
		for _, entry := range entries {
			category, v, e := requiredCategory(entry)
			if e != nil {
				return e
			}
			switch category {
			case "record":
				first := ""
				if x, ok := obj(entry)["first_written_sha256"]; ok {
					if declared == 0 {
						return invalid("a record carries first_written_sha256 but the manifest declares no first_written count")
					}
					first = str(x)
					if !hashPattern.MatchString(first) {
						return invalid("first_written_sha256 must be a SHA-256 hex digest")
					}
					carried++
				}
				v, e = validateRecord(v)
				if e == nil {
					e = s.insertRecord(v, first)
				}
				if e != nil {
					return importProblem(e)
				}
				counts["records"] = counts["records"].(int) + 1
			case "model":
				if e = s.insertMapping("models", modelColumns, v); e != nil {
					return importProblem(e)
				}
				counts["models"] = counts["models"].(int) + 1
			case "vector":
				encoded, ok := v["vector"].(string)
				if !ok {
					return invalid("invalid import: vector must be base64 text")
				}
				for _, c := range encoded {
					if c == '\r' || c == '\n' || c == ' ' || c == '\t' {
						return invalid("invalid import: invalid base64 vector")
					}
				}
				blob, e := base64.StdEncoding.DecodeString(encoded)
				if e != nil {
					return invalid("invalid import: invalid base64 vector")
				}
				v["vector"] = blob
				if e = s.insertMapping("vectors", vectorColumns, v); e != nil {
					return importProblem(e)
				}
				counts["vectors"] = counts["vectors"].(int) + 1
			case "egress":
				if e = s.insertMapping("egress_log", egressColumns, v); e != nil {
					return importProblem(e)
				}
				counts["egress"] = counts["egress"].(int) + 1
			}
		}
		if !equal(counts, manifest["counts"]) {
			return invalid("import manifest counts mismatch")
		}
		if carried != declared {
			return invalid("import manifest first_written count mismatch")
		}
		if _, e = s.verifySnapshot(4); e != nil {
			return importProblem(e)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return object{"imported": counts["records"]}, nil
}
func importProblem(e error) error {
	if p, ok := e.(*problem); ok {
		if p.code == 3 {
			return invalid("invalid import: " + p.message)
		}
		return e
	}
	switch sqliteCode(e) {
	case 5, 6, 8, 10, 13, 14:
		return e
	default:
		return invalid("invalid import: database constraint or unsupported value")
	}
}
func (s *store) appendFeedback(id, event, source, at string) (object, error) {
	if !member(event, "merged accepted abandoned refusal cited") {
		return nil, invalid("unsupported feedback event")
	}
	if e := textValue(source, "feedback source", false, false); e != nil {
		return nil, e
	}
	if at == "" {
		at = now()
	}
	if _, e := timestamp(at, "feedback.at"); e != nil {
		return nil, e
	}
	v := object{"case_id": id, "event": event, "at": at, "source": source}
	v["entry_sha256"] = entryHash(v)
	added := false
	e := s.transaction(func() error {
		n, e := s.count("SELECT (SELECT count(*) FROM records WHERE id = ?) + (SELECT count(*) FROM lane_records WHERE id = ?)", id, id)
		if e != nil {
			return e
		}
		if n == 0 {
			return invalid("feedback case does not exist")
		}
		old, e := s.one("SELECT * FROM feedback WHERE case_id = ? AND event = ? AND source = ?", id, event, source)
		if e != nil {
			return e
		}
		if old != nil {
			v, e = checkedFeedback(old)
			return e
		}
		if e = s.insertMapping("feedback", feedbackColumns, v); e != nil {
			return e
		}
		added = true
		return nil
	})
	if e != nil {
		return nil, e
	}
	v["added"] = added
	return v, nil
}
func lineError(line int, e error) error { return invalid(fmt.Sprintf("line %d: %s", line, e.Error())) }
