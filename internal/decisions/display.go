package decisions

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sort"
)

// ReadDisplay runs the CLI's exact verification/search/record code on an
// in-memory SQLite snapshot. The source is opened mode=ro and never receives
// verify's rollback-only FTS integrity command or a writer lock.
func ReadDisplay(path, query string) (map[string]any, error) {
	result := object{"available": false, "items": []object{}, "chains": []any{}, "changes": []object{}, "feedback": []object{}, "lane_scopes": []object{}, "integrity": object{"ok": nil, "problem": nil}}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256*1024*1024 {
		return nil, invalid("the decision store must be a bounded regular file")
	}
	result["available"] = true
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	source, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	conn, err := source.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var image []byte
	err = conn.Raw(func(driver any) error {
		reader, ok := driver.(interface{ Serialize() ([]byte, error) })
		if !ok {
			return invalid("the SQLite driver cannot create a read snapshot")
		}
		var e error
		image, e = reader.Serialize()
		return e
	})
	if err != nil {
		return nil, err
	}
	if len(image) > 256*1024*1024 {
		return nil, invalid("the decision snapshot exceeds its byte limit")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	copy, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer copy.Close()
	err = copy.Raw(func(driver any) error {
		writer, ok := driver.(interface{ Deserialize([]byte) error })
		if !ok {
			return invalid("the SQLite driver cannot restore a read snapshot")
		}
		return writer.Deserialize(image)
	})
	if err != nil {
		return nil, err
	}
	s := &store{db: db, conn: copy, progress: &progress{}}
	version, err := s.count("PRAGMA user_version")
	if err == nil && version != schemaVersion {
		if version >= 1 && version <= 3 {
			err = integrity(fmt.Sprintf("unsupported database schema_version %d: this code uses %d; run the migrate command to upgrade the store (nothing is upgraded automatically)", version, schemaVersion))
		} else {
			err = integrity(fmt.Sprintf("unsupported database schema_version %d", version))
		}
	}
	if err == nil {
		_, err = s.verify()
	}
	if err != nil {
		message, _ := failure(err, &arguments{command: "verify"}, &progress{})
		result["integrity"] = object{"ok": false, "problem": message}
		return result, nil
	}
	result["integrity"] = object{"ok": true, "problem": nil}
	scoped, err := s.query("SELECT * FROM lane_records ORDER BY id")
	if err != nil {
		return nil, err
	}
	for _, row := range scoped {
		record, err := s.checkedLane(row)
		if err != nil {
			return nil, err
		}
		result["lane_scopes"] = append(result["lane_scopes"].([]object), object{"id": record["id"], "config": record["config"], "lane": record["lane"], "instance": record["instance"], "level": record["level"]})
	}
	rows, err := s.query("SELECT * FROM records ORDER BY id")
	if err != nil {
		return nil, err
	}
	all := map[string]object{}
	changes := []object{}
	for _, row := range rows {
		record, err := s.checkedRecord(row)
		if err != nil {
			return nil, err
		}
		all[str(record["id"])] = record
		changes = append(changes, object{"id": record["id"], "time": obj(record["provenance"])["recorded_at"], "kind": "record_written"})
	}
	a := &arguments{command: "search", values: map[string][]string{"mode": {"exact"}, "all": {"true"}, "limit": {fmt.Sprint(len(rows) + 1)}, "scope": {"intersection"}, "rank": {"relevance"}, "cautions": {"0"}}, positionals: []string{query}}
	if query != "" && all[query] == nil {
		a.values["mode"] = []string{"keyword"}
	}
	hits, err := s.search(a)
	if err != nil {
		return nil, err
	}
	items := []object{}
	for _, hit := range hits {
		record := obj(hit["record"])
		if record == nil {
			continue
		}
		items = append(items, object{"id": record["id"], "status": record["status"], "question": obj(record["question"])["text"], "date": record["answered_at"], "text": obj(record["answer"])["verbatim"], "supersedes": record["supersedes"], "superseded_by": record["superseded_by"]})
	}
	chains := []any{}
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if str(all[id]["supersedes"]) != "" {
			continue
		}
		chain := []any{}
		seen := map[string]bool{}
		for current := id; current != "" && !seen[current]; current = str(all[current]["superseded_by"]) {
			seen[current] = true
			chain = append(chain, current)
		}
		if len(chain) > 1 {
			chains = append(chains, chain)
		}
	}
	feedback, err := s.feedback()
	if err != nil {
		return nil, err
	}
	for _, entry := range feedback {
		changes = append(changes, object{"id": entry["case_id"], "time": entry["at"], "kind": entry["event"]})
	}
	result["items"], result["chains"], result["changes"], result["feedback"] = items, chains, changes, feedback
	return result, nil
}
