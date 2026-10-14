package lane

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

type historyOrg struct {
	home, db, instance string
	level              int
}

func historyTOML(root *os.Root, path string) (object, error) {
	b, err := rootRead(root, path, 65536)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(b) {
		return nil, refuse("org history metadata must be UTF-8")
	}
	var value object
	if _, err = toml.Decode(string(b), &value); err != nil {
		return nil, refuse("org history metadata has invalid TOML")
	}
	return value, nil
}
func historyLocation(directory string) (*historyOrg, error) {
	bound := os.Getenv("LANEBOSS_ORG")
	if bound == "" {
		return nil, refuse("org-dir or LANEBOSS_ORG is required")
	}
	home := realPath(bound)
	if filepath.Base(home) != ".laneboss" {
		home = filepath.Join(home, ".laneboss")
	}
	root, err := rootDirectory(home)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := historyTOML(root, "org.toml")
	if err != nil {
		return nil, err
	}
	settings := obj(data["history"])
	if data["history"] != nil && settings == nil {
		return nil, refuse("org history settings must be a table")
	}
	settings = clone(settings)
	service := filepath.Join(home, "shared", "services", "history.toml")
	resolved := realPath(service)
	if !inside(resolved, home) {
		return nil, refuse("history service configuration leaves its org")
	}
	if info, err := os.Stat(resolved); err == nil && info.Mode().IsRegular() {
		relative, err := filepath.Rel(home, resolved)
		if err != nil {
			return nil, err
		}
		overlay, err := historyTOML(root, relative)
		if err != nil {
			return nil, err
		}
		for key, value := range overlay {
			settings[key] = value
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	path, ok := valueOr(settings, "db", "shared/services/decisions.sqlite").(string)
	if !ok || path == "" || strings.ContainsRune(path, 0) {
		return nil, refuse("history db path must be nonempty text")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(home, path)
	}
	path = realPath(path)
	if !inside(path, home) {
		return nil, refuse("history database leaves its org")
	}
	selected := os.Getenv("LANEBOSS_INSTANCE")
	instances := filepath.Join(home, "instances")
	if strings.Contains(selected, "/") || strings.HasSuffix(selected, ".toml") {
		candidate := realPath(expandHome(selected))
		if !inside(candidate, instances) {
			return nil, refuse("instance path leaves the trusted org's instance tree")
		}
		if filepath.Base(candidate) == "instance.toml" {
			candidate = filepath.Dir(candidate)
		}
		selected = filepath.Base(candidate)
	}
	if selected == "" {
		start := realPath(directory)
		if !inside(start, instances) {
			return nil, refuse("no trusted org instance could be found")
		}
		for current := start; ; current = filepath.Dir(current) {
			if filepath.Dir(current) == instances {
				selected = filepath.Base(current)
				break
			}
			if filepath.Dir(current) == current {
				break
			}
		}
	}
	if !match(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, selected) {
		return nil, refuse("instance label is invalid")
	}
	instancePath := realPath(filepath.Join(instances, selected))
	if !inside(instancePath, instances) {
		return nil, refuse("instance metadata leaves the trusted instance tree")
	}
	relative, err := filepath.Rel(home, filepath.Join(instancePath, "instance.toml"))
	if err != nil {
		return nil, err
	}
	instance, err := historyTOML(root, relative)
	if err != nil {
		return nil, err
	}
	metadata := obj(instance["instance"])
	if instance["instance"] == nil {
		metadata = instance
	}
	if metadata == nil || !whole(metadata["level"], 3, 6) || str(valueOr(metadata, "name", selected)) != selected {
		return nil, refuse("instance metadata has an invalid level or mismatched name")
	}
	return &historyOrg{home: home, db: path, instance: selected, level: integer(metadata["level"])}, nil
}
func checkHistorySchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 4 {
		return integrity("the decision store is not version 4; nothing is upgraded automatically")
	}
	expected := map[string]historySchemaObject{}
	for _, entry := range historySchema {
		expected[entry.kind+"/"+entry.name] = entry
	}
	rows, err := db.Query("SELECT type,name,tbl_name,sql FROM sqlite_master")
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var kindValue, nameValue, tableValue, statementValue any
		if err = rows.Scan(&kindValue, &nameValue, &tableValue, &statementValue); err != nil {
			return err
		}
		kind, ok1 := kindValue.(string)
		name, ok2 := nameValue.(string)
		table, ok3 := tableValue.(string)
		if !ok1 || !ok2 || !ok3 {
			return integrity("decision-store schema has a non-text field")
		}
		key := kind + "/" + name
		want, ok := expected[key]
		if !ok || seen[key] || table != want.table {
			return integrity("decision-store schema definition mismatch")
		}
		if want.nullSQL {
			if statementValue != nil {
				return integrity("decision-store autoindex definition mismatch")
			}
		} else {
			statement, ok := statementValue.(string)
			if !ok || statement != want.statement {
				return integrity("decision-store schema definition mismatch")
			}
		}
		seen[key] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return integrity("decision-store schema objects are missing")
	}
	return nil
}

var historyColumns = strings.Fields("id config lane part source_path source_sha256 text created_utc ingested_utc level instance")

func historyRecord(row scanner) (object, error) {
	values := make([]any, len(historyColumns))
	targets := make([]any, len(values))
	for i := range values {
		targets[i] = &values[i]
	}
	if err := row.Scan(targets...); err != nil {
		return nil, err
	}
	record := object{}
	for i, key := range historyColumns {
		record[key] = values[i]
	}
	if err := validateHistoryRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}
func validateHistoryRecord(record object) error {
	for _, key := range historyColumns[:9] {
		text, ok := record[key].(string)
		if !ok || strings.TrimSpace(text) == "" || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return integrity("a stored lane record has invalid text metadata")
		}
	}
	if !match(`[a-z0-9][a-z0-9-]{0,31}`, str(record["config"])) || !match(`[a-z0-9][a-z0-9._-]{0,63}`, str(record["lane"])) || !contains([]string{"report", "events", "attachment"}, str(record["part"])) {
		return integrity("a lane record's identity is invalid")
	}
	hash := str(record["source_sha256"])
	if !match(`[0-9a-f]{64}`, hash) || digest([]byte(str(record["text"]))) != hash || str(record["id"]) != str(record["config"])+"/"+str(record["lane"])+"/"+str(record["part"])+"/"+hash[:16] {
		return integrity("a lane record's text, source hash and identifier do not agree")
	}
	if !validTimestamp(record["created_utc"]) || !validTimestamp(record["ingested_utc"]) {
		return integrity("a lane record has an invalid timestamp")
	}
	if record["level"] == nil && record["instance"] == nil {
		return nil
	}
	if !whole(record["level"], 3, 6) || !match(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, str(record["instance"])) {
		return integrity("a lane record has invalid scope")
	}
	return nil
}
func historySource(config, lane, part, path string, data []byte, created, at string, org *historyOrg) (object, error) {
	if !utf8.Valid(data) || len(data) > 8*1024*1024 || strings.TrimSpace(string(data)) == "" {
		return nil, refuse("the lane's history source is empty, too large or not UTF-8")
	}
	hash := digest(data)
	record := object{"id": config + "/" + lane + "/" + part + "/" + hash[:16], "config": config, "lane": lane, "part": part, "source_path": path, "source_sha256": hash, "text": string(data), "created_utc": created, "ingested_utc": at, "level": org.level, "instance": org.instance}
	if err := validateHistoryRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}
func (s *session) historySources(lane string, org *historyOrg) ([]object, []object, error) {
	if err := s.refresh(); err != nil {
		return nil, nil, err
	}
	row, err := s.known(lane)
	if err != nil {
		return nil, nil, err
	}
	if flag(row["running"]) {
		return nil, nil, refuse("a running lane's records are not ingested")
	}
	events, err := s.laneEvents(lane)
	if err != nil {
		return nil, nil, err
	}
	history := []object{}
	for _, event := range events {
		if str(event["kind"]) != "lane.ingested" {
			history = append(history, event)
		}
	}
	records, err := s.everyRecord(lane)
	if err != nil {
		return nil, nil, err
	}
	var latest object
	for _, record := range records {
		if latest == nil || integer(record["run"]) > integer(latest["run"]) {
			latest = record
		}
	}
	if latest == nil {
		return nil, nil, refuse("the lane has no run record, so no report is ingested")
	}
	span := obj(latest["log"])
	if !whole(span["start"], 0, 1<<62) || !whole(span["end"], 0, 1<<62) || number(span["end"]) < number(span["start"]) || number(span["end"])-number(span["start"]) > 8*1024*1024 {
		return nil, nil, refuse("the report's recorded log range is invalid or exceeds its byte limit")
	}
	root, err := s.laneRoot(lane, false)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	log, err := childOpen(root, "output.log", os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	defer log.Close()
	info, err := log.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, refuse("the lane report is not a regular file")
	}
	start, length := int64(number(span["start"])), int64(number(span["end"])-number(span["start"]))
	data := make([]byte, length)
	n, err := log.ReadAt(data, start)
	if err != nil && err != io.EOF {
		return nil, nil, err
	}
	if int64(n) != length {
		return nil, nil, refuse("the lane's report has fewer bytes than its run recorded")
	}
	created := info.ModTime().UTC().Format("2006-01-02T15:04:05.000000-07:00")
	for i := len(history) - 1; i >= 0; i-- {
		event := history[i]
		if str(event["kind"]) == "lane.ended" && integer(obj(event["payload"])["run"]) == integer(latest["run"]) {
			created = str(valueOr(event, "occurred_at", nil))
			if created == "" {
				created = str(event["recorded_at"])
			}
			break
		}
	}
	at := time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")
	report, err := historySource(s.c.name, lane, "report", s.lanePath(lane, "output.log"), data, created, at, org)
	if err != nil {
		return nil, nil, err
	}
	var output bytes.Buffer
	for _, event := range history {
		output.Write(canonical(event))
		output.WriteByte('\n')
	}
	if len(history) == 0 {
		return nil, nil, refuse("the lane has no events to ingest")
	}
	last := history[len(history)-1]
	created = str(last["occurred_at"])
	if created == "" {
		created = str(last["recorded_at"])
	}
	eventSource, err := historySource(s.c.name, lane, "events", filepath.Join(s.c.state, "events.sqlite"), output.Bytes(), created, at, org)
	if err != nil {
		return nil, nil, err
	}
	return []object{report, eventSource}, history, nil
}
func insertHistoryRecord(db *sql.DB, record object) (bool, error) {
	columns := strings.Join(historyColumns, ",")
	old, err := historyRecord(db.QueryRow("SELECT "+columns+" FROM lane_records WHERE id=?", record["id"]))
	if err == nil {
		if str(old["source_sha256"]) != str(record["source_sha256"]) {
			return false, integrity("a lane record id already exists with a different source hash")
		}
		if integer(old["level"]) != integer(record["level"]) || old["instance"] != record["instance"] {
			return false, refuse("a lane record's scope cannot be changed by re-ingest")
		}
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	values := make([]any, len(historyColumns))
	placeholders := make([]string, len(values))
	for i, key := range historyColumns {
		values[i] = record[key]
		placeholders[i] = "?"
	}
	result, err := db.Exec("INSERT INTO lane_records ("+columns+") VALUES ("+strings.Join(placeholders, ",")+")", values...)
	if err != nil {
		return false, err
	}
	rowID, err := result.LastInsertId()
	if err != nil {
		return false, err
	}
	if _, err = db.Exec("INSERT INTO lane_keyword_index(rowid,id,text) VALUES (?,?,?)", rowID, record["id"], record["text"]); err != nil {
		return false, err
	}
	return true, nil
}
func appendHistoryFeedback(db *sql.DB, id, event, source, at string) error {
	if !contains(strings.Fields("accepted merged abandoned refusal cited"), event) || strings.TrimSpace(source) == "" || strings.ContainsRune(source, 0) || !validTimestamp(at) {
		return refuse("history feedback metadata is invalid")
	}
	var count int
	if err := db.QueryRow("SELECT (SELECT count(*) FROM records WHERE id=?)+(SELECT count(*) FROM lane_records WHERE id=?)", id, id).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return refuse("history feedback case does not exist")
	}
	var caseValue, eventValue, timeValue, sourceValue, hashValue any
	err := db.QueryRow("SELECT case_id,event,at,source,entry_sha256 FROM feedback WHERE case_id=? AND event=? AND source=?", id, event, source).Scan(&caseValue, &eventValue, &timeValue, &sourceValue, &hashValue)
	if err == nil {
		for _, value := range []any{caseValue, eventValue, timeValue, sourceValue, hashValue} {
			if _, ok := value.(string); !ok {
				return integrity("stored feedback has a non-text field")
			}
		}
		entry := object{"case_id": caseValue, "event": eventValue, "at": timeValue, "source": sourceValue}
		if digest(canonical(entry)) != str(hashValue) || !validTimestamp(timeValue) {
			return integrity("stored feedback has an invalid hash or time")
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	entry := object{"case_id": id, "event": event, "at": at, "source": source}
	_, err = db.Exec("INSERT INTO feedback(case_id,event,at,source,entry_sha256) VALUES (?,?,?,?,?)", id, event, at, source, digest(canonical(entry)))
	return err
}
func historyCitation(text, id string) bool {
	for offset := 0; offset <= len(text); {
		relative := strings.Index(text[offset:], id)
		if relative < 0 {
			return false
		}
		start := offset + relative
		end := start + len(id)
		blocked := func(r rune) bool {
			return unicode.IsLetter(r) || unicode.IsNumber(r) || strings.ContainsRune("_./:-", r)
		}
		left, right := false, false
		if start > 0 {
			r, _ := utf8.DecodeLastRuneInString(text[:start])
			left = blocked(r)
		}
		if end < len(text) {
			r, _ := utf8.DecodeRuneInString(text[end:])
			right = blocked(r)
		}
		if !left && !right {
			return true
		}
		offset = end
	}
	return false
}
func citeHistory(db *sql.DB, org *historyOrg, report object) error {
	root, err := rootDirectory(org.home)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := rootChild(root, "shared/state/history", false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := childOpen(directory, "injections.jsonl", os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return refuse("history injection log is not a regular file")
	}
	start := info.Size() - 8*1024*1024
	if start < 0 {
		start = 0
	}
	data := make([]byte, info.Size()-start)
	if _, err = file.ReadAt(data, start); err != nil && err != io.EOF {
		return err
	}
	lines := strings.Split(string(data), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	created, _ := time.Parse(time.RFC3339Nano, str(report["created_utc"]))
	cited := map[string]bool{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		value, err := parseJSON([]byte(line))
		if err != nil {
			return err
		}
		receipt := obj(value)
		if str(receipt["instance"]) != org.instance {
			continue
		}
		if !validTimestamp(receipt["at"]) {
			return refuse("history injection time is invalid")
		}
		at, _ := time.Parse(time.RFC3339Nano, str(receipt["at"]))
		if at.After(created) {
			continue
		}
		for _, id := range stringsOf(receipt["ids"]) {
			if cited[id] || id == "" || !historyCitation(str(report["text"]), id) {
				continue
			}
			source := "report:" + str(report["source_path"]) + ":" + str(report["source_sha256"])
			if err = appendHistoryFeedback(db, id, "cited", source, str(report["created_utc"])); err != nil {
				return err
			}
			cited[id] = true
		}
	}
	return nil
}
func (s *session) ingestHistory(lane, directory string) (object, error) {
	org, err := historyLocation(directory)
	if err != nil {
		return nil, err
	}
	sources, history, err := s.historySources(lane, org)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(org.db)
	if err != nil || !info.Mode().IsRegular() {
		return nil, refuse("the org decision store does not exist as a regular file; initialize it first")
	}
	u := url.URL{Scheme: "file", Path: org.db}
	q := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(10000)", "foreign_keys(1)"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		return nil, err
	}
	if _, err = db.Exec("BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			db.Exec("ROLLBACK")
		}
	}()
	if err = checkHistorySchema(db); err != nil {
		return nil, err
	}
	rows := []any{}
	added, existing := 0, 0
	for _, record := range sources {
		written, err := insertHistoryRecord(db, record)
		if err != nil {
			return nil, err
		}
		if written {
			added++
		} else {
			existing++
		}
		rows = append(rows, object{"id": record["id"], "sha256": record["source_sha256"]})
	}
	for _, event := range history {
		reward := ""
		switch str(event["kind"]) {
		case "lane.state":
			reward = str(obj(event["payload"])["state"])
		case "lane.merged":
			reward = "merged"
		case "lane.refusal":
			reward = "refusal"
		}
		if !contains(strings.Fields("accepted merged abandoned refusal"), reward) {
			continue
		}
		source := fmt.Sprintf("lane:%s/%s:event:%d", s.c.name, lane, integer(event["seq"]))
		at := str(event["occurred_at"])
		if at == "" {
			at = str(event["recorded_at"])
		}
		for _, record := range sources {
			if err = appendHistoryFeedback(db, str(record["id"]), reward, source, at); err != nil {
				return nil, err
			}
		}
	}
	if err = citeHistory(db, org, sources[0]); err != nil {
		return nil, err
	}
	if _, err = db.Exec("COMMIT"); err != nil {
		return nil, err
	}
	committed = true
	receipt := object{"lane": lane, "rows_added": added, "rows_existing": existing, "rows": rows}
	event := envelope(lane, "lane.ingested", receipt, "laneboss")
	event["occurred_at"] = nil
	if _, err = s.append(event, 10); err != nil {
		return nil, err
	}
	return receipt, nil
}
func (r *supervisedRun) historyReceipt() object {
	receipt, err := r.s.ingestHistory(r.lane, str(r.spec["cwd"]))
	if err == nil {
		result := clone(receipt)
		result["ok"] = true
		return result
	}
	kind := "HistoryError"
	if problem, ok := err.(*problem); ok {
		kind = "InvalidInput"
		if problem.code == 3 {
			kind = "IntegrityError"
		}
	}
	return object{"ok": false, "lane": r.lane, "ingest_error": kind}
}
