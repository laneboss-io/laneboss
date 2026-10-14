package decisionsrv

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/protocol"
)

func protocolVersion() (string, error) {
	_, version, err := protocol.Load()
	if err != nil {
		return "", integrity(err.Error())
	}
	return version, nil
}
func validSourceBytes(data []byte, label string) (string, error) {
	if !utf8.Valid(data) {
		return "", invalid(label + " is not UTF-8 text")
	}
	return string(data), nil
}
func eventNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }
func eventTime(event object) string {
	if value := str(event["occurred_at"]); value != "" {
		return value
	}
	return str(event["recorded_at"])
}
func makeLaneSource(config, lane, part, path, text, created, ingested string, identity object) (object, error) {
	h := digest(text)
	id, e := laneRecordID(config, lane, part, h)
	if e != nil {
		return nil, e
	}
	r := object{"id": id, "config": config, "lane": lane, "part": part, "source_path": path, "source_sha256": h, "text": text, "created_utc": created, "ingested_utc": ingested}
	for k, v := range identity {
		r[k] = v
	}
	return r, validateLaneRecord(r)
}
func openEventStore(c *privateConfiguration, readonly bool) (*sql.DB, error) {
	marker, e := c.openState(false)
	if e != nil {
		return nil, e
	}
	recorded := obj(marker["store"])
	path := filepath.Join(c.state, "events.sqlite")
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		if recorded != nil {
			return nil, integrity("the event store recorded by the ownership marker is missing, empty or not a regular file")
		}
		return nil, invalid("configuration has no event store; nothing was ingested")
	}
	if recorded == nil {
		return nil, integrity("event store exists but its ownership marker records no store")
	}
	u := url.URL{Scheme: "file", Path: path}
	query := url.Values{}
	if readonly {
		query.Set("mode", "ro")
	} else {
		query.Set("mode", "rw")
	}
	query.Add("_pragma", "busy_timeout(10000)")
	u.RawQuery = query.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, databaseError(e, readonly)
	}
	db.SetMaxOpenConns(1)
	var version int
	e = db.QueryRow("PRAGMA user_version").Scan(&version)
	if e != nil {
		db.Close()
		return nil, databaseError(e, readonly)
	}
	if version != 1 {
		db.Close()
		return nil, integrity("not an event store of version 1")
	}
	rows, e := readRows(context.Background(), db, "SELECT key,value FROM meta")
	if e != nil {
		db.Close()
		return nil, e
	}
	meta := object{}
	for _, row := range rows {
		meta[str(row["key"])] = row["value"]
	}
	if len(meta) != 4 || meta["format"] != "event-store" || meta["config"] != c.name || meta["store_id"] != recorded["id"] || meta["created_at"] != recorded["created_at"] {
		db.Close()
		return nil, integrity("event store metadata does not match its ownership marker")
	}
	return db, nil
}
func checkedProjection(value string) (object, error) {
	v, e := parseJSON([]byte(value))
	if e != nil {
		return nil, integrity("the lane projection is not readable; run state rebuild")
	}
	p := obj(v)
	if p == nil {
		return nil, integrity("the lane projection is not in this version's form; run state rebuild")
	}
	base := wordsSet("lane state state_at times landing run running runner model effort account worktree branch reason exit_code resumes lost cleaned events last_seq")
	for k := range base {
		if _, ok := p[k]; !ok {
			return nil, integrity("the lane projection is not in this version's form; run state rebuild")
		}
	}
	for k := range p {
		if !base[k] && k != "refusals" && k != "mail" {
			return nil, integrity("the lane projection is not in this version's form; run state rebuild")
		}
	}
	times := obj(p["times"])
	if len(times) != 8 {
		return nil, integrity("invalid lane times projection")
	}
	for _, k := range strings.Fields("planned started ended timeout stuck resumed lost cleaned") {
		if _, ok := times[k]; !ok {
			return nil, integrity("invalid lane times projection")
		}
	}
	if _, ok := p["running"].(bool); !ok {
		return nil, integrity("invalid lane running flag")
	}
	for _, field := range []string{"events", "run"} {
		value, ok := integer(p[field])
		if !ok || value < 0 {
			return nil, integrity("invalid lane count or run number")
		}
	}
	for _, item := range []struct{ field, keys string }{{"refusals", "recorded suspected verdicts unreviewed"}, {"mail", "turn_based idle_seconds last waiting returned in_flight delivered settled"}} {
		value, exists := p[item.field]
		if !exists {
			continue
		}
		table := obj(value)
		keys := wordsSet(item.keys)
		if table == nil || len(table) != len(keys) {
			return nil, integrity("invalid lane optional projection")
		}
		for key := range table {
			if !keys[key] {
				return nil, integrity("invalid lane optional projection")
			}
		}
		if item.field == "mail" {
			if _, ok := table["turn_based"].(bool); !ok {
				return nil, integrity("invalid lane mail flag")
			}
		}
	}
	return p, nil
}

func laneWaiting(directory string) (bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, invalid("cannot read the lane's pending events")
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "pending.jsonl" && !(strings.HasPrefix(name, "pending-") && strings.HasSuffix(name, ".jsonl")) {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, invalid("cannot inspect the lane's pending events")
		}
		if info.Size() > 0 {
			return true, nil
		}
	}
	return false, nil
}
func laneProjection(ctx context.Context, r sqlReader, lane string) (object, error) {
	rows, e := readRows(ctx, r, "SELECT projection FROM lanes WHERE lane = ?", lane)
	if e != nil {
		return nil, e
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return checkedProjection(str(rows[0]["projection"]))
}

var eventHashedFields = strings.Fields("id kind lane actor occurred_at payload protocol_version seq recorded_at")

func checkedEvent(row object) (object, error) {
	payload, e := parseJSON([]byte(str(row["payload"])))
	if e != nil || obj(payload) == nil {
		return nil, integrity("event stored payload is not valid JSON")
	}
	form, e := canonical(payload)
	if e != nil || form != row["payload"] {
		return nil, integrity("event stored payload is not a canonical JSON object")
	}
	event := copyObject(row)
	event["payload"] = payload
	hashable := object{}
	for _, field := range eventHashedFields {
		if _, ok := event[field]; !ok {
			return nil, integrity("event is missing a stored field")
		}
		hashable[field] = event[field]
	}
	h, e := canonicalHash(hashable)
	if e != nil || event["sha256"] != h {
		return nil, integrity("event stored hash does not match its content")
	}
	return event, nil
}
func readLaneEvents(ctx context.Context, db *sql.DB, lane string) ([]object, error) {
	rows, e := readRows(ctx, db, "SELECT * FROM events ORDER BY seq")
	if e != nil {
		return nil, e
	}
	events := []object{}
	for _, row := range rows {
		event, e := checkedEvent(row)
		if e != nil {
			return nil, e
		}
		if event["lane"] == lane && event["kind"] != "lane.ingested" {
			events = append(events, event)
		}
	}
	return events, nil
}
func latestRun(c *privateConfiguration, lane string) (object, error) {
	directory := filepath.Join(c.state, "lanes", lane, "runs")
	if e := refuseLinks(directory); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(directory)
	if os.IsNotExist(e) {
		return nil, invalid("lane has no run record, so it has no readable report; nothing was ingested")
	}
	if e != nil {
		return nil, invalid("cannot list run records")
	}
	var latest object
	largest := int64(-1)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		text, e := readRegular(filepath.Join(directory, entry.Name()), 4<<20)
		if e != nil {
			return nil, e
		}
		v, e := parseJSON([]byte(text))
		if e != nil {
			return nil, integrity("the lane run record is not readable")
		}
		record := obj(v)
		launch := strings.TrimSuffix(entry.Name(), ".json")
		processes, ok := record["processes"].([]any)
		_ = processes
		if record == nil || record["launch"] != launch || !ok {
			return nil, integrity("the lane run record is not a run record")
		}
		run, ok := integer(record["run"])
		if !ok || run < 1 {
			return nil, integrity("the lane run record has an invalid run number")
		}
		if record["config"] != c.name || record["lane"] != lane {
			return nil, integrity("run record belongs to another configuration or lane")
		}
		if run > largest {
			latest = record
			largest = run
		}
	}
	if latest == nil {
		return nil, invalid("lane has no run record, so it has no readable report; nothing was ingested")
	}
	return latest, nil
}
func ingestLane(args options) (object, error) {
	var o *orgContext
	identity := object{}
	var e error
	if args.get("org-dir") != "" || args.get("instance") != "" {
		o, identity, _, _, e = discover("", args.get("org-dir"), args.get("instance"))
		if e != nil {
			return nil, e
		}
		if e = o.checkStore(args.get("db")); e != nil {
			return nil, e
		}
	}
	// The CLI opens and checks the destination before it reads configuration or
	// lane sources. Keep the same order so an older store always names migrate.
	db, e := openStore(args.get("db"), false, 10*time.Second)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	lane := args.get("lane")
	if len(args["attach"]) > 4094 {
		return nil, invalid("a lane ingest has at most 4096 sources")
	}
	if !lanePattern.MatchString(lane) {
		return nil, invalid("lane must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	c, e := loadConfiguration(args.get("config"), false)
	if e != nil {
		return nil, e
	}
	if _, e = c.openState(false); e != nil {
		return nil, e
	}
	lock, e := directoryLock(c.state, true)
	if e != nil {
		return nil, e
	}
	eventStore, e := openEventStore(c, true)
	if e != nil {
		lock.Close()
		return nil, e
	}
	projection, e := laneProjection(context.Background(), eventStore, lane)
	if e != nil {
		eventStore.Close()
		lock.Close()
		return nil, e
	}
	if projection == nil {
		eventStore.Close()
		lock.Close()
		return nil, invalid("lane is not in the event store of its configuration; nothing was ingested")
	}
	count, _ := integer(projection["events"])
	if count == 0 {
		eventStore.Close()
		lock.Close()
		return nil, invalid("lane has no events; nothing was ingested")
	}
	if projection["running"] == true {
		eventStore.Close()
		lock.Close()
		return nil, invalid(fmt.Sprintf("lane %s is running run %v; a running lane's records are not ingested", lane, projection["run"]))
	}
	history, e := readLaneEvents(context.Background(), eventStore, lane)
	eventStore.Close()
	lock.Close()
	if e != nil {
		return nil, e
	}
	latest, e := latestRun(c, lane)
	if e != nil {
		return nil, e
	}
	span := obj(latest["log"])
	start, startOK := integer(span["start"])
	end, endOK := integer(span["end"])
	if !startOK || !endOK {
		return nil, invalid("the log range of the lane's latest run is not a pair of offsets")
	}
	reportPath := filepath.Join(c.state, "lanes", lane, "output.log")
	report, e := readRange(reportPath, start, end)
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(report) == "" {
		return nil, invalid("lane's latest run wrote nothing; an empty report is not ingested")
	}
	info, e := os.Stat(reportPath)
	if e != nil {
		return nil, invalid("cannot read lane report time")
	}
	reportAt := info.ModTime().UTC().Format("2006-01-02T15:04:05.000000+00:00")
	for i := len(history) - 1; i >= 0; i-- {
		event := history[i]
		if event["kind"] == "lane.ended" && equalValue(obj(event["payload"])["run"], latest["run"]) {
			reportAt = eventTime(event)
			break
		}
	}
	ingested := utcNow()
	sources := []object{}
	r, e := makeLaneSource(c.name, lane, "report", reportPath, report, reportAt, ingested, identity)
	if e != nil {
		return nil, e
	}
	sources = append(sources, r)
	var eventText strings.Builder
	for _, event := range history {
		line, e := canonical(event)
		if e != nil {
			return nil, e
		}
		eventText.WriteString(line)
		eventText.WriteByte('\n')
	}
	if eventText.Len() == 0 {
		return nil, invalid("lane has no events; an empty event record is not ingested")
	}
	historyAt := eventTime(history[len(history)-1])
	r, e = makeLaneSource(c.name, lane, "events", filepath.Join(c.state, "events.sqlite"), eventText.String(), historyAt, ingested, identity)
	if e != nil {
		return nil, e
	}
	sources = append(sources, r)
	for _, path := range args["attach"] {
		text, e := readRegular(path, maxTextBytes)
		if e != nil {
			return nil, e
		}
		if strings.TrimSpace(text) == "" {
			return nil, invalid("the attached file is empty or holds no text; it is not ingested")
		}
		info, e := os.Stat(path)
		if e != nil {
			return nil, invalid("cannot read attachment time")
		}
		r, e = makeLaneSource(c.name, lane, "attachment", path, text, info.ModTime().UTC().Format("2006-01-02T15:04:05.000000+00:00"), ingested, identity)
		if e != nil {
			return nil, e
		}
		sources = append(sources, r)
	}
	// Keep the state writer lock until the receipt is recorded. A new run cannot
	// start between the final running check and this batch's decision-store writes.
	lock, e = directoryLock(c.state, false)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	eventStore, e = openEventStore(c, false)
	if e != nil {
		return nil, e
	}
	defer eventStore.Close()
	projection, e = laneProjection(context.Background(), eventStore, lane)
	if e != nil {
		return nil, e
	}
	if projection == nil || projection["running"] == true {
		return nil, invalid("lane started running while its records were read; nothing was ingested")
	}
	laneDirectory := filepath.Join(c.state, "lanes", lane)
	if e = refuseLinks(laneDirectory); e != nil {
		return nil, e
	}
	laneLock, e := directoryLock(laneDirectory, false)
	if e != nil {
		return nil, e
	}
	defer laneLock.Close()
	waiting, e := laneWaiting(laneDirectory)
	if e != nil {
		return nil, e
	}
	if waiting {
		return nil, invalid("lane has events waiting to be recorded; lane check records them first")
	}
	added, existing := 0, 0
	rows := []object{}
	ctx := context.Background()
	e = writeTransaction(ctx, db, func(w sqlWriter) error {
		for _, record := range sources {
			written, e := insertLane(ctx, w, record)
			if e != nil {
				return e
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
			switch event["kind"] {
			case "lane.state":
				reward = str(obj(event["payload"])["state"])
			case "lane.merged":
				reward = "merged"
			case "lane.refusal":
				reward = "refusal"
			}
			if wordsSet("accepted merged abandoned refusal")[reward] {
				reference := fmt.Sprintf("lane:%s/%s:event:%v", c.name, lane, event["seq"])
				for _, record := range sources {
					if _, e = appendFeedback(ctx, w, str(record["id"]), reward, reference, eventTime(event)); e != nil {
						return e
					}
				}
			}
		}
		if o != nil {
			report := sources[0]
			_, e := citations(ctx, w, o, str(report["text"]), "report:"+str(report["source_path"])+":"+str(report["source_sha256"]), str(report["created_utc"]), identity)
			return e
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	receipt := object{"lane": lane, "rows_added": added, "rows_existing": existing, "rows": rows}
	if e = appendIngested(ctx, eventStore, lane, receipt); e != nil {
		return nil, e
	}
	return receipt, nil
}
func appendIngested(ctx context.Context, db *sql.DB, lane string, receipt object) error {
	version, e := protocolVersion()
	if e != nil {
		return e
	}
	if credentialsInValue(receipt) {
		return invalid("ingest receipt contains a credential; no value is repeated")
	}
	payload, e := canonical(receipt)
	if e != nil {
		return e
	}
	if len(payload) > 1<<20 {
		return invalid("ingest receipt exceeds its byte limit")
	}
	id, e := uuidHex()
	if e != nil {
		return e
	}
	return writeTransaction(ctx, db, func(w sqlWriter) error {
		projection, e := laneProjection(ctx, w, lane)
		if e != nil {
			return e
		}
		if projection == nil || projection["running"] == true {
			return invalid("lane started running while its records were read; the event was not recorded")
		}
		var seq int64
		if e = w.QueryRowContext(ctx, "SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name='events'),0),coalesce((SELECT max(seq) FROM events),0))+1").Scan(&seq); e != nil {
			return databaseError(e, false)
		}
		event := object{"seq": seq, "id": "ev-" + id, "kind": "lane.ingested", "lane": lane, "actor": "laneboss", "occurred_at": nil, "payload": receipt, "protocol_version": version, "recorded_at": eventNow()}
		h, e := canonicalHash(event)
		if e != nil {
			return e
		}
		event["sha256"] = h
		event["payload"] = payload
		columns := strings.Fields("seq id kind lane actor occurred_at payload protocol_version recorded_at sha256")
		if _, e = insertMapping(ctx, w, "events", columns, event); e != nil {
			return e
		}
		count, ok := integer(projection["events"])
		if !ok {
			return integrity("invalid lane event count")
		}
		projection["events"] = count + 1
		projection["last_seq"] = seq
		serial, e := canonical(projection)
		if e != nil {
			return e
		}
		_, e = w.ExecContext(ctx, "UPDATE lanes SET projection = ? WHERE lane = ?", serial, lane)
		return databaseError(e, false)
	})
}

// LaneEnd is the best-effort launcher seam, with an observable failure receipt.
func LaneEnd(configuration, lane, orgDir, instance, db, directory string) object {
	o, identity, _, _, e := discover(directory, orgDir, instance)
	if e != nil {
		return object{"ok": false, "lane": lane, "ingest_error": "InvalidInput"}
	}
	if db == "" {
		db = o.db
	}
	if e = o.checkStore(db); e != nil {
		return object{"ok": false, "lane": lane, "ingest_error": "InvalidInput"}
	}
	receipt, e := ingestLane(options{"config": {configuration}, "lane": {lane}, "org-dir": {o.root}, "instance": {str(identity["instance"])}, "db": {db}})
	if e != nil {
		kind := "InvalidInput"
		if errorCode(e) == 3 {
			kind = "IntegrityError"
		}
		receipt = object{"ok": false, "lane": lane, "ingest_error": kind}
	} else {
		receipt["ok"] = true
	}
	return receipt
}
