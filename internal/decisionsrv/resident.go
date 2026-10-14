package decisionsrv

import (
	"bytes"
	"container/list"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

type cacheItem struct {
	key   string
	value any
	size  int
}

const answerEntries = 128
const answerBytes = 16 << 20
const queryCacheEntries = 512

func newAnswerCache() *lruCache { return newCache(answerEntries, answerBytes) }

type lruCache struct {
	items                map[string]*list.Element
	order                *list.List
	bytes                int
	maxEntries, maxBytes int
}

func newCache(entries, bytes int) *lruCache {
	return &lruCache{items: map[string]*list.Element{}, order: list.New(), maxEntries: entries, maxBytes: bytes}
}
func (c *lruCache) get(key string) (any, bool) {
	e, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.order.MoveToBack(e)
	return e.Value.(cacheItem).value, true
}
func (c *lruCache) put(key string, v any, size int) {
	if e, ok := c.items[key]; ok {
		c.bytes -= e.Value.(cacheItem).size
		c.order.Remove(e)
	}
	e := c.order.PushBack(cacheItem{key, v, size})
	c.items[key] = e
	c.bytes += size
	for len(c.items) > c.maxEntries || (c.maxBytes > 0 && c.bytes > c.maxBytes) {
		e := c.order.Front()
		x := e.Value.(cacheItem)
		delete(c.items, x.key)
		c.bytes -= x.size
		c.order.Remove(e)
	}
}

type storedCase struct {
	row, record object
	answered    time.Time
}
type vectorEntry struct {
	id, side string
	vector   []float64
	norm     float64
}
type vectorTable struct {
	entries []vectorEntry
	err     error
}
type snapshot struct {
	db                 *sql.DB
	records, lanes     []storedCase
	byID               map[string]object
	damage, laneDamage error
	fingerprint        string
	mu                 sync.Mutex
	refs               int
	retired            bool
	answers            *lruCache
	tables             map[string]*vectorTable
}

func (s *snapshot) release() {
	s.mu.Lock()
	s.refs--
	close := s.retired && s.refs == 0
	s.mu.Unlock()
	if close {
		s.db.Close()
	}
}
func (s *snapshot) retire() {
	s.mu.Lock()
	s.retired = true
	close := s.refs == 0
	s.mu.Unlock()
	if close {
		s.db.Close()
	}
}
func (s *snapshot) table(p *embeddingProvider) *vectorTable {
	key := p.identity()
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.tables[key]; t != nil {
		return t
	}
	t := &vectorTable{}
	s.tables[key] = t
	rows, e := readRows(context.Background(), s.db, "SELECT * FROM models WHERE model = ?", p.model)
	if e != nil {
		t.err = e
		return t
	}
	if len(rows) > 0 {
		if e = checkedModel(rows[0]); e != nil {
			t.err = e
			return t
		}
	}
	if len(rows) == 0 || !equalValue(rows[0]["dimension"], p.dimension) || rows[0]["provider"] != p.name {
		t.err = invalid("model has no compatible embeddings; run embed with this config first")
		return t
	}
	rows, e = readRows(context.Background(), s.db, "SELECT * FROM vectors WHERE model = ?", p.model)
	if e != nil {
		t.err = e
		return t
	}
	for _, row := range rows {
		v, e := checkedVector(row, p.dimension)
		if e != nil {
			t.err = e
			t.entries = nil
			return t
		}
		current := s.byID[str(row["record_id"])]
		if current == nil {
			continue
		}
		hashCol := "q_sha256"
		if row["which_text"] == "d_text" {
			hashCol = "d_sha256"
		}
		if row["text_sha256"] != current[hashCol] {
			continue
		}
		t.entries = append(t.entries, vectorEntry{str(row["record_id"]), str(row["which_text"]), v, vectorNorm(v)})
	}
	return t
}

var fingerprintQueries = []string{
	"PRAGMA user_version",
	"SELECT count(*),group_concat(row_id || ':' || id || ':' || record_sha256 || ':' || q_sha256 || ':' || d_sha256, ';') FROM records",
	"SELECT count(*),group_concat(model || ':' || provider || ':' || dimension || ':' || entry_sha256, ';') FROM models",
	"SELECT count(*),group_concat(record_id || ':' || which_text || ':' || model || ':' || text_sha256 || ':' || vector_sha256 || ':' || entry_sha256, ';') FROM vectors",
	"SELECT count(*),group_concat(id || ':' || source_sha256 || ':' || created_utc || ':' || coalesce(level,'') || ':' || coalesce(instance,''), ';') FROM lane_records",
	"SELECT count(*),group_concat(id || ':' || entry_sha256, ';') FROM feedback",
	// Also notice direct tampering with payloads that leaves their claimed hashes intact.
	"SELECT id,record_json,q_text,d_text,hex(verbatim) FROM records ORDER BY id",
	"SELECT id,text,source_path FROM lane_records ORDER BY id",
	"SELECT record_id,which_text,model,hex(vector) FROM vectors ORDER BY record_id,which_text,model",
	"SELECT case_id,event,at,source FROM feedback ORDER BY id",
	"SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name,type",
}

func fingerprint(ctx context.Context, r sqlReader) (string, error) {
	values := []any{}
	for _, q := range fingerprintQueries {
		rows, e := readRows(ctx, r, q)
		if e != nil {
			return "", e
		}
		values = append(values, rows)
	}
	return canonicalHash(values)
}

func copySnapshot(ctx context.Context, source *sql.Conn, hash string) (*snapshot, error) {
	var data []byte
	e := source.Raw(func(raw any) error {
		s, ok := raw.(interface{ Serialize() ([]byte, error) })
		if !ok {
			return integrity("SQLite snapshot serialization unavailable")
		}
		var e error
		data, e = s.Serialize()
		return e
	})
	if e != nil {
		return nil, databaseError(e, true)
	}
	if len(data) < 100 || !bytes.Equal(data[:16], []byte("SQLite format 3\x00")) {
		return nil, integrity("SQLite snapshot has an invalid header")
	}
	// A serialized WAL database includes its committed pages but retains WAL
	// journal flags. The private memory copy has no WAL file. Only its copy of
	// these header bytes is changed; the source file and its journal are untouched.
	if data[18] == 2 || data[19] == 2 {
		data[18], data[19] = 1, 1
	}
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		return nil, databaseError(e, true)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, e := db.Conn(ctx)
	if e != nil {
		db.Close()
		return nil, databaseError(e, true)
	}
	e = conn.Raw(func(raw any) error {
		d, ok := raw.(interface{ Deserialize([]byte) error })
		if !ok {
			return integrity("SQLite snapshot deserialization unavailable")
		}
		return d.Deserialize(data)
	})
	conn.Close()
	if e != nil {
		db.Close()
		return nil, databaseError(e, true)
	}
	s := &snapshot{db: db, byID: map[string]object{}, fingerprint: hash, answers: newAnswerCache(), tables: map[string]*vectorTable{}}
	var version int
	if e = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
		db.Close()
		return nil, databaseError(e, true)
	}
	if version != schemaVersion {
		db.Close()
		return nil, unsupportedVersion(version)
	}
	rows, e := readRows(ctx, db, "SELECT * FROM records ORDER BY id")
	if e != nil {
		db.Close()
		return nil, e
	}
	for _, row := range rows {
		r, e := checkedRecord(row)
		if e != nil {
			if s.damage == nil {
				s.damage = e
			}
			continue
		}
		t, e := timestamp(r["answered_at"], "answered_at")
		if e != nil {
			db.Close()
			return nil, e
		}
		s.records = append(s.records, storedCase{row, r, t})
		s.byID[str(row["id"])] = row
	}
	rows, e = readRows(ctx, db, "SELECT * FROM lane_records ORDER BY id")
	if e != nil {
		db.Close()
		return nil, e
	}
	for _, row := range rows {
		r, e := checkedLane(row)
		if e != nil {
			if s.laneDamage == nil {
				s.laneDamage = e
			}
			continue
		}
		t, e := timestamp(r["created_utc"], "created_utc")
		if e != nil {
			db.Close()
			return nil, e
		}
		s.lanes = append(s.lanes, storedCase{row, r, t})
	}
	return s, nil
}

type resident struct {
	path, config                           string
	refresh                                sync.Mutex
	monitor                                *sql.DB
	identity                               os.FileInfo
	stamp                                  string
	snapshot                               *snapshot
	builds                                 int
	cacheMu                                sync.Mutex
	cache                                  *lruCache
	flights                                map[string]*sync.Mutex
	hits, misses, answerHits, answerMisses int
}

func newResident(path, config string) (*resident, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, invalid("unreadable database path")
	}
	if config != "" {
		config, e = filepath.Abs(config)
		if e != nil {
			return nil, invalid("unreadable config path")
		}
	}
	return &resident{path: abs, config: config, cache: newCache(queryCacheEntries, 0), flights: map[string]*sync.Mutex{}}, nil
}
func (r *resident) current(ctx context.Context) (*snapshot, error) {
	r.refresh.Lock()
	defer r.refresh.Unlock()
	info, e := os.Stat(r.path)
	if e != nil || !info.Mode().IsRegular() {
		if e != nil && os.IsPermission(e) {
			return nil, databaseError(e, true)
		}
		return nil, invalid("database does not exist; run init first")
	}
	if r.monitor == nil || r.identity == nil || !os.SameFile(info, r.identity) {
		if r.monitor != nil {
			r.monitor.Close()
			r.monitor = nil
		}
		r.monitor, e = openStore(r.path, true, 10*time.Second)
		if e != nil {
			return nil, e
		}
		r.identity = info
		r.stamp = ""
	}
	var version int64
	if e = r.monitor.QueryRowContext(ctx, "PRAGMA data_version").Scan(&version); e != nil {
		return nil, databaseError(e, true)
	}
	stamp := fmt.Sprintf("%d:%d:%d", info.Size(), info.ModTime().UnixNano(), version)
	if r.snapshot != nil && r.stamp == stamp {
		r.snapshot.mu.Lock()
		r.snapshot.refs++
		r.snapshot.mu.Unlock()
		return r.snapshot, nil
	}
	conn, e := r.monitor.Conn(ctx)
	if e != nil {
		return nil, databaseError(e, true)
	}
	defer conn.Close()
	if _, e = conn.ExecContext(ctx, "BEGIN"); e != nil {
		return nil, databaseError(e, true)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	hash, e := fingerprint(ctx, conn)
	if e != nil {
		return nil, e
	}
	if r.snapshot != nil && r.snapshot.fingerprint == hash {
		r.stamp = stamp
		r.snapshot.mu.Lock()
		r.snapshot.refs++
		r.snapshot.mu.Unlock()
		return r.snapshot, nil
	}
	s, e := copySnapshot(ctx, conn, hash)
	if e != nil {
		return nil, e
	}
	if r.snapshot != nil {
		r.snapshot.retire()
	}
	r.snapshot = s
	r.stamp = stamp
	r.builds++
	s.refs++
	// Warm the configured model before it is first searched. Invalid provider settings
	// are deferred to the search that actually asks for vectors.
	if p, e := providerFromConfig(r.config); e == nil {
		s.table(p)
	}
	return s, nil
}
func (r *resident) answer(ctx context.Context, a searchArguments) ([]byte, error) {
	s, e := r.current(ctx)
	if e != nil {
		return nil, e
	}
	defer s.release()
	var p *embeddingProvider
	if a.mode == "vector" || a.mode == "hybrid" {
		if a.scope == "own-or-level" && (a.level == 0 || !a.instanceSet) {
			return nil, invalid("own-or-level scope requires both level and instance")
		}
		if a.rank != "time" && (a.now != "" || len(a.halfLife) != 0) {
			return nil, invalid("now and half-life require --rank time")
		}
		if _, _, e = filteredCases(s, a); e != nil {
			return nil, e
		}
		if strings.ContainsRune(a.query, 0) || !utf8.ValidString(a.query) {
			return nil, invalid("query must be text without NUL")
		}
		p, e = providerFromConfig(r.config)
		if e != nil {
			return nil, e
		}
	}
	key := ""
	if a.rank != "time" || a.now != "" {
		m := a.key()
		if p != nil {
			m["provider"] = p.identity()
		}
		key, e = canonical(m)
		if e != nil {
			return nil, e
		}
		s.mu.Lock()
		cached, ok := s.answers.get(key)
		s.mu.Unlock()
		if ok {
			r.cacheMu.Lock()
			r.answerHits++
			r.cacheMu.Unlock()
			return cached.([]byte), nil
		}
	}
	hits, e := searchSnapshot(ctx, s, r, a, p)
	if e != nil {
		return nil, e
	}
	body, e := jsonout.Line(hits)
	if e != nil {
		return nil, invalid(e.Error())
	}
	r.cacheMu.Lock()
	r.answerMisses++
	r.cacheMu.Unlock()
	if key != "" {
		s.mu.Lock()
		s.answers.put(key, body, len(body))
		s.mu.Unlock()
	}
	return body, nil
}
func (r *resident) queryVector(p *embeddingProvider, query string) ([]float64, error) {
	key := p.identity() + ":" + digest(query)
	r.cacheMu.Lock()
	v, ok := r.cache.get(key)
	if ok {
		r.hits++
		r.cacheMu.Unlock()
		return v.([]float64), nil
	}
	flight := r.flights[key]
	if flight == nil {
		flight = &sync.Mutex{}
		r.flights[key] = flight
	}
	r.cacheMu.Unlock()
	flight.Lock()
	defer flight.Unlock()
	defer func() {
		r.cacheMu.Lock()
		if r.flights[key] == flight {
			delete(r.flights, key)
		}
		r.cacheMu.Unlock()
	}()
	r.cacheMu.Lock()
	if v, ok = r.cache.get(key); ok {
		r.hits++
		r.cacheMu.Unlock()
		return v.([]float64), nil
	}
	r.misses++
	r.cacheMu.Unlock()
	if e := p.checkQuery(query); e != nil {
		return nil, e
	}
	if e := logQuery(r.path, p, query); e != nil {
		return nil, e
	}
	vector, e := p.embed(query)
	if e != nil {
		return nil, e
	}
	r.cacheMu.Lock()
	r.cache.put(key, vector, len(vector)*8)
	delete(r.flights, key)
	r.cacheMu.Unlock()
	return vector, nil
}
func (r *resident) status() object {
	r.refresh.Lock()
	defer r.refresh.Unlock()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	records, models, answers := 0, 0, 0
	if s := r.snapshot; s != nil {
		s.mu.Lock()
		records = len(s.records)
		answers = len(s.answers.items)
		for _, t := range s.tables {
			if t.err == nil {
				models++
			}
		}
		s.mu.Unlock()
	}
	path, e := filepath.EvalSymlinks(r.path)
	if e != nil {
		path = r.path
	}
	return object{"pid": os.Getpid(), "builds": r.builds, "cache": object{"entries": len(r.cache.items), "hits": r.hits, "misses": r.misses}, "answers": object{"entries": answers, "hits": r.answerHits, "misses": r.answerMisses}, "store_id": digest(path), "schema_version": schemaVersion, "records": records, "vector_models": models, "provider_reads": providerReads.Load()}
}
func (r *resident) close() {
	r.refresh.Lock()
	defer r.refresh.Unlock()
	if r.monitor != nil {
		r.monitor.Close()
		r.monitor = nil
	}
	if r.snapshot != nil {
		r.snapshot.retire()
		r.snapshot = nil
	}
}
