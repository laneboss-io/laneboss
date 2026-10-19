// Package store is the service-owned SQLite writer. Clients never import it.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type Dependencies struct {
	JudgeMaxCostMicros   int64
	JudgeCost            func(api.JudgeConfig, int64, int64) (int64, error)
	CredentialProjection CredentialProjectionSource
	ArchiveLimits        ArchiveLimits
	ArchiveNative        archivejob.Native
	CleanupNative        CleanupNative
	Enrollment           *api.AdminEnrollmentEndpoint
	Config               string
	Directory            string
	Clock                api.Clock
}

type Service struct {
	reviewNative      reviewNative
	reviewExecutor    reviewExecutor
	deps              Dependencies
	db                *sql.DB
	root              *os.Root
	lock              *os.File
	mu                sync.RWMutex
	orgMu             sync.Mutex
	closed            bool
	closeErr          error
	key               []byte
	storeID           api.ID
	views             map[*readView]struct{}
	changed           chan struct{}
	dbInfo            os.FileInfo
	reservationOwners map[api.ID]*reservationOwner
	archiveFreezes    map[api.ID]bool
}

var _ api.Store = (*Service)(nil)

const ddl = `
CREATE TABLE meta (name TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE events (
 seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
 data BLOB NOT NULL, input BLOB NOT NULL,
 sha256 TEXT NOT NULL, chain TEXT NOT NULL
);
CREATE TABLE receipts (
 principal TEXT NOT NULL, method TEXT NOT NULL, key TEXT NOT NULL,
 digest TEXT NOT NULL, request BLOB NOT NULL, operation BLOB NOT NULL,
 PRIMARY KEY(principal, method, key)
);
CREATE TABLE operations (
 id TEXT PRIMARY KEY, principal TEXT NOT NULL, data BLOB NOT NULL
);
CREATE TABLE projections (
 kind TEXT NOT NULL, id TEXT NOT NULL, generation INTEGER NOT NULL,
 data BLOB NOT NULL, PRIMARY KEY(kind,id)
);
CREATE TABLE effects (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
 operation_id TEXT NOT NULL, data BLOB NOT NULL
);
CREATE TABLE reservations (
 principal TEXT NOT NULL, method TEXT NOT NULL, key TEXT NOT NULL,
 digest TEXT NOT NULL, request BLOB NOT NULL, operation_id TEXT NOT NULL,
 deadline TEXT NOT NULL, recorded TEXT NOT NULL,
 PRIMARY KEY(principal,method,key)
);
CREATE TABLE replies (
 principal TEXT NOT NULL, method TEXT NOT NULL, key TEXT NOT NULL,
 data BLOB NOT NULL, PRIMARY KEY(principal,method,key)
);
CREATE TABLE objects (
 id TEXT PRIMARY KEY, metadata BLOB NOT NULL, data BLOB NOT NULL
);
CREATE TABLE uploads (
 id TEXT PRIMARY KEY, lease BLOB NOT NULL, data BLOB NOT NULL
);
CREATE TABLE effect_states (
 id TEXT PRIMARY KEY, data BLOB NOT NULL
);
CREATE TABLE projection_history (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
 id TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL
);
CREATE INDEX events_by_life ON events(json_extract(data,'$.life_id'),json_extract(data,'$.run'),seq);
CREATE INDEX records_by_collection ON projections(kind,json_extract(data,'$.collection'));
CREATE INDEX launches_by_life ON projections(kind,json_extract(data,'$.target.life_id'));
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
 BEGIN SELECT RAISE(ABORT, 'immutable events'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
 BEGIN SELECT RAISE(ABORT, 'immutable events'); END;
CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts
 BEGIN SELECT RAISE(ABORT, 'immutable receipts'); END;
CREATE TRIGGER receipts_no_delete BEFORE DELETE ON receipts
 BEGIN SELECT RAISE(ABORT, 'immutable receipts'); END;
CREATE TRIGGER replies_no_update BEFORE UPDATE ON replies
 BEGIN SELECT RAISE(ABORT, 'immutable replies'); END;
CREATE TRIGGER replies_no_delete BEFORE DELETE ON replies
 BEGIN SELECT RAISE(ABORT, 'immutable replies'); END;
CREATE TRIGGER objects_no_update BEFORE UPDATE ON objects
 BEGIN SELECT RAISE(ABORT, 'immutable objects'); END;
CREATE TRIGGER objects_no_delete BEFORE DELETE ON objects
 WHEN NOT EXISTS (SELECT 1 FROM projections WHERE kind='collection_delete' AND id=OLD.id
 AND json_extract(data,'$.Metadata')=CAST(OLD.metadata AS TEXT))
 BEGIN SELECT RAISE(ABORT, 'immutable objects'); END;
CREATE TRIGGER history_no_update BEFORE UPDATE ON projection_history
 BEGIN SELECT RAISE(ABORT, 'immutable projection history'); END;
CREATE TRIGGER history_no_delete BEFORE DELETE ON projection_history
 BEGIN SELECT RAISE(ABORT, 'immutable projection history'); END;
PRAGMA user_version=2;
`

func fault(code api.ErrorCode, message string) *api.Error {
	result := &api.Error{Code: code, Owner: "lb-v2-service", Message: message,
		Instead: "Preserve the service state and repair the named prerequisite through its supervisor."}
	if code == api.CodeUnauthenticated {
		return api.WithErrorComponent(result, "store_scope")
	}
	return result
}

func New(deps Dependencies) (_ *Service, resultErr error) {
	if err := deps.ArchiveLimits.validate(); err != nil {
		return nil, err
	}
	if !wire.ValidID(deps.Config) || !filepath.IsAbs(deps.Directory) || deps.Clock == nil {
		return nil, wire.Invalid("store requires config, absolute directory and clock")
	}
	if os.Geteuid() == 0 {
		return nil, fault(api.CodePrerequisite, "state writer must use the dedicated unprivileged service UID")
	}
	physical, err := filepath.EvalSymlinks(deps.Directory)
	if err != nil || physical != filepath.Clean(deps.Directory) {
		return nil, fault(api.CodePrerequisite, "state directory must exist without symbolic links")
	}
	if err := privateParents(physical); err != nil {
		return nil, err
	}
	info, err := os.Lstat(physical)
	if err != nil || !private(info, true) {
		return nil, fault(api.CodePrerequisite, "state directory requires service ownership and mode 0700")
	}
	root, err := os.OpenRoot(physical)
	if err != nil {
		return nil, fault(api.CodeUnavailable, "cannot open private state directory")
	}
	s := &Service{deps: deps, root: root, views: make(map[*readView]struct{}), changed: make(chan struct{})}
	defer func() {
		if resultErr != nil {
			if closeErr := s.Close(); closeErr != nil {
				resultErr = fault(api.CodeIntegrity, "state initialization and close failed")
			}
		}
	}()
	s.lock, err = root.OpenFile("writer.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fault(api.CodeUnavailable, "cannot open writer lock")
	}
	lockInfo, err := s.lock.Stat()
	if err != nil || !private(lockInfo, false) {
		return nil, fault(api.CodePrerequisite, "writer lock ownership or mode is unsafe")
	}
	if err := unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fault(api.CodeUnavailable, "configuration already has a state writer")
	}
	for _, name := range []string{"state.sqlite", "state.sqlite-wal", "state.sqlite-shm", "state.sqlite-journal"} {
		info, err := root.Lstat(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fault(api.CodeIntegrity, "state file cannot be inspected")
		}
		if err == nil && !private(info, false) {
			return nil, fault(api.CodeIntegrity, "state file ownership, mode or link count is unsafe")
		}
	}
	f, err := root.OpenFile("state.sqlite", os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fault(api.CodeUnavailable, "cannot open state database")
	}
	s.dbInfo, err = f.Stat()
	if err != nil || !private(s.dbInfo, false) {
		f.Close()
		return nil, fault(api.CodePrerequisite, "opened database ownership or link count is unsafe")
	}
	if err := f.Close(); err != nil {
		return nil, fault(api.CodeIntegrity, "cannot close database preparation descriptor")
	}
	uri := url.URL{Scheme: "file", Path: filepath.Join(physical, "state.sqlite")}
	s.db, err = sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, fault(api.CodeUnavailable, "cannot initialize SQLite writer")
	}
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, statement := range []string{"PRAGMA busy_timeout=5000", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return nil, fault(api.CodeIntegrity, "cannot configure SQLite durability")
		}
	}
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}
	verification, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		return nil, fault(api.CodeIntegrity, "state verification failed at open")
	}
	// Inspect schema/configuration/integrity before changing an existing DB's
	// journal mode. An incompatible file must not be converted as a side effect.
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		return nil, fault(api.CodeIntegrity, "SQLite WAL mode is unavailable")
	}
	if err := s.verifyFiles(); err != nil {
		return nil, err
	}
	if err := api.CheckHumanEnrollmentPolicy(ctx, s, deps.Config); err != nil {
		return nil, err
	}
	return s, nil
}

func privateParents(path string) error {
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return fault(api.CodePrerequisite, "state ancestor permits untrusted writes")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return fault(api.CodePrerequisite, "state ancestor has an untrusted owner")
		}
		if directory == "/" {
			return nil
		}
	}
}
func (s *Service) verifyFiles() error {
	if err := privateParents(s.deps.Directory); err != nil {
		return err
	}
	directory, err := s.root.Stat(".")
	if err != nil || !private(directory, true) {
		return fault(api.CodeIntegrity, "state directory privacy changed")
	}
	physical, err := os.Lstat(s.deps.Directory)
	if err != nil || !os.SameFile(directory, physical) {
		return fault(api.CodeIntegrity, "state directory identity changed")
	}
	for _, name := range []string{"state.sqlite", "state.sqlite-wal", "state.sqlite-shm", "state.sqlite-journal", "writer.lock"} {
		info, err := s.root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) && name != "state.sqlite" && name != "writer.lock" {
			continue
		}
		if err != nil || !private(info, false) {
			return fault(api.CodeIntegrity, "state file privacy or link count changed")
		}
		if name == "state.sqlite" && s.dbInfo != nil && !os.SameFile(s.dbInfo, info) {
			return fault(api.CodeIntegrity, "database file identity changed")
		}
	}
	return nil
}

func private(info os.FileInfo, directory bool) bool {
	if info == nil || directory != info.IsDir() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	if directory {
		return info.Mode() == os.ModeDir|0700
	}
	return info.Mode() == 0600 && stat.Nlink == 1
}

func (s *Service) initialize(ctx context.Context) (resultErr error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fault(api.CodeIntegrity, "cannot begin store initialization")
	}
	defer finish(tx, &resultErr)
	var version, objects int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fault(api.CodeIntegrity, "cannot read store version")
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return fault(api.CodeIntegrity, "cannot inspect store schema")
	}
	if version == 0 && objects == 0 {
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			return fault(api.CodeIntegrity, "cannot create store schema")
		}
		s.storeID, err = wire.NewID()
		if err != nil {
			return err
		}
		s.key = make([]byte, 32)
		if _, err := rand.Read(s.key); err != nil {
			return fault(api.CodeUnavailable, "cursor signing key generation unavailable")
		}
		for name, value := range map[string][]byte{"config": []byte(s.deps.Config), "store_id": []byte(s.storeID), "cursor_key": s.key} {
			if _, err := tx.ExecContext(ctx, "INSERT INTO meta VALUES(?,?)", name, value); err != nil {
				return fault(api.CodeIntegrity, "cannot persist store identity")
			}
		}
	} else if version != api.SchemaVersion {
		return fault(api.CodeVersion, "database is not a schema-2 store")
	}
	var config, storeID []byte
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE name='config'").Scan(&config); err != nil || string(config) != s.deps.Config {
		return fault(api.CodeIntegrity, "store configuration binding mismatch")
	}
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE name='store_id'").Scan(&storeID); err != nil || !wire.ValidID(string(storeID)) {
		return fault(api.CodeIntegrity, "store identity is missing")
	}
	s.storeID = api.ID(storeID)
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE name='cursor_key'").Scan(&s.key); err != nil || len(s.key) != 32 {
		return fault(api.CodeIntegrity, "cursor signing key is missing")
	}
	// Upgrade only the exact previous schema. Unknown or weakened triggers are
	// never repaired by open. This revision adds one private journal-gated delete
	// condition without adding a second writer, table or public state setter.
	legacy := strings.Replace(ddl, "\n WHEN NOT EXISTS (SELECT 1 FROM projections WHERE kind='collection_delete' AND id=OLD.id\n AND json_extract(data,'$.Metadata')=CAST(OLD.metadata AS TEXT))", "", 1)
	var trigger string
	if err := tx.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE name='objects_no_delete'").Scan(&trigger); err != nil {
		return err
	}
	if !strings.Contains(trigger, "collection_delete") {
		if err := verifySchemaDDL(ctx, tx, legacy); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DROP TRIGGER objects_no_delete"); err != nil {
			return err
		}
		for _, statement := range strings.Split(ddl, ";\n") {
			if strings.HasPrefix(strings.TrimSpace(statement), "CREATE TRIGGER objects_no_delete ") {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return err
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fault(api.CodeIntegrity, "store initialization commit failed")
	}
	return nil
}

func finish(tx *sql.Tx, resultErr *error) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		*resultErr = fault(api.CodeIntegrity, "transaction rollback failed")
	}
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.changed != nil {
		close(s.changed)
		s.changed = make(chan struct{})
	}
	var result error
	for view := range s.views {
		result = errors.Join(result, view.closeLocked())
	}
	if s.db != nil {
		result = errors.Join(result, s.db.Close())
	}
	if s.lock != nil {
		result = errors.Join(result, s.lock.Close())
	}
	if s.root != nil {
		result = errors.Join(result, s.root.Close())
	}
	if result != nil {
		s.closeErr = fault(api.CodeIntegrity, "state writer close failed")
		return s.closeErr
	}
	return nil
}

func (s *Service) available() error {
	if s.closed || s.db == nil {
		return fault(api.CodeUnavailable, "state writer is closed")
	}
	return nil
}

func principal(scope api.Scope) string {
	return scope.Actor.Kind + ":" + string(scope.Actor.ID) + ":" + string(scope.Actor.LifeID)
}

func hash(data []byte) string {
	// Cursor and journal hashes are generated values, never literal fixtures.
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
