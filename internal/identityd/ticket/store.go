package ticket

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"laneboss.io/laneboss/internal/faults"
)

// Store uses the identity service's database, never the caller's state store.
// The owner of db must keep its files inaccessible to lane OS users. Closing
// the database is the service's responsibility.
type Store struct {
	db    *sql.DB
	human HumanAuthorizer
	now   func() time.Time
}

func NewStore(ctx context.Context, db *sql.DB, human HumanAuthorizer) (*Store, error) {
	if db == nil {
		return nil, refusal(Unavailable)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, refusal(Unavailable)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS identity_registration_tickets (
		digest BLOB PRIMARY KEY NOT NULL CHECK (length(digest) = 32),
		config TEXT NOT NULL,
		level INTEGER NOT NULL CHECK (level BETWEEN 3 AND 6),
		role TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		used_at INTEGER
	) WITHOUT ROWID`)
	if err != nil {
		return nil, refusal(Unavailable)
	}
	// Serialize schema inspection with other service handles. Pre-R39 rows
	// have no issued level; leave them NULL, never infer it from current policy.
	if _, err := tx.ExecContext(ctx, `UPDATE identity_registration_tickets SET used_at = used_at WHERE 0`); err != nil {
		return nil, refusal(Unavailable)
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(identity_registration_tickets)`)
	if err != nil {
		return nil, refusal(Unavailable)
	}
	hasLevel := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return nil, refusal(Unavailable)
		}
		hasLevel = hasLevel || name == "level"
	}
	readErr := rows.Err()
	if closeErr := rows.Close(); readErr != nil || closeErr != nil {
		return nil, refusal(Unavailable)
	}
	if !hasLevel {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE identity_registration_tickets
			ADD COLUMN level INTEGER CHECK (level BETWEEN 3 AND 6)`); err != nil {
			return nil, refusal(Unavailable)
		}
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS identity_ticket_consumers (
		digest BLOB PRIMARY KEY NOT NULL, pid INTEGER NOT NULL, start TEXT NOT NULL,
		uid INTEGER NOT NULL, consumed_at INTEGER NOT NULL) WITHOUT ROWID`); err != nil {
		return nil, refusal(Unavailable)
	}
	if err := tx.Commit(); err != nil {
		return nil, refusal(Unavailable)
	}
	return &Store{db: db, human: human, now: time.Now}, nil
}

// Issue authorizes before generating anything. The raw value is returned once;
// only its digest is passed to SQL. No cleartext ticket appears in a database
// parameter, audit record, filename, or error.
func (s *Store) Issue(ctx context.Context, scope Scope, ttl time.Duration) (string, error) {
	if s == nil || s.db == nil {
		return "", refusal(Unavailable)
	}
	if s.human == nil || s.human.RequireHuman(ctx) != nil {
		return "", refusal(HumanRequired)
	}
	if !scope.Valid() {
		return "", refusal(InvalidScope)
	}
	if !ValidTTL(ttl) {
		return "", refusal(InvalidTTL)
	}
	// Keep one day of expired tombstones for diagnostics and theft review.
	cutoff := s.now().Add(-24 * time.Hour).UnixNano()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM identity_ticket_consumers WHERE consumed_at < ?`, cutoff); err != nil {
		return "", refusal(Unavailable)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM identity_registration_tickets WHERE expires_at < ?`, cutoff); err != nil {
		return "", refusal(Unavailable)
	}
	var random [randomBytes]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", refusal(Unavailable)
	}
	raw := prefix + scope.Config + "." + strconv.Itoa(scope.Level) + "." + scope.Role + "." + base64.RawURLEncoding.EncodeToString(random[:])
	hash := digest(raw)
	_, err := s.db.ExecContext(ctx, `INSERT INTO identity_registration_tickets
		(digest, config, level, role, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hash[:], scope.Config, scope.Level, scope.Role, s.now().Add(ttl).UnixNano())
	if err != nil {
		return "", refusal(Unavailable)
	}
	return raw, nil
}

// Consume is the store-only form of Redeem, without a registration grant.
func (s *Store) Consume(ctx context.Context, scope Scope, raw string) error {
	return s.Redeem(ctx, scope, raw, nil)
}

// Redeem's update is the single-use decision. All store instances and service
// processes sharing this database compete for the same NULL -> timestamp
// transition. A failed registration after this succeeds burns the ticket; it
// must never reset used_at to make a retry succeed. The write lock is acquired
// before reading the clock, so waiting for another writer cannot extend expiry.
// authorize receives only the authenticated database scope while the writer
// lock is held. A denied grant rolls back without burning the ticket. No grant
// may escape to registration until this method commits successfully.
func (s *Store) Redeem(ctx context.Context, scope Scope, raw string, authorize func(Scope) error) (failure error) {
	if s == nil || s.db == nil {
		return refusal(Unavailable)
	}
	if !scope.Valid() {
		return refusal(InvalidScope)
	}
	publicScope, ok := scopeOf(raw)
	if !ok {
		return refusal(Unknown)
	}
	hash := digest(raw)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return refusal(Unavailable)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			failure = refusal(Unavailable)
		}
	}()
	// A write statement acquires SQLite's transaction-wide writer lock even
	// though it preserves this row. This avoids sampling time before a blocked
	// conditional consume. Refused operations roll back this lock-only update.
	if _, err := tx.ExecContext(ctx, `UPDATE identity_registration_tickets
		SET used_at = used_at WHERE digest = ?`, hash[:]); err != nil {
		return refusal(Unavailable)
	}
	now := s.now().UnixNano()
	var issued Scope
	var level, used sql.NullInt64
	var expires int64
	err = tx.QueryRowContext(ctx, `SELECT config, level, role, expires_at, used_at
		FROM identity_registration_tickets WHERE digest = ?`, hash[:]).Scan(&issued.Config, &level, &issued.Role, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		// Isolated configurations cannot read each other's records. Public
		// scope permits this diagnostic only; it can never authorize a use.
		if publicScope.Config != scope.Config {
			return refusal(WrongConfig)
		}
		return refusal(Unknown)
	}
	if err != nil {
		return refusal(Unavailable)
	}
	if !level.Valid {
		return refusal(Unknown)
	}
	issued.Level = int(level.Int64)
	if !issued.Valid() || issued != publicScope {
		return refusal(Unavailable)
	}
	unused := " AND used_at IS NULL"
	// A fault build can deliberately remove the guard. The second-use row
	// must then fail, and Reach retains evidence that this mutation executed.
	if faults.Get("ticket-reuse").Point != "" {
		if err := faults.Reach("ticket-reuse"); err != nil {
			return refusal(Unavailable)
		}
		unused = ""
	}
	// Consumed status wins over requested scope, including a request that
	// changes both level and role. Level wins over role for an unused ticket.
	if used.Valid && unused != "" {
		return refusal(Used)
	}
	if issued.Config != scope.Config {
		return refusal(WrongConfig)
	}
	if issued.Level != scope.Level {
		if faults.Get("ticket-level-unchecked").Point == "" {
			return refusal(WrongLevel)
		}
		if err := faults.Reach("ticket-level-unchecked"); err != nil {
			return refusal(Unavailable)
		}
	}
	if issued.Role != scope.Role {
		return refusal(WrongRole)
	}
	if expires <= now {
		return refusal(Expired)
	}
	if authorize != nil {
		if err := authorize(issued); err != nil {
			return err
		}
	}
	// Resolve the parent before sampling expiry again: grant resolution must
	// not extend a ticket's lifetime while it holds the writer lock.
	now = s.now().UnixNano()
	result, err := tx.ExecContext(ctx, `UPDATE identity_registration_tickets SET used_at = ?
		WHERE digest = ? AND config = ? AND level = ? AND role = ? AND expires_at > ?`+unused,
		now, hash[:], issued.Config, issued.Level, issued.Role, now)
	if err != nil {
		return refusal(Unavailable)
	}
	count, err := result.RowsAffected()
	if err != nil || count > 1 {
		return refusal(Unavailable)
	}
	if count == 1 {
		if peer, ok := ctx.Value(consumerKey{}).(Consumer); ok {
			if peer.PID <= 1 || peer.Start == "" {
				return refusal(Unavailable)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO identity_ticket_consumers
				(digest, pid, start, uid, consumed_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(digest) DO UPDATE SET pid=excluded.pid, start=excluded.start,
				uid=excluded.uid, consumed_at=excluded.consumed_at`, hash[:], peer.PID, peer.Start, peer.UID, now); err != nil {
				return refusal(Unavailable)
			}
		}
		if err := tx.Commit(); err != nil {
			return refusal(Unavailable)
		}
		return nil
	}
	if expires <= now {
		return refusal(Expired)
	}
	return refusal(Unavailable)
}
