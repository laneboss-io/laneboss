package ticket

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"laneboss.io/laneboss/internal/faults"
)

type peerKey struct{}
type testPeer struct {
	principal string
	terminal  bool
}
type testHuman struct{}

func (testHuman) RequireHuman(ctx context.Context) error {
	peer, ok := ctx.Value(peerKey{}).(testPeer)
	if !ok || peer.principal != "human" || !peer.terminal {
		return errors.New("the peer is not the terminal human")
	}
	return nil
}

func humanContext() context.Context {
	return context.WithValue(context.Background(), peerKey{}, testPeer{"human", true})
}

func openTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal("cannot open the real SQLite fixture")
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error("cannot close the SQLite fixture")
		}
	})
	return db
}

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.sqlite")
	s, err := NewStore(context.Background(), openTestDB(t, path), testHuman{})
	if err != nil {
		t.Fatal("cannot initialize the ticket store")
	}
	return s, path
}

func issueTestTicket(t *testing.T, s *Store, scope Scope, ttl time.Duration) string {
	t.Helper()
	raw, err := s.Issue(humanContext(), scope, ttl)
	if err != nil || !Valid(raw) {
		t.Fatal("the authorized issue did not produce a canonical ticket")
	}
	return raw
}

func requireReason(t *testing.T, err error, reason Reason) {
	t.Helper()
	var refused *Refusal
	if !errors.As(err, &refused) || refused.Reason != reason {
		t.Fatalf("expected refusal %s; the operation did not refuse for that reason", reason)
	}
	if !strings.Contains(refused.Error(), "\nInstead: ") {
		t.Fatal("the refusal lost its recovery route")
	}
}

func TestSingleUse(t *testing.T) {
	s, _ := newTestStore(t)
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	if err := s.Consume(context.Background(), scope, raw); err != nil {
		t.Fatal("the first use did not consume the ticket")
	}
	second := s.Consume(context.Background(), scope, raw)
	if fault := faults.Get("ticket-reuse"); fault.Point != "" {
		if _, err := os.Stat(fault.Marker); err != nil {
			t.Fatal("the single-use mutant did not reach its marker")
		}
	}
	if second == nil {
		t.Fatal("a registration ticket verified twice")
	}
	requireReason(t, second, Used)
}

func TestScopeAndUnknownDoNotBurnTicket(t *testing.T) {
	s, _ := newTestStore(t)
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	requireReason(t, s.Consume(context.Background(), Scope{Config: "example", Level: 4, Role: "mini"}, raw), WrongLevel)
	requireReason(t, s.Consume(context.Background(), Scope{Config: "other", Level: 5, Role: "top"}, raw), WrongConfig)
	requireReason(t, s.Consume(context.Background(), Scope{Config: "example", Level: 5, Role: "mini"}, raw), WrongRole)
	var random [randomBytes]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("cannot generate an unknown ticket")
	}
	unknown := prefix + scope.Config + ".5." + scope.Role + "." + base64.RawURLEncoding.EncodeToString(random[:])
	requireReason(t, s.Consume(context.Background(), scope, unknown), Unknown)
	for _, malformed := range []string{"", raw + "\n", strings.TrimPrefix(raw, prefix), raw + "="} {
		requireReason(t, s.Consume(context.Background(), scope, malformed), Unknown)
	}
	if err := s.Consume(context.Background(), scope, raw); err != nil {
		t.Fatal("a wrong scope or unknown input burned the valid ticket")
	}
}

func TestIssuedLevelAndUsedPrecedence(t *testing.T) {
	s, _ := newTestStore(t)
	scope := Scope{Config: "example", Level: 4, Role: "supervisor"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	var persisted Scope
	if err := s.db.QueryRow(`SELECT config, level, role FROM identity_registration_tickets`).Scan(&persisted.Config, &persisted.Level, &persisted.Role); err != nil || persisted != scope {
		t.Fatal("the persisted scope differs from the issued level and role")
	}
	changed := strings.Replace(raw, ".4.supervisor.", ".5.supervisor.", 1)
	requireReason(t, s.Consume(context.Background(), Scope{Config: "example", Level: 5, Role: "supervisor"}, changed), Unknown)
	if err := s.Redeem(context.Background(), scope, raw, func(issued Scope) error {
		if issued != persisted {
			t.Fatal("grant construction did not receive the stored issued scope")
		}
		return nil
	}); err != nil {
		t.Fatal("the exact issued scope did not redeem")
	}
	for _, requested := range []Scope{scope, {Config: "example", Level: 5, Role: "top"}, {Config: "example", Level: 4, Role: "mini"}} {
		requireReason(t, s.Consume(context.Background(), requested, raw), Used)
	}
}

func TestLegacyTicketHasNoIssuedLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db := openTestDB(t, path)
	if _, err := db.Exec(`CREATE TABLE identity_registration_tickets (
		digest BLOB PRIMARY KEY NOT NULL, config TEXT NOT NULL, role TEXT NOT NULL,
		expires_at INTEGER NOT NULL, used_at INTEGER) WITHOUT ROWID`); err != nil {
		t.Fatal("cannot create the actual pre-R39 schema")
	}
	var nonce [randomBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("cannot generate a legacy ticket fixture")
	}
	raw := "lbt1.example.supervisor." + base64.RawURLEncoding.EncodeToString(nonce[:])
	hash := digest(raw)
	if _, err := db.Exec(`INSERT INTO identity_registration_tickets (digest, config, role, expires_at)
		VALUES (?, ?, ?, ?)`, hash[:], "example", "supervisor", time.Now().Add(DefaultTTL).UnixNano()); err != nil {
		t.Fatal("cannot retain a legacy unconsumed ticket")
	}
	s, err := NewStore(context.Background(), db, testHuman{})
	if err != nil {
		t.Fatal("cannot migrate the pre-R39 ticket database")
	}
	var level, used sql.NullInt64
	if err := db.QueryRow(`SELECT level, used_at FROM identity_registration_tickets WHERE digest = ?`, hash[:]).Scan(&level, &used); err != nil || level.Valid || used.Valid {
		t.Fatal("migration inferred a missing level or consumed the legacy row")
	}
	scope := Scope{Config: "example", Level: 4, Role: "supervisor"}
	requireReason(t, s.Consume(context.Background(), scope, raw), Unknown)
	control := issueTestTicket(t, s, scope, DefaultTTL)
	if err := s.Consume(context.Background(), scope, control); err != nil {
		t.Fatal("migration prevented fresh explicitly scoped issuance")
	}
}

func TestIsolatedScopesAndForgery(t *testing.T) {
	s, _ := newTestStore(t)
	other, _ := newTestStore(t)
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	requireReason(t, other.Consume(context.Background(), Scope{Config: "other", Level: 5, Role: "top"}, raw), WrongConfig)
	claimed := strings.Replace(raw, ".example.", ".other.", 1)
	requireReason(t, other.Consume(context.Background(), Scope{Config: "other", Level: 5, Role: "top"}, claimed), Unknown)
	requireReason(t, s.Consume(context.Background(), Scope{Config: "other", Level: 5, Role: "top"}, claimed), Unknown)
	if err := s.Consume(context.Background(), scope, raw); err != nil {
		t.Fatal("a scope claim or cross-store refusal burned the real ticket")
	}
}

func TestExpiryAtBoundary(t *testing.T) {
	s, _ := newTestStore(t)
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return issued }
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, time.Second)
	s.now = func() time.Time { return issued.Add(time.Second) }
	requireReason(t, s.Consume(context.Background(), scope, raw), Expired)
	var used sql.NullInt64
	if err := s.db.QueryRow(`SELECT used_at FROM identity_registration_tickets`).Scan(&used); err != nil || used.Valid {
		t.Fatal("an expired ticket was consumed or could not be inspected")
	}
	control := issueTestTicket(t, s, scope, time.Second)
	if err := s.Consume(context.Background(), scope, control); err != nil {
		t.Fatal("a newly issued unexpired control was refused")
	}
}

func TestAtomicUseAcrossStores(t *testing.T) {
	s, path := newTestStore(t)
	other, err := NewStore(context.Background(), openTestDB(t, path), testHuman{})
	if err != nil {
		t.Fatal("cannot open the independent store handle")
	}
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	const attempts = 24
	results := make(chan error, attempts)
	ready := make(chan struct{})
	var workers sync.WaitGroup
	for i := range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-ready
			store := s
			if i%2 != 0 {
				store = other
			}
			results <- store.Consume(context.Background(), scope, raw)
		}()
	}
	close(ready)
	workers.Wait()
	close(results)
	accepted := 0
	for result := range results {
		if result == nil {
			accepted++
		} else {
			requireReason(t, result, Used)
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent consumption accepted %d uses; expected exactly one", accepted)
	}
}

func TestTerminalHumanOnly(t *testing.T) {
	s, _ := newTestStore(t)
	for _, peer := range []testPeer{{"", false}, {"human", false}, {"lane:worker", true}, {"supervisor:top", true}} {
		ctx := context.WithValue(context.Background(), peerKey{}, peer)
		raw, err := s.Issue(ctx, Scope{Config: "example", Level: 5, Role: "top"}, DefaultTTL)
		requireReason(t, err, HumanRequired)
		if raw != "" {
			t.Fatal("a nonhuman peer received a ticket")
		}
	}
	s.human = nil
	raw, err := s.Issue(humanContext(), Scope{Config: "example", Level: 5, Role: "top"}, DefaultTTL)
	requireReason(t, err, HumanRequired)
	if raw != "" {
		t.Fatal("an absent authorizer minted a ticket")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM identity_registration_tickets`).Scan(&count); err != nil || count != 0 {
		t.Fatal("a refused issue changed the ticket store")
	}
}

func TestRefusalText(t *testing.T) {
	for _, row := range []struct {
		reason Reason
		first  string
	}{
		{Required, "supervisor registration requires a human-issued ticket"},
		{Unknown, "the registration ticket is unknown"},
		{Expired, "the registration ticket has expired"},
		{WrongLevel, "the registration ticket is for another level"},
		{WrongRole, "the registration ticket is for another role"},
		{WrongConfig, "the registration ticket is for another configuration"},
		{Used, "the registration ticket has already been used"},
		{HumanRequired, "only the human at a real terminal may issue a registration ticket"},
	} {
		text := (&Refusal{Reason: row.reason}).Error()
		first, instead, ok := strings.Cut(text, "\n")
		if first != row.first || !ok || !strings.HasPrefix(instead, "Instead: ") {
			t.Fatalf("the %s refusal lost its exact first line or recovery route", row.reason)
		}
	}
}

func TestHashOnlyPersistenceAndRestart(t *testing.T) {
	s, path := newTestStore(t)
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	var saved []byte
	if err := s.db.QueryRow(`SELECT digest FROM identity_registration_tickets`).Scan(&saved); err != nil {
		t.Fatal("cannot inspect the persisted ticket digest")
	}
	hash := digest(raw)
	if !bytes.Equal(saved, hash[:]) {
		t.Fatal("the store did not retain exactly the ticket digest")
	}
	files, err := filepath.Glob(path + "*")
	if err != nil || len(files) == 0 {
		t.Fatal("the store has no on-disk evidence")
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil || bytes.Contains(data, []byte(raw)) {
			t.Fatal("a database or journal is unreadable or contains the cleartext ticket")
		}
	}
	restarted, err := NewStore(context.Background(), openTestDB(t, path), testHuman{})
	if err != nil {
		t.Fatal("the stored ticket could not survive a new service handle")
	}
	if err := restarted.Consume(context.Background(), scope, raw); err != nil {
		t.Fatal("the persisted ticket was refused after restart")
	}
	requireReason(t, s.Consume(context.Background(), scope, raw), Used)
}

func TestInvalidLifetimeAndStorageFailure(t *testing.T) {
	s, _ := newTestStore(t)
	for _, ttl := range []time.Duration{0, -time.Second, MaxTTL + time.Nanosecond} {
		raw, err := s.Issue(humanContext(), Scope{Config: "example", Level: 5, Role: "top"}, ttl)
		requireReason(t, err, InvalidTTL)
		if raw != "" {
			t.Fatal("an invalid lifetime minted a ticket")
		}
	}
	raw := issueTestTicket(t, s, Scope{Config: "example", Level: 5, Role: "top"}, DefaultTTL)
	if err := s.db.Close(); err != nil {
		t.Fatal("cannot close the store for the failure control")
	}
	requireReason(t, s.Consume(context.Background(), Scope{Config: "example", Level: 5, Role: "top"}, raw), Unavailable)
	issued, err := s.Issue(humanContext(), Scope{Config: "example", Level: 5, Role: "top"}, DefaultTTL)
	requireReason(t, err, Unavailable)
	if issued != "" || strings.Contains(err.Error(), raw) {
		t.Fatal("a storage failure returned or disclosed a raw ticket")
	}
}

func TestPrivateFile(t *testing.T) {
	s, _ := newTestStore(t)
	raw := issueTestTicket(t, s, Scope{Config: "example", Level: 5, Role: "top"}, DefaultTTL)
	path := filepath.Join(t.TempDir(), "ticket")
	if err := os.WriteFile(path, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal("cannot write the private handoff fixture")
	}
	if read, err := ReadFile(path); err != nil || read != raw {
		t.Fatal("the private ticket file was not read exactly")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal("cannot change handoff permissions")
	}
	_, err := ReadFile(path)
	requireReason(t, err, InvalidFile)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal("cannot restore private permissions")
	}
	for _, content := range []string{raw + "\n\n", raw + "\r\n", strings.Repeat("x", 257)} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal("cannot change handoff contents")
		}
		_, err := ReadFile(path)
		requireReason(t, err, InvalidFile)
		if strings.Contains(err.Error(), raw) {
			t.Fatal("a file refusal disclosed the ticket")
		}
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal("cannot create the link fixture")
	}
	_, err = ReadFile(link)
	requireReason(t, err, InvalidFile)
	_, err = ReadFile(filepath.Dir(path))
	requireReason(t, err, InvalidFile)
}
