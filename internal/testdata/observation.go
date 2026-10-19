// Package testdata supplies identical stored observation bytes to every reader
// test. It seeds events through the real event store without launching a runner.
package testdata

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/eventstore"
)

//go:embed shell-observation.json
var observationBytes []byte

const Lane = "fixture"
const EventKind = "lane.workaround_suspected"

// CommandText is the fixture command; its sha256 is filled into the payload
// here so the repository holds no 64-hex literal (the release scan's token rule).
const CommandText = "printf \"`printf fixture`\""

// PayloadBytes removes only the fixture file's terminal newline and fills the
// command hash. These are the exact canonical bytes stored in SQLite; no reader
// repairs numbers or hashes.
func PayloadBytes() []byte {
	sum := sha256.Sum256([]byte(CommandText))
	return bytes.Replace(bytes.TrimSuffix(observationBytes, []byte{'\n'}), []byte("@COMMAND_SHA256@"), []byte(hex.EncodeToString(sum[:])), 1)
}

func Payload(t *testing.T, decode func([]byte) (any, error)) map[string]any {
	t.Helper()
	v, err := decode(PayloadBytes())
	if err != nil {
		t.Fatal(err)
	}
	p, ok := v.(map[string]any)
	if !ok {
		t.Fatal("the observation payload must decode as an object")
	}
	return p
}

func Envelope(payload map[string]any) map[string]any {
	return map[string]any{"id": "ev-observation", "kind": EventKind, "lane": Lane,
		"actor": "laneboss", "occurred_at": nil, "payload": payload, "protocol_version": "1.3.0"}
}

func ReplayEvent(t *testing.T, decode func([]byte) (any, error)) map[string]any {
	t.Helper()
	e := Envelope(Payload(t, decode))
	e["seq"] = int64(2)
	e["recorded_at"] = "2026-10-15T00:00:00.000000Z"
	return e
}

// Contract validates the positive bytes first, so malformed-byte assertions
// cannot pass merely because the reader rejects every observation.
func Contract(t *testing.T, decode func([]byte) (any, error), check func(map[string]any) error) {
	t.Helper()
	if err := check(Payload(t, decode)); err != nil {
		t.Fatalf("valid stored observation rejected before contract assertions: %s", err)
	}
	for _, row := range []struct{ name, before, after string }{
		{"nil-workaround", `"how":["shell-substitution-in-text"]`, `"how":["shell-write"]`},
		{"linked-observation", `"refusal":null`, `"refusal":"rf-0123456789abcdef01234567"`},
		{"mixed-kind", `"how":["shell-substitution-in-text"]`, `"how":["shell-substitution-in-text","shell-write"]`},
		{"file-path", `"paths":["(command)"]`, `"paths":["/fixture/file"]`},
		{"similarity", `"similarity":null`, `"similarity":{"containment":1,"coverage":1}`},
		{"missing-refusal", `"refusal":null,`, ``},
		{"item-float", `"item":0`, `"item":0.0`},
		{"item-exponent", `"item":0`, `"item":0e0`},
		{"item-string", `"item":0`, `"item":"0"`},
		{"item-negative", `"item":0`, `"item":-1`},
		{"item-too-large", `"item":0`, `"item":1000001`},
		{"item-missing", `"item":0,`, ``},
		{"line-zero", `"line":1`, `"line":0`},
		{"line-too-large", `"line":1`, `"line":4611686018427387905`},
		{"offset-negative", `"offset":0`, `"offset":-1`},
		{"offset-too-large", `"offset":0`, `"offset":4611686018427387905`},
		{"length-float", `"length":25`, `"length":25.0`},
		{"length-too-large", `"length":25`, `"length":4611686018427387905`},
		{"run-zero", `"run":1`, `"run":0`},
	} {
		t.Run(row.name, func(t *testing.T) {
			if bytes.Count(PayloadBytes(), []byte(row.before)) != 1 {
				t.Fatal("the contract mutation must change exactly one stored field")
			}
			data := bytes.Replace(PayloadBytes(), []byte(row.before), []byte(row.after), 1)
			value, err := decode(data)
			if err != nil {
				t.Fatalf("the contract mutation must reach field validation: %s", err)
			}
			if err := check(value.(map[string]any)); err == nil {
				t.Fatal("invalid independent-observation contract was accepted")
			}
		})
	}
	// Excerpt lengths can describe a truncated large command. This bound must
	// agree across readers even though the fixture's displayed prefix is short.
	t.Run("large-excerpt", func(t *testing.T) {
		data := bytes.Replace(PayloadBytes(), []byte(`"length":25`), []byte(`"length":1000000001`), 1)
		value, err := decode(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := check(value.(map[string]any)); err != nil {
			t.Fatalf("valid large excerpt rejected: %s", err)
		}
	})
}

type StoreFixture struct {
	Config *eventstore.Configuration
	Store  *eventstore.Store
	DB     *sql.DB
	Path   string
}

// OpenStore uses the production writer and schema, then verifies that the
// payload column contains the original fixture bytes. Readers use this database
// directly, rather than reconstructing reader-specific event maps.
func OpenStore(t *testing.T) *StoreFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &eventstore.Configuration{Name: Lane, Home: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), Directory: filepath.Join(root, "config", "configs", Lane),
		StatePath: filepath.Join(root, "state", Lane)}
	if err := os.MkdirAll(c.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte("schema_version = 1\nname = \"fixture\"\n[runners.fixture]\ncommand = [\"sh\"]\nresume = [\"sh\"]\nprompt = \"stdin\"\n[supervisors.top]\nlevel = 5\nrunner = \"fixture\"\n")
	if err := os.WriteFile(filepath.Join(c.Directory, "config.toml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	dir, err := c.OpenDirectory(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	})
	store, err := eventstore.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	brief := []byte("Read the stored observation fixture.\n")
	briefSum := sha256.Sum256(brief)
	briefHash := hex.EncodeToString(briefSum[:])
	laneDir := filepath.Join(c.StatePath, "lanes", Lane)
	if err := os.MkdirAll(filepath.Join(laneDir, "rendered"), 0700); err != nil {
		t.Fatal(err)
	}
	briefPath := filepath.Join(laneDir, "rendered", briefHash+".md")
	if err := os.WriteFile(briefPath, brief, 0600); err != nil {
		t.Fatal(err)
	}
	started := map[string]any{"run": 1, "how": "start", "launch": "0123456789abcdef0123456789abcdef",
		"runner": "fixture", "model": "fixture-model-1", "effort": nil, "account": nil,
		"chosen_by":  map[string]any{"runner": "supervisor", "model": "supervisor", "effort": nil, "account": nil},
		"difficulty": nil, "project": nil, "worktree": root, "branch": nil, "base": nil, "repository": nil,
		"budget_minutes": 1, "quiet_seconds": 60, "brief": map[string]any{"path": briefPath, "sha256": briefHash},
		"log": filepath.Join(laneDir, "output.log"), "session": map[string]any{"socket": c.Socket(c.StatePath), "name": Lane},
		"touches": []any{}, "claims": nil}
	e := Envelope(started)
	e["id"], e["kind"] = "ev-started", "lane.started"
	if _, err := store.Append(e); err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) (any, error) { return eventstore.Parse(data, "stored observation") }
	if _, err := store.Append(Envelope(Payload(t, decode))); err != nil {
		t.Fatal(err)
	}
	e = Envelope(map[string]any{"run": 1, "reason": "exit", "exit_code": 0, "signal": nil,
		"duration_seconds": 0, "pattern": nil, "classification": nil, "survivors": 0})
	e["id"], e["kind"] = "ev-ended", "lane.ended"
	if _, err := store.Append(e); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.StatePath, "events.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	var payload string
	if err := db.QueryRow("SELECT payload FROM events WHERE kind = ?", EventKind).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(payload), PayloadBytes()) {
		t.Fatal("the production writer changed the canonical observation bytes")
	}
	return &StoreFixture{Config: c, Store: store, DB: db, Path: path}
}

func AssertState(t *testing.T, row map[string]any) {
	t.Helper()
	found, ok := row["refusals"].(map[string]any)
	if !ok {
		t.Fatal("replay lost the observation state")
	}
	if len(found["recorded"].(map[string]any)) != 0 || len(found["suspected"].(map[string]any)) != 1 || len(found["unreviewed"].([]any)) != 0 {
		t.Fatal("replay must preserve one observation without a refusal or acceptance hold")
	}
	decode := func(data []byte) (any, error) { return eventstore.Parse(data, "stored observation") }
	payload := Payload(t, decode)
	item, ok := found["suspected"].(map[string]any)[payload["suspicion"].(string)].(map[string]any)
	if !ok {
		t.Fatal("replay changed the stored observation's identity")
	}
	for _, key := range []string{"refusal", "run", "how", "paths"} {
		if eventstore.Canonical(item[key]) != eventstore.Canonical(payload[key]) {
			t.Fatalf("replay changed the observation's %s field", key)
		}
	}
	if eventstore.Canonical(item["seq"]) != "2" {
		t.Fatal("replay changed the stored observation's event position")
	}
}
