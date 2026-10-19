package boxledger_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxledger"
)

// TestOpenAndWritable detects eager creation or Writable writing event data.
func TestOpenAndWritable(t *testing.T) {
	l, path := newLedger(t)
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("Open created a directory or stat failed: %v", err)
	}
	rows, err := l.Events()
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("missing ledger events = %v, %v", rows, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("Events created a directory")
	}
	for i := 0; i < 2; i++ {
		if err := l.Writable(); err != nil {
			t.Fatal(err)
		}
		if len(readBytes(t, path)) != 0 {
			t.Fatal("Writable wrote a line")
		}
	}
	for _, row := range []struct{ path, schema string }{
		{"", schema}, {path, ""}, {path, "demo\n"}, {path, strings.Repeat("a", 65)},
	} {
		if l, err := boxledger.Open(row.path, row.schema); err == nil || l != nil {
			t.Fatal("invalid Open arguments accepted")
		}
	}
}

// TestPrivateModes detects omitted permission creation or repair.
func TestPrivateModes(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			l, path := newLedger(t)
			dir := filepath.Dir(path)
			if existing {
				seed(t, path, "")
				if err := os.WriteFile(path+".lock", nil, 0644); err != nil {
					t.Fatal(err)
				}
				for _, entry := range []struct {
					path string
					mode os.FileMode
				}{{dir, 0755}, {path, 0644}, {path + ".lock", 0644}} {
					if err := os.Chmod(entry.path, entry.mode); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := l.Writable(); err != nil {
				t.Fatal(err)
			}
			check := func() {
				t.Helper()
				for _, entry := range []struct {
					path string
					mode os.FileMode
				}{{dir, 0700}, {path, 0600}, {path + ".lock", 0600}} {
					info, err := os.Stat(entry.path)
					if err != nil || info.Mode().Perm() != entry.mode {
						t.Fatalf("private mode mismatch for %s: %v", filepath.Base(entry.path), err)
					}
				}
			}
			check()
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			for _, entry := range []string{path, path + ".lock"} {
				if err := os.Chmod(entry, 0644); err != nil {
					t.Fatal(err)
				}
			}
			appendEvent(t, l, "LAUNCHED", map[string]any{"instance_id": "i-demo1"})
			check()
		})
	}
}

// TestWritableFailures detects swallowed directory, open or read failures.
func TestWritableFailures(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("demo"), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := boxledger.Open(filepath.Join(blocker, "ledger.jsonl"), schema)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Writable(); err == nil {
		t.Fatal("regular file accepted as ledger directory")
	}
	if got := string(readBytes(t, blocker)); got != "demo" {
		t.Fatal("failed Writable changed the blocking file")
	}
	for _, blockLock := range []bool{false, true} {
		l, path := newLedger(t)
		blocked := path
		if blockLock {
			blocked += ".lock"
		}
		if err := os.MkdirAll(blocked, 0700); err != nil {
			t.Fatal(err)
		}
		if err := l.Writable(); err == nil {
			t.Fatal("directory accepted as ledger or lock file")
		}
		if _, err := l.Append("LAUNCHED", map[string]any{"instance_id": "i-demo1"}); err == nil {
			t.Fatal("append ignored a file-open failure")
		}
		if !blockLock {
			if _, err := l.Events(); err == nil {
				t.Fatal("Events ignored a read failure")
			}
		}
	}
}

// TestWritableReadOnly detects bypassing read-only directory permissions.
func TestWritableReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("read-only permissions do not constrain root")
	}
	l, path := newLedger(t)
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	if err := l.Writable(); err == nil {
		t.Fatal("Writable accepted a read-only directory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed Writable created a ledger")
	}
}

// TestEventValidation detects unknown events, kinds or invalid instance IDs.
func TestEventValidation(t *testing.T) {
	rows := []struct {
		name, event string
		fields      map[string]any
	}{
		{"unknown", "SECRET-NEEDLE", map[string]any{"instance_id": "i-demo1"}},
		{"kind", "INCIDENT", map[string]any{"kind": "SECRET-NEEDLE"}},
		{"kind-missing", "INCIDENT", nil},
		{"kind-type", "INCIDENT", map[string]any{"kind": 12}},
		{"id-missing", "LAUNCHED", nil},
		{"id-empty", "LAUNCHED", map[string]any{"instance_id": ""}},
		{"id-type", "LAUNCHED", map[string]any{"instance_id": 12}},
		{"id-null", "LAUNCHED", map[string]any{"instance_id": nil}},
		{"incident-id", "INCIDENT", map[string]any{"kind": "no_end", "instance_id": 12}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			l, path := newLedger(t)
			got, err := l.Append(row.event, row.fields)
			if err == nil || got != nil || strings.Contains(err.Error(), "SECRET-NEEDLE") {
				t.Fatal("invalid event accepted or value repeated")
			}
			if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("invalid append created files")
			}
		})
	}
	l, _ := newLedger(t)
	for _, kind := range []string{"past_cap", "no_end", "unregistered", "standing_over_cap", "standing_without_row", "standing_second_box"} {
		row := appendEvent(t, l, "INCIDENT", map[string]any{"kind": kind})
		if row["kind"] != kind || row["event"] != "INCIDENT" {
			t.Fatal("valid no-box incident changed")
		}
	}
	for _, event := range []string{"LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED", "END_PENDING", "END_UNKNOWN", "STATE_OBSERVED"} {
		row := appendEvent(t, l, event, map[string]any{"instance_id": "i-demo1"})
		if row["event"] != event {
			t.Fatal("valid event changed")
		}
	}
	for _, id := range []any{nil, ""} {
		row := appendEvent(t, l, "INCIDENT", map[string]any{"kind": "no_end", "instance_id": id})
		if value, present := row["instance_id"]; !present || value != id {
			t.Fatal("explicit no-box incident ID changed")
		}
	}
	if len(readEvents(t, l)) != 14 {
		t.Fatal("valid event kinds were not all written")
	}
}

type failingNotes struct{ err error }

func (w failingNotes) Write([]byte) (int, error) { return 0, w.err }

// TestNotesFailure detects swallowed sink failures or a leaked file lock.
func TestNotesFailure(t *testing.T) {
	l, path := newLedger(t)
	seed(t, path, "demo-garbage\n")
	cause := errors.New("demo sink failure")
	l.SetNotes(failingNotes{err: cause})
	if _, err := l.Events(); !errors.Is(err, cause) {
		t.Fatal("Events swallowed a notes failure")
	}
	if _, err := l.Append("LAUNCHED", map[string]any{"instance_id": "i-demo1"}); !errors.Is(err, cause) {
		t.Fatal("Append swallowed a notes failure")
	}
	if !bytes.Equal(readBytes(t, path), []byte("demo-garbage\n")) {
		t.Fatal("append continued after a notes failure")
	}
	l.SetNotes(nil)
	appendEvent(t, l, "LAUNCHED", map[string]any{"instance_id": "i-demo1"})
	if len(readEvents(t, l)) != 1 {
		t.Fatal("lock was not released after a notes failure")
	}
}
