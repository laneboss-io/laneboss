package boxledger_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxledger"
)

const schema = "laneboss-box-event/v1"

func fixedClock() time.Time {
	return time.Date(2026, 10, 14, 5, 6, 7, 0, time.UTC)
}

func newLedger(t *testing.T) (*boxledger.Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "boxes", "ledger.jsonl")
	l, err := boxledger.Open(path, schema)
	if err != nil {
		t.Fatal(err)
	}
	l.SetClock(fixedClock)
	l.SetNotes(nil)
	return l, path
}

func appendEvent(t *testing.T, l *boxledger.Ledger, event string, fields map[string]any) map[string]any {
	t.Helper()
	row, err := l.Append(event, fields)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readEvents(t *testing.T, l *boxledger.Ledger) []map[string]any {
	t.Helper()
	rows, err := l.Events()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func seed(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentSequence detects a missing or prematurely released file lock.
func TestConcurrentSequence(t *testing.T) {
	l, path := newLedger(t)
	const writers = 50
	start := make(chan struct{})
	failures := make(chan error, writers)
	var ready, finished sync.WaitGroup
	ready.Add(writers)
	finished.Add(writers)
	for i := 0; i < writers; i++ {
		go func(index int) {
			defer finished.Done()
			writer, err := boxledger.Open(path, schema)
			if err == nil {
				writer.SetClock(fixedClock)
				writer.SetNotes(nil)
			}
			ready.Done()
			<-start
			if err != nil {
				failures <- err
				return
			}
			_, err = writer.Append("LAUNCHED", map[string]any{"instance_id": fmt.Sprintf("i-demo%d", index)})
			if err != nil {
				failures <- err
			}
		}(i)
	}
	ready.Wait()
	close(start)
	finished.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	data := readBytes(t, path)
	if bytes.Count(data, []byte{'\n'}) != writers {
		t.Fatalf("ledger does not have %d complete lines", writers)
	}
	rows := readEvents(t, l)
	if len(rows) != writers {
		t.Fatalf("event count = %d, want %d", len(rows), writers)
	}
	seen := make(map[float64]bool)
	for i, row := range rows {
		seq, ok := row["seq"].(float64)
		if !ok || seq != float64(i+1) || seen[seq] {
			t.Fatalf("sequence at line %d is invalid or repeated: %v", i+1, row["seq"])
		}
		seen[seq] = true
	}
}

// TestMalformedLines detects stopped reads, changed bytes or missing notes.
func TestMalformedLines(t *testing.T) {
	l, path := newLedger(t)
	original := "{\"seq\":7}\nnot JSON SECRET-NEEDLE\n[]\n\nnull\ntrue\n" +
		"{\"bad\":\"" + string([]byte{255}) + "\"}\n{\"seq\":99}{}\n{}\n"
	seed(t, path, original)
	var notes bytes.Buffer
	l.SetNotes(&notes)
	if rows := readEvents(t, l); len(rows) != 2 || rows[0]["seq"] != float64(7) {
		t.Fatal("valid objects were lost or numbers changed type")
	}
	wantNotes := ""
	for _, number := range []int{2, 3, 4, 5, 6, 7, 8} {
		wantNotes += fmt.Sprintf("%s: line %d: skipped invalid event\n", path, number)
	}
	if notes.String() != wantNotes || strings.Contains(notes.String(), "SECRET-NEEDLE") {
		t.Fatal("skip notes lack line numbers or repeat line contents")
	}
	notes.Reset()
	appendEvent(t, l, "DONE_SENT", map[string]any{"instance_id": "i-demo1"})
	wantLine := `{"at_utc":"2026-10-14T05:06:07Z","event":"DONE_SENT","instance_id":"i-demo1",` +
		`"schema":"laneboss-box-event/v1","seq":8}` + "\n"
	if got := string(readBytes(t, path)); got != original+wantLine || notes.String() != wantNotes {
		t.Fatal("append changed old bytes, failed after garbage, or lost notes")
	}
	if rows := readEvents(t, l); len(rows) != 3 || rows[2]["seq"] != float64(8) {
		t.Fatal("append after malformed lines was not readable")
	}
}

// TestAppendCopies detects caller mutation or swallowed encoding failures.
func TestAppendCopies(t *testing.T) {
	l, _ := newLedger(t)
	fields := map[string]any{
		"instance_id": "i-demo1", "event": "END_UNKNOWN", "schema": "demo-schema",
		"seq": 99, "at_utc": "2026-10-14 04:00:00 GMT",
	}
	want := map[string]any{
		"instance_id": "i-demo1", "event": "END_UNKNOWN", "schema": "demo-schema",
		"seq": 99, "at_utc": "2026-10-14 04:00:00 GMT",
	}
	got := appendEvent(t, l, "LAUNCHED", fields)
	if !reflect.DeepEqual(fields, want) || got["schema"] != schema || got["event"] != "LAUNCHED" ||
		got["at_utc"] != "2026-10-14T04:00:00Z" {
		t.Fatal("caller fields were changed or reserved fields not replaced")
	}
	rows := readEvents(t, l)
	if len(rows) != 1 || rows[0]["seq"] != float64(1) {
		t.Fatal("caller sequence was used")
	}
	_, err := l.Append("LAUNCHED", map[string]any{"instance_id": "i-demo1", "invalid": make(chan int)})
	if err == nil || len(readEvents(t, l)) != 1 {
		t.Fatal("encoding error was swallowed or wrote a partial row")
	}
	appendEvent(t, l, "DONE_SENT", map[string]any{"instance_id": "i-demo1"})
	if rows := readEvents(t, l); rows[1]["seq"] != float64(2) {
		t.Fatal("failed encoding consumed a sequence")
	}
}
