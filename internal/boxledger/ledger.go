// Package boxledger stores box events in a locked, append-only JSON Lines file.
package boxledger

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/boxcore"
)

// Ledger is the file-backed boxcore.Ledger. Independent handles share a file lock.
type Ledger struct {
	mu     sync.Mutex
	path   string
	schema string
	now    func() time.Time
	notes  io.Writer
}

var _ boxcore.Ledger = (*Ledger)(nil)

// Open prepares a handle without creating any directory, ledger or lock file.
func Open(path, schema string) (*Ledger, error) {
	if path == "" {
		return nil, errors.New("ledger path is required")
	}
	if !utf8.ValidString(schema) || utf8.RuneCountInString(schema) < 1 || utf8.RuneCountInString(schema) > 64 {
		return nil, errors.New("ledger schema must be valid text within the length bounds")
	}
	for _, r := range schema {
		if unicode.IsControl(r) {
			return nil, errors.New("ledger schema must not contain control characters")
		}
	}
	return &Ledger{path: path, schema: schema, now: time.Now, notes: os.Stderr}, nil
}

// SetClock replaces the clock; nil restores the real clock.
func (l *Ledger) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	l.now = now
}

// SetNotes sets the sink for skipped-line notes; nil discards notes.
func (l *Ledger) SetNotes(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w == nil {
		w = io.Discard
	}
	l.notes = w
}

// Writable prepares private files and proves that the ledger can be opened.
func (l *Ledger) Writable() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.locked(func() error {
		f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
		modeErr := f.Chmod(0600)
		return errors.Join(modeErr, f.Close())
	})
}

func flock(f *os.File, operation int) error {
	for {
		err := syscall.Flock(int(f.Fd()), operation)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

func (l *Ledger) locked(action func() error) (err error) {
	dir := filepath.Dir(l.path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	// Opening first also detects a read-only directory before changing its mode.
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if err = flock(f, syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, flock(f, syscall.LOCK_UN)) }()
	return action()
}

func validEvent(event string) bool {
	switch event {
	case "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED", "END_PENDING",
		"END_UNKNOWN", "INCIDENT", "STATE_OBSERVED":
		return true
	}
	return false
}

func validIncident(kind string) bool {
	switch kind {
	case "past_cap", "no_end", "unregistered", "standing_over_cap",
		"standing_without_row", "standing_second_box":
		return true
	}
	return false
}

// Append copies fields, assigns the sequence under the lock and syncs one write.
func (l *Ledger) Append(event string, fields map[string]any) (map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !validEvent(event) {
		return nil, errors.New("ledger event: unknown event")
	}
	if event == "INCIDENT" {
		kind, ok := fields["kind"].(string)
		if !ok || !validIncident(kind) {
			return nil, errors.New("ledger kind: invalid incident kind")
		}
	}
	id, present := fields["instance_id"]
	instance, ok := id.(string)
	noBox := event == "INCIDENT" && (!present || id == nil || ok && instance == "")
	if !noBox && (!ok || instance == "") {
		return nil, errors.New("ledger instance_id: must be a non-empty string")
	}
	row := make(map[string]any, len(fields)+4)
	for key, value := range fields {
		row[key] = value
	}
	row["schema"], row["event"] = l.schema, event
	if _, present := row["at_utc"]; !present {
		row["at_utc"] = boxcore.FormatUTC(l.now())
	}
	for _, key := range []string{"launch_time_utc", "terminated_utc", "at_utc"} {
		if value, ok := row[key].(string); ok {
			if normalized, valid := boxcore.NormalizeUTC(value); valid {
				row[key] = normalized
			}
		}
	}
	err := l.locked(func() error {
		events, needsNewline, err := l.readEvents(true)
		if err != nil {
			return err
		}
		row["seq"], err = nextSequence(events)
		if err != nil {
			return err
		}
		if _, supplied := row["billed_seconds"]; event == "TERMINATED_CONFIRMED" && !supplied {
			launch := LastLaunch(events, instance)
			start, startOK := launch["launch_time_utc"].(string)
			end, endOK := row["terminated_utc"].(string)
			if startOK && endOK {
				if seconds, valid := boxcore.SecondsBetween(start, end); valid {
					row["billed_seconds"] = seconds
				}
			}
		}
		line, err := encodeLine(row)
		if err != nil {
			return fmt.Errorf("ledger fields: cannot encode JSON: %w", err)
		}
		if needsNewline {
			// Preserve an unterminated legacy line and start the new event separately.
			line = append([]byte{'\n'}, line...)
		}
		return l.writeLine(line)
	})
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (l *Ledger) writeLine(line []byte) (err error) {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	n, err := f.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Chmod(0600)
}

// Events returns objects in file order, with all JSON numbers decoded as float64.
func (l *Ledger) Events() ([]map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	events, _, err := l.readEvents(false)
	return events, err
}

// LastLaunch returns the last launch for instanceID, or nil when none exists.
func LastLaunch(events []map[string]any, instanceID string) map[string]any {
	for i := len(events) - 1; i >= 0; i-- {
		row := events[i]
		if row["instance_id"] == instanceID && row["event"] == "LAUNCHED" {
			return row
		}
	}
	return nil
}

// EndOf returns the last confirmed termination or unknown end for instanceID.
func EndOf(events []map[string]any, instanceID string) (kind string, ok bool) {
	for i := len(events) - 1; i >= 0; i-- {
		row := events[i]
		if row["instance_id"] != instanceID {
			continue
		}
		if row["event"] == "TERMINATED_CONFIRMED" || row["event"] == "END_UNKNOWN" {
			return row["event"].(string), true
		}
	}
	return "", false
}
