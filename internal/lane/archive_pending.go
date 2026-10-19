package lane

import (
	"errors"
	"slices"

	"laneboss.io/laneboss/internal/faults"

	"modernc.org/sqlite"
)

// A concurrent drainer can remove a prefix. Only the exact remaining suffix of
// this verified attempt's own events may pass the normal pending-event gate.
func archiveQueueMatches(queue, expected []string) bool {
	return len(queue) <= len(expected) && slices.Equal(queue, expected[len(expected)-len(queue):])
}

func (s *session) checkArchivePending(lane string, expected []string) error {
	r, unlock, err := s.laneLock(lane, false)
	if err != nil {
		return err
	}
	defer unlock()
	queue, err := queueAt(r)
	if err != nil {
		return err
	}
	if !archiveQueueMatches(queue, expected) {
		return refuse("lane %s has pending or refused events; nothing was archived or removed", lane)
	}
	return nil
}

func archiveStoreReadOnly(err error) bool {
	if unavailable, ok := err.(*storeUnavailableError); ok {
		err = unavailable.cause
	}
	var sqliteError *sqlite.Error
	// SQLite's low byte is its primary result code; include extended READONLY
	// codes, but never turn corruption, disk, lock or validation errors pending.
	const sqliteReadOnly = 8
	return errors.As(err, &sqliteError) && sqliteError.Code()&0xff == sqliteReadOnly
}

// Plain clean can finish a verified file-backed archive while SQLite is
// temporarily read-only. Persist each exact event before proceeding; start's
// existing drain stores the ordered queue before a reused lane.started.
func (s *session) recordArchive(e object, plan *archivePlan) (object, bool, error) {
	if !plan.deferReadOnly {
		stored, err := s.append(e, 10)
		return stored, err == nil, err
	}
	e, err := normalizeEnvelope(e)
	if err != nil {
		return nil, false, err
	}
	lane := str(e["lane"])
	if err = s.validateBinding(str(e["kind"]), lane, obj(e["payload"])); err != nil {
		return nil, false, err
	}
	r, unlock, err := s.laneLock(lane, false)
	if err != nil {
		return nil, false, err
	}
	defer unlock()
	if err = mergeAside(r); err != nil {
		return nil, false, err
	}
	queue, err := linesAt(r, "pending.jsonl")
	if err != nil {
		return nil, false, err
	}
	if !archiveQueueMatches(queue, plan.pending) {
		return nil, false, refuse("lane %s has events outside this archive attempt waiting to be recorded", lane)
	}
	if len(plan.pending) == 0 {
		stored, err := s.appendRaw(e, 10)
		if err == nil {
			return stored, true, nil
		}
		if !archiveStoreReadOnly(err) {
			return nil, false, err
		}
		if faults.Get("archive-readonly-store-fails").Point != "" {
			if reached := faults.Reach("archive-readonly-store-fails"); reached != nil {
				return nil, false, reached
			}
			return nil, false, err
		}
	}
	line := string(canonical(e))
	if err = rewriteLines(r, "pending.jsonl", append(queue, line)); err != nil {
		return nil, false, err
	}
	plan.pending = append(plan.pending, line)
	return nil, false, nil
}
