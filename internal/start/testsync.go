package start

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// pauseSnapshotForTest is inactive unless a black-box test explicitly supplies
// LANEBOSS_TEST_START_SYNC as an absolute file prefix. Reaching this point means
// the real store, event hashes and lane projection have already been verified.
// The hook retains that snapshot in memory, releases SQLite and directory locks
// so a real writer can commit, creates PREFIX-reached, and waits for PREFIX-go.
// It never substitutes events, projections, output or verification results.
func (s *storeSnapshot) pauseSnapshotForTest() error {
	prefix := os.Getenv("LANEBOSS_TEST_START_SYNC")
	if prefix == "" {
		return nil
	}
	if !filepath.IsAbs(prefix) || strings.ContainsRune(prefix, '\x00') {
		return refused("LANEBOSS_TEST_START_SYNC must name an absolute synchronization file prefix")
	}
	if err := s.releaseSnapshotLocks(); err != nil {
		return err
	}
	marker, err := os.OpenFile(prefix+"-reached", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return refused("LANEBOSS_TEST_START_SYNC: cannot create the synchronization marker")
	}
	if err := marker.Close(); err != nil {
		return refused("LANEBOSS_TEST_START_SYNC: cannot close the synchronization marker")
	}
	deadline := time.NewTimer(40 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		info, err := os.Lstat(prefix + "-go")
		if err == nil {
			if !info.Mode().IsRegular() {
				return refused("LANEBOSS_TEST_START_SYNC: the continue signal must be a regular file")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return refused("LANEBOSS_TEST_START_SYNC: cannot inspect the continue signal")
		}
		select {
		case <-deadline.C:
			return refused("LANEBOSS_TEST_START_SYNC: timed out waiting for the continue signal")
		case <-tick.C:
		}
	}
}

// Keep the pinned state root for pending-file reads and the verified slices for
// rendering, while allowing the synchronization test's writer to append.
func (s *storeSnapshot) releaseSnapshotLocks() error {
	if s.tx != nil {
		if err := s.tx.Rollback(); err != nil {
			return integrity("cannot release the verified store's read transaction")
		}
		s.tx = nil
	}
	if s.db != nil {
		db := s.db
		s.db = nil
		if err := db.Close(); err != nil {
			return integrity("cannot close the verified store's database connection")
		}
	}
	if s.lock != nil {
		if err := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN); err != nil {
			return integrity("cannot release the verified state directory's reader lock")
		}
		lock := s.lock
		s.lock = nil
		if err := lock.Close(); err != nil {
			return integrity("cannot close the verified state directory's reader lock")
		}
	}
	return nil
}
