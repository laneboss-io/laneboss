package orgtree

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// SQLite sees only these exact, already bounded snapshot bytes. Locks and SHM
// updates belong to the private copy; no SQLite connection opens the live store.
func copyDecisionStore(snapshot map[string]*storeFileSnapshot, binaryFiles map[string]bool) (string, func() error, error) {
	directory, err := os.MkdirTemp("", "laneboss-org-store-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() error { return os.RemoveAll(directory) }
	name := filepath.Base(decisionStorePath)
	for _, suffix := range decisionStoreSuffixes {
		relative := decisionStorePath + suffix
		item := snapshot[relative]
		if item == nil || (suffix != "" && !binaryFiles[relative]) {
			continue
		}
		path := filepath.Join(directory, name+suffix)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return "", nil, errors.Join(err, cleanup())
		}
		n, writeErr := file.Write(item.data)
		closeErr := file.Close()
		if writeErr == nil && n != len(item.data) {
			writeErr = io.ErrShortWrite
		}
		if writeErr != nil || closeErr != nil {
			return "", nil, errors.Join(writeErr, closeErr, cleanup())
		}
	}
	return filepath.Join(directory, name), cleanup, nil
}
