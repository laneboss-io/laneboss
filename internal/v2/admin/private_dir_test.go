package admin

import (
	"os"
	"testing"
)

// Temporary roots model helper-private storage, journals and retained inputs.
// Their mode is an explicit fixture property, independent of the process umask.
func privateTestDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}
