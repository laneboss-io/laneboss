package orgtree

import (
	"strings"
	"testing"
	"time"
)

func TestScanDeadline(t *testing.T) {
	clean := newTree(t.TempDir())
	clean.scan("source.js", "token = worker.lookup(name);\n")
	if err := problemsError(clean.problems); err != nil {
		t.Fatal("clean scans within budget must retain their control")
	}
	bad := newTree(t.TempDir())
	bad.scan("source.js", "password = 'harmless-canary';\n")
	if err := problemsError(bad.problems); err == nil || !strings.Contains(err.Error(), "secret value detected") {
		t.Fatal("credential detection must remain active within budget")
	}
	expired := newTree(t.TempDir())
	expired.deadline = time.Now().Add(-time.Second)
	expired.scan("source.js", "token = worker.lookup(name);\n")
	if err := problemsError(expired.problems); err == nil || !strings.Contains(err.Error(), "inspection exceeded") {
		t.Fatal("expired scans must fail closed")
	}
}
