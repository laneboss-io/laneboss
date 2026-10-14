package laneturns

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRunnerWatcherRejectsStaleStart(t *testing.T) {
	entry, err := processInfo(os.Getpid())
	if err != nil || entry == nil {
		t.Fatalf("cannot observe the control process: %v", err)
	}
	identity := identityOf(*entry)
	observed, err := observeRunner(identity)
	if err != nil || observed == nil || observed.pid != entry.pid || observed.start != entry.start {
		t.Fatalf("matching runner identity was refused: %v", err)
	}
	stale := copyObject(identity)
	stale["start"] = str(stale["start"]) + "1"
	if observed, err := observeRunner(stale); err == nil || observed != nil {
		t.Fatal("the runner watcher accepted the current PID with a different saved start time")
	}
	// Signal zero checks the same identity gate without stopping any process.
	if sent, err := signalChecked(stale, syscall.Signal(0)); err != nil || sent {
		t.Fatalf("a stale identity reached the signal operation: sent=%v error=%v", sent, err)
	}
	if sent, err := signalChecked(identity, syscall.Signal(0)); err != nil || !sent {
		t.Fatalf("the matching signal control failed: sent=%v error=%v", sent, err)
	}
	otherPID := copyObject(identity)
	otherPID["pid"] = entry.pid + 1
	if err := checkRunnerEntry(entry, otherPID); err == nil {
		t.Fatal("the runner watcher compared start times without checking the PID")
	}
	// Exit observation must compare the identity even for an uncollected zombie.
	zombie := *entry
	zombie.state = "Z"
	if err := checkRunnerEntry(&zombie, identity); err != nil {
		t.Fatalf("the matching zombie identity was refused: %v", err)
	}
	if err := checkRunnerEntry(&zombie, stale); err == nil {
		t.Fatal("the runner watcher accepted a zombie belonging to a different start time")
	}
}

func scanFixture(t *testing.T, directory, content string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "record.jsonl")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanOpenedFileAfterAncestorSwap(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	zone := filepath.Join(root, "protected")
	content := "ordinary session record\n"
	allowedPath := scanFixture(t, allowed, content)
	protectedPath := scanFixture(t, zone, "private canary record\n")
	zones := []string{zone}
	control, info, actual, err := openScanRecord(allowedPath, zones)
	if err != nil {
		t.Fatalf("the allowed regular-file control was refused: %v", err)
	}
	data, readErr := io.ReadAll(control)
	control.Close()
	if readErr != nil || string(data) != content || info == nil || !info.Mode().IsRegular() || actual != realPath(allowedPath) {
		t.Fatal("the allowed descriptor did not return its own regular-file bytes and location")
	}
	alias := filepath.Join(root, "records")
	if err := os.Symlink(allowed, alias); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(alias, filepath.Base(protectedPath))
	if within(path, zone) {
		t.Fatal("the pre-open control unexpectedly lies in the protected zone")
	}
	// Put the protected directory in place after the path was considered, open
	// through it, then put the allowed directory back. A check of file.Name()
	// now passes, but the descriptor still refers to the protected canary.
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(zone, alias); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(allowed, alias); err != nil {
		t.Fatal(err)
	}
	if within(opened.Name(), zone) {
		t.Fatal("the race fixture did not restore an allowed pathname")
	}
	openedInfo, openedPath, err := validateScanFile(opened, zones)
	if err == nil || openedInfo == nil || !openedInfo.Mode().IsRegular() || openedPath != realPath(protectedPath) {
		t.Fatal("descriptor validation accepted the protected file behind an allowed pathname")
	}
	if !strings.Contains(err.Error(), "refused configuration zone") {
		t.Fatalf("the canary failed for an unrelated reason: %v", err)
	}
}

func TestScanOpenerRefusesLinks(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	zone := filepath.Join(root, "protected")
	allowedPath := scanFixture(t, allowed, "ordinary record\n")
	protectedPath := scanFixture(t, zone, "private canary record\n")
	scan := &laneScan{s: &laneSession{c: &configuration{home: zone}}}
	record := &scanRecord{path: allowedPath, format: "claude-code"}
	control, err := scan.opener(record)()
	if err != nil {
		t.Fatalf("the scanner's allowed control was refused: %v", err)
	}
	control.Close()
	if err := os.Rename(allowed, filepath.Join(root, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(zone, allowed); err != nil {
		t.Fatal(err)
	}
	if file, err := scan.opener(record)(); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("the scanner opened a record through a replaced protected ancestor")
	}
	finalLink := filepath.Join(root, "record-link.jsonl")
	if err := os.Symlink(protectedPath, finalLink); err != nil {
		t.Fatal(err)
	}
	if file, _, _, err := openScanRecord(finalLink, []string{zone}); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("the scanner followed a final-component symbolic link")
	}
	if file, _, _, err := openScanRecord(root, []string{zone}); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("the scanner accepted a directory as a regular session record")
	}
}
