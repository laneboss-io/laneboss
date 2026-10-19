//go:build linux

package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readChildLinks(t *testing.T, descriptors []string, extra []*os.File) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/readlink", descriptors...)
	command.ExtraFiles = extra
	output, err := command.Output()
	if ctx.Err() != nil {
		t.Fatal("descriptor child timed out")
	}
	if err != nil {
		var exited *exec.ExitError
		// readlink's documented exit 1 means at least one input was not a
		// readable symlink. A separate intentionally inherited control must
		// succeed, so an absent/broken native probe cannot count as isolation.
		if !errors.As(err, &exited) || exited.ExitCode() != 1 || len(exited.Stderr) != 0 {
			t.Fatal("descriptor child failed its native prerequisite")
		}
	}
	if len(output) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
}

func TestStateFDExec(t *testing.T) {
	s, deps := testStore(t)
	if _, err := s.Transact(context.Background(), testTransaction(t)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var descriptors []string
	seen := make(map[string]bool)
	for _, entry := range entries {
		path := filepath.Join("/proc/self/fd", entry.Name())
		target, err := os.Readlink(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if target == deps.Directory || strings.HasPrefix(target, deps.Directory+"/") {
			descriptors = append(descriptors, path)
			seen[filepath.Base(target)] = true
		}
	}
	if !seen["state.sqlite"] || !seen["writer.lock"] {
		t.Fatal("parent state descriptor canaries are missing")
	}
	// A real exec with an explicitly passed protected descriptor is the positive
	// control. These are test-owned files; no state bytes or targets are printed.
	control := readChildLinks(t, []string{"/proc/self/fd/3"}, []*os.File{s.lock})
	if len(control) != 1 || control[0] != filepath.Join(deps.Directory, "writer.lock") {
		t.Fatal("inherited state descriptor control was not observed")
	}
	for _, target := range readChildLinks(t, descriptors, nil) {
		if target == deps.Directory || strings.HasPrefix(target, deps.Directory+"/") {
			t.Fatal("state descriptor survived ordinary exec")
		}
	}
	// This proves the component's exec boundary only. It is not a separate-UID
	// confined-lane launch or proof for an inactive SQLite rollback journal.
}
