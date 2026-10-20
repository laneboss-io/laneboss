//go:build linux

package dirtycase

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDirtySelection(t *testing.T) {
	command := exec.Command("python3", "-I", "-B", "test_select.py")
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("dirty project selection or host-write fence failed", err)
	}
}

func TestDirtyPhases(t *testing.T) {
	command := exec.Command("python3", "-I", "-B", "test_phases.py")
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("dirty retention phase comparison failed", err)
	}
}

func TestDirtyTickets(t *testing.T) {
	command := exec.Command("python3", "-I", "-B", "test_tickets.py")
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("dirty item grant rounds failed", err)
	}
}

func TestRestoreReads(t *testing.T) {
	command := exec.Command("python3", "-I", "-B", "test_restore.py")
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("restore archive read checks failed", err)
	}
}
