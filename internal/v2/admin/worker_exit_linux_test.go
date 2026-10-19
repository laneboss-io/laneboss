//go:build linux

package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestWorkerExitJournal(t *testing.T) {
	private, err := randomID("private-worker-")
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct{ first, later, want string }{
		{"", "", "none"},
		{`{"code":"` + string(api.CodeInvalid) + `","message":"explicit configuration required"}`, "", "cli_configuration_required"},
		{`{"code":"` + string(api.CodeForbidden) + `","message":"/` + string(private) + `"}`, "", "worker_" + string(api.CodeForbidden)},
		{string(private), "\nbwrap: Creating new namespace failed: Permission denied\n", "other"},
		{"panic: /" + string(private), "", "panic"},
		{strings.Repeat(string(private), 1024), "", "other"},
	} {
		observer := &bootstrapStderr{destination: io.Discard}
		observer.freeze() // Worker diagnostics arrive after native readiness.
		first := []byte(sample.first + "\n")
		for _, part := range [][]byte{first[:len(first)/2], first[len(first)/2:], []byte(sample.later)} {
			if _, err := observer.Write(part); err != nil {
				t.Fatal(err)
			}
		}
		command := exec.Command("/proc/self/exe", "admin-stderr-fixture")
		command.Env = []string{}
		command.Stdin, command.Stderr = strings.NewReader(""), io.Discard
		if err := command.Run(); err == nil || command.ProcessState.ExitCode() != 1 {
			t.Fatal("worker journal control did not actually exit nonzero", err)
		}
		var journal bytes.Buffer
		if err := writeWorkerExit(&journal, command.ProcessState, observer); err != nil {
			t.Fatal(err)
		}
		var entry map[string]string
		if json.Unmarshal(journal.Bytes(), &entry) != nil || len(entry) != 3 || entry["event"] != "worker_exit" || entry["status"] != "exit_1" || entry["stderr"] != sample.want || bytes.Contains(journal.Bytes(), []byte(private)) {
			t.Fatal("native worker exit lost its actual status or private first-line category", journal.String())
		}
	}
	command := exec.Command("/proc/self/exe", "admin-stderr-fixture")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Env = []string{}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := command.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("worker signal control did not actually fail")
	}
	var journal bytes.Buffer
	if err := writeWorkerExit(&journal, command.ProcessState, nil); err != nil || !strings.Contains(journal.String(), `"status":"signal_9"`) {
		t.Fatal("worker journal lost the actual kernel signal", err)
	}
	if err := writeWorkerExit(shortHelperJournal{}, command.ProcessState, nil); err == nil {
		t.Fatal("worker journal accepted a truncated exit record")
	}
}
