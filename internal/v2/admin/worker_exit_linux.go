//go:build linux

package admin

import (
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only kernel wait facts and a closed first-line category leave the private
// capture. Neither arguments nor arbitrary error text enters the journal.
func writeWorkerExit(writer io.Writer, state *os.ProcessState, stderr *bootstrapStderr) error {
	status := "unavailable"
	if state != nil {
		if wait, ok := state.Sys().(syscall.WaitStatus); ok {
			if wait.Exited() {
				status = "exit_" + strconv.Itoa(wait.ExitStatus())
			} else if wait.Signaled() {
				status = "signal_" + strconv.Itoa(int(wait.Signal()))
			}
		}
	}
	data, err := json.Marshal(struct {
		Event  string `json:"event"`
		Status string `json:"status"`
		Stderr string `json:"stderr"`
	}{"worker_exit", status, stderr.workerFact()})
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := writer.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (s *bootstrapStderr) workerFact() string {
	if s == nil {
		return "unavailable"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return classifyWorkerStderr(s.firstLine)
}

func classifyWorkerStderr(data []byte) string {
	line, _, _ := strings.Cut(string(data), "\n")
	if line == "" {
		return "none"
	}
	var typed struct {
		Code    api.ErrorCode `json:"code"`
		Message string        `json:"message"`
	}
	if json.Unmarshal([]byte(line), &typed) == nil {
		if typed.Code == api.CodeInvalid && typed.Message == "explicit configuration required" {
			return "cli_configuration_required"
		}
		switch typed.Code {
		case api.CodeInvalid, api.CodeUnauthenticated, api.CodeForbidden, api.CodeNotFound,
			api.CodeConflict, api.CodeIntegrity, api.CodeBudget, api.CodePrerequisite,
			api.CodeUnsupported, api.CodeUnavailable, api.CodeDeadline, api.CodeContainmentUnknown,
			api.CodeCancelled, api.CodeVersion, api.CodeIdempotencyConflict, api.CodeNotImplemented,
			api.CodeUnscored, api.CodeCursorExpired:
			return "worker_" + string(typed.Code)
		}
		return "worker_error_unclassified"
	}
	if strings.HasPrefix(line, "runtime: failed to create new OS thread") || strings.HasPrefix(line, "runtime/cgo: pthread_create failed:") {
		if strings.Contains(line, "errno=11") || strings.HasSuffix(line, "Resource temporarily unavailable") {
			return "runtime_thread_limit"
		}
		if strings.Contains(line, "errno=1)") || strings.Contains(line, "errno=13") || strings.HasSuffix(line, "Operation not permitted") || strings.HasSuffix(line, "Permission denied") {
			return "runtime_thread_denied"
		}
		return "runtime_thread_failed"
	}
	if strings.HasPrefix(line, "fatal error:") || strings.HasPrefix(line, "runtime:") || strings.HasPrefix(line, "runtime/cgo:") {
		return "runtime_failure"
	}
	if strings.HasPrefix(line, "panic:") {
		return "panic"
	}
	return classifyBwrapStderr([]byte(line))
}
