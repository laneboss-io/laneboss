//go:build linux

package admin

import (
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestNativeReadinessCauseFacts(t *testing.T) {
	for _, mode := range []string{"setup", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			private, err := randomID("cause-")
			if err != nil {
				t.Fatal(err)
			}
			ready, gate := readinessFixture(t, mode, string(private))
			controls, err := readNativeReadiness(ready, string(private), gate)
			var typed *api.Error
			if len(controls) != 0 || !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || strings.Contains(typed.Message, string(private)) {
				t.Fatal("acceptance: readiness cause facts admitted a failure or exposed private data")
			}
			for _, field := range []string{"on_refusal={primary=", "before_stop={primary=", "spawn_thread=", "spawn_pdeathsig=", "primary_seccomp=", "oom_before=unavailable", "oom_kill_delta=unavailable", "memory_max=unavailable->unavailable", "pids_max=unavailable->unavailable"} {
				if !strings.Contains(typed.Message, field) {
					t.Fatal("acceptance: readiness refusal lost measured cause provenance")
				}
			}
			if mode == "setup" {
				if !strings.Contains(typed.Message, "child exited code=1;") || !strings.Contains(typed.Message, "bwrap_stderr=mount_source_unavailable;") ||
					!strings.Contains(typed.Message, "helper_kill=not_needed_") || gate.helperKillFact() == "sent" {
					t.Fatal("acceptance: setup exit was replaced by a helper SIGKILL or lost its operation")
				}
			} else if !strings.Contains(typed.Message, "child killed signal=SIGKILL;") || !strings.Contains(typed.Message, "helper_kill=sent;") || gate.helperKillFact() != "sent" {
				t.Fatal("acceptance: actual helper SIGKILL was missing or falsely attributed")
			}
		})
	}
}
