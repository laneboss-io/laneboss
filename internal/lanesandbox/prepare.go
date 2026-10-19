package lanesandbox

import (
	"os"
	"os/exec"

	"laneboss.io/laneboss/internal/faults"
)

// Preparation describes the command prepared for exec, not proof that a runner
// has started or that an enforcement canary passed.
type Preparation struct {
	Requested, Prepared bool
	Backend, Notice     string
	ProtectedCount      int
}

// RecordRunnerSandbox stores the selected runner policy on each new run. A
// configuration changed back to native mode cannot inherit an old replacement.
func RecordRunnerSandbox(payload, data map[string]any) {
	delete(payload, "runner_sandbox")
	if ReplacesRunner(data) {
		payload["runner_sandbox"] = RunnerReplaced
	}
}

// Prepare leaves disabled configurations unchanged. The launcher records a
// nonempty Notice in the run's watch log. Only the runner command is wrapped;
// the supervisor and the launcher's state-writing processes stay outside it.
func Prepare(cmd *exec.Cmd, c Configuration) Preparation {
	if !Enabled(c.Data) {
		return Preparation{}
	}
	result := Preparation{Requested: true}
	if faults.Get("sandbox-empty-home").Point != "" {
		if err := faults.Reach("sandbox-empty-home"); err != nil {
			result.Notice = "empty-home input mutation could not be recorded"
			return result
		}
		c.Home = ""
	}
	if ReplacesRunner(c.Data) {
		if cmd == nil {
			result.Notice = "runner command is missing; lane sandbox was not prepared"
			return result
		}
		if err := CheckClaudeSettings(cmd.Args); err != nil {
			result.Notice = err.Error()
			return result
		}
	}
	if c.Executable == "" {
		var err error
		c.Executable, err = os.Executable()
		if err != nil {
			result.Notice = "launcher executable could not be located; no Laneboss-files sandbox was prepared"
			return result
		}
	}
	paths, err := ProtectedPaths(c)
	if err != nil {
		result.Notice = "protected paths could not be resolved: " + err.Error()
		return result
	}
	result.ProtectedCount = len(paths)
	allowed, err := nativeAllowedWrites(cmd, c, paths)
	if err != nil {
		result.Notice = err.Error()
		return result
	}
	result.Prepared, result.Backend, result.Notice = nativeRunner(cmd, paths, allowed)
	return result
}
