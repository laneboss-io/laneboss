package caller

import (
	"fmt"
	"strings"
)

// RunnerSessionIdentity records the kernel identity of the runner's session
// leader. Unlike portable run tracking, this start time is never rounded by ps.
func RunnerSessionIdentity(pid int) (map[string]any, error) {
	p, err := nativeProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("the runner's kernel session identity cannot be read")
	}
	if pid <= 1 || p.PID != pid || p.SID != pid || p.Start == "" || strings.HasPrefix(p.State, "Z") {
		return nil, nil
	}
	return map[string]any{"pid": p.PID, "start": p.Start, "sid": p.SID}, nil
}

// laneSessionMatches is only used for an open run. A runner PID must agree
// with the separate kernel record and still name the same live session leader.
// No environment label, sampled helper or rounded start time supplies proof.
func laneSessionMatches(runner, recorded *process, sid int) (bool, error) {
	if runner == nil || recorded == nil || sid <= 1 || recorded.PID <= 1 ||
		runner.PID != recorded.PID || recorded.SID != recorded.PID || recorded.Start == "" {
		return false, nil
	}
	current, err := nativeProcess(recorded.PID)
	if err != nil {
		return false, fmt.Errorf("the recorded runner's kernel session identity cannot be read")
	}
	if current.PID != recorded.PID || current.SID != recorded.PID || strings.HasPrefix(current.State, "Z") {
		return false, nil
	}
	sameStart, err := sameLaneRunnerStart(current.Start, recorded.Start)
	if err != nil || !sameStart {
		return false, err
	}
	return sameLaneSession(sid, recorded.PID)
}
