//go:build laneboss_faults

package caller

import "laneboss.io/laneboss/internal/faults"

func sameLaneSession(callerSID, runnerPID int) (bool, error) {
	if faults.Get("caller-no-lane-session").Point != "" {
		if err := faults.Reach("caller-no-lane-session"); err != nil {
			return false, err
		}
		return false, nil
	}
	if faults.Get("caller-any-lane-session").Point != "" {
		if err := faults.Reach("caller-any-lane-session"); err != nil {
			return false, err
		}
		// The cross-session canary must reject this deliberate loss of equality.
		return callerSID > 1, nil
	}
	return callerSID == runnerPID, nil
}

func sameLaneRunnerStart(current, recorded string) (bool, error) {
	if faults.Get("caller-lane-session-no-start").Point != "" {
		if err := faults.Reach("caller-lane-session-no-start"); err != nil {
			return false, err
		}
		return true, nil
	}
	return current == recorded, nil
}
