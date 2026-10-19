//go:build !laneboss_faults

package caller

func sameLaneSession(callerSID, runnerPID int) (bool, error) {
	return callerSID == runnerPID, nil
}

func sameLaneRunnerStart(current, recorded string) (bool, error) {
	return current == recorded, nil
}
