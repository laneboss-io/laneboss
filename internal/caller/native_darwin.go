package caller

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// sysctl preserves microseconds, unlike the rounded lstart column of ps.
func nativeProcess(pid int) (process, error) {
	sid, err := unix.Getsid(pid)
	if err == unix.ESRCH {
		return process{}, nil
	}
	if err != nil {
		return process{}, err
	}
	// Read start time after the SID query, so a PID reused between these
	// reads cannot retain the previous leader's recorded start time.
	entries, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil || len(entries) == 0 {
		return process{}, err
	}
	entry := entries[0]
	if len(entries) != 1 || int(entry.Proc.P_pid) != pid || entry.Proc.P_starttime.Sec <= 0 {
		return process{}, fmt.Errorf("invalid kernel process identity")
	}
	state := "S"
	if entry.Proc.P_stat == 5 {
		state = "Z"
	}
	return process{
		PID:    pid,
		Parent: int(entry.Eproc.Ppid),
		PGID:   int(entry.Eproc.Pgid),
		SID:    sid,
		Start:  fmt.Sprintf("%d.%06d", entry.Proc.P_starttime.Sec, entry.Proc.P_starttime.Usec),
		State:  state,
	}, nil
}
